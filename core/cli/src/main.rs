//! `indexone-cli` — a thin JSON-over-stdio sidecar over the IndexOne core.
//!
//! Non-Rust SDKs (Python, TypeScript) bind to the real chain, crypto, witness,
//! attestation, and composed verifier through this binary instead of
//! reimplementing any of it (CLAUDE.md §11: SDKs are thin bindings, not a second
//! implementation). It reads exactly one JSON request object from stdin and
//! writes exactly one JSON response object to stdout.
//!
//! Requests (tagged by `cmd`). Chain / keys / receipts / proofs / attestations
//! are threaded as opaque JSON objects; digests are lowercase hex strings.
//!
//! ```text
//! issue           {seed, principal, scope} -> {ok, chain, root_key}
//! attenuate       {chain, signer_seed, to, to_seed, scope, purpose} -> {ok, chain, to_key}
//! verify          {chain, root_key} -> {ok, effective_scope}          (chain only)
//! pubkey          {seed} -> {ok, public_key}
//! chain_digest    {chain} -> {ok, digest}
//! witness_append  {log?, chain_digest, action_digest, nonce, prev_root}
//!                   -> {ok, receipt, log, leaf_index, root, inclusion_proof}
//! attest          {seed, attester, chain_digest, requested_action, outcome,
//!                  witnessed_root, inclusion_proof, role?} -> {ok, completion}
//! composed_verify {chain, root_key, trusted_root, action_receipt, completion, policy?}
//!                   -> {ok, effective_scope}   (the full §6 verify(): completeness +
//!                      independent attestation + non-equivocation, fail closed)
//! ```
//!
//! Key material is a 32-byte hex seed (the client manages its own seeds); the
//! sidecar derives the Ed25519 keypair deterministically. Any error is reported
//! as {"ok":false,"error":".."} with a non-zero exit — never a silent success.

use std::io::{Read, Write};

use indexone_attestation::{AttesterRole, CompletionAttestation};
use indexone_chain::{Chain, Principal, Scope};
use indexone_crypto::{Ed25519Signer, PublicKey, Signer};
use indexone_verifier::{verify, VerifiableAction, VerifyPolicy};
use indexone_witness::{ActionReceipt, Digest, InclusionProof, Witness};
use serde::{Deserialize, Serialize};

/// Attestation flow, mirrors `indexone_attestation::AttesterRole` on the wire.
#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum AttestRole {
    #[default]
    ThirdParty,
    CounterSigned,
}

impl From<AttestRole> for AttesterRole {
    fn from(r: AttestRole) -> Self {
        match r {
            AttestRole::ThirdParty => AttesterRole::ThirdParty,
            AttestRole::CounterSigned => AttesterRole::CounterSigned,
        }
    }
}

/// Verifier policy on the wire (`VerifyPolicy` is not itself `Deserialize`).
#[derive(Deserialize, Default)]
struct PolicyDto {
    #[serde(default)]
    trusted_attesters: Vec<PublicKey>,
    #[serde(default)]
    allow_counter_signed: bool,
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
enum Request {
    Issue {
        seed: String,
        principal: Principal,
        scope: Scope,
    },
    Attenuate {
        chain: Chain,
        signer_seed: String,
        to: Principal,
        to_seed: String,
        scope: Scope,
        purpose: String,
    },
    Verify {
        chain: Chain,
        root_key: PublicKey,
    },
    /// Derive a public key from a seed — e.g. to name a trusted attester in a
    /// `composed_verify` policy without issuing a chain.
    Pubkey {
        seed: String,
    },
    ChainDigest {
        chain: Chain,
    },
    WitnessAppend {
        #[serde(default)]
        log: Vec<ActionReceipt>,
        chain_digest: String,
        action_digest: String,
        nonce: String,
        prev_root: String,
    },
    Attest {
        seed: String,
        attester: Principal,
        chain_digest: String,
        requested_action: String,
        outcome: String,
        witnessed_root: String,
        inclusion_proof: InclusionProof,
        #[serde(default)]
        role: AttestRole,
    },
    ComposedVerify {
        chain: Chain,
        root_key: PublicKey,
        trusted_root: String,
        action_receipt: ActionReceipt,
        completion: CompletionAttestation,
        #[serde(default)]
        policy: PolicyDto,
    },
}

#[derive(Serialize)]
#[serde(untagged)]
// One-shot request/response objects (deserialized once, serialized once, never
// stored in bulk), so the size spread across variants doesn't matter here.
#[allow(clippy::large_enum_variant)]
enum Response {
    Issue {
        ok: bool,
        chain: Chain,
        root_key: PublicKey,
    },
    Attenuate {
        ok: bool,
        chain: Chain,
        to_key: PublicKey,
    },
    Scope {
        ok: bool,
        effective_scope: Scope,
    },
    Digest {
        ok: bool,
        digest: String,
    },
    WitnessAppend {
        ok: bool,
        receipt: ActionReceipt,
        log: Vec<ActionReceipt>,
        leaf_index: usize,
        root: String,
        inclusion_proof: InclusionProof,
    },
    Attest {
        ok: bool,
        completion: CompletionAttestation,
    },
    Pubkey {
        ok: bool,
        public_key: PublicKey,
    },
    Error {
        ok: bool,
        error: String,
    },
}

fn seed_from_hex(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex seed: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "seed must be exactly 32 bytes (64 hex chars)".to_string())
}

fn digest_from_hex(s: &str) -> Result<Digest, String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex digest: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "digest must be exactly 32 bytes (64 hex chars)".to_string())
}

fn handle(req: Request) -> Result<Response, String> {
    match req {
        Request::Issue {
            seed,
            principal,
            scope,
        } => {
            let signer = Ed25519Signer::from_seed(seed_from_hex(&seed)?);
            let root_key = signer.public_key();
            let chain = Chain::issue(&signer, principal, scope);
            Ok(Response::Issue {
                ok: true,
                chain,
                root_key,
            })
        }
        Request::Attenuate {
            mut chain,
            signer_seed,
            to,
            to_seed,
            scope,
            purpose,
        } => {
            let signer = Ed25519Signer::from_seed(seed_from_hex(&signer_seed)?);
            let to_key = Ed25519Signer::from_seed(seed_from_hex(&to_seed)?).public_key();
            chain
                .attenuate(&signer, to, to_key.clone(), scope, purpose)
                .map_err(|e| e.to_string())?;
            Ok(Response::Attenuate {
                ok: true,
                chain,
                to_key,
            })
        }
        Request::Verify { chain, root_key } => {
            let effective_scope = chain.verify(&root_key).map_err(|e| e.to_string())?;
            Ok(Response::Scope {
                ok: true,
                effective_scope,
            })
        }
        Request::Pubkey { seed } => {
            let signer = Ed25519Signer::from_seed(seed_from_hex(&seed)?);
            Ok(Response::Pubkey {
                ok: true,
                public_key: signer.public_key(),
            })
        }
        Request::ChainDigest { chain } => Ok(Response::Digest {
            ok: true,
            digest: hex::encode(chain.digest()),
        }),
        Request::WitnessAppend {
            log,
            chain_digest,
            action_digest,
            nonce,
            prev_root,
        } => {
            // Rebuild the log statelessly from the threaded `log`, then append the
            // new receipt. The caller threads `log` back on each call.
            let mut witness = Witness::new();
            for r in &log {
                witness.append(r);
            }
            let receipt = ActionReceipt {
                chain_digest: digest_from_hex(&chain_digest)?,
                action_digest: digest_from_hex(&action_digest)?,
                nonce: digest_from_hex(&nonce)?,
                prev_root: digest_from_hex(&prev_root)?,
            };
            let leaf_index = witness.append(&receipt);
            let inclusion_proof = witness
                .inclusion_proof(leaf_index)
                .ok_or("just-appended leaf is out of range (unreachable)")?;
            let root = hex::encode(witness.root());
            let mut new_log = log;
            new_log.push(receipt.clone());
            Ok(Response::WitnessAppend {
                ok: true,
                receipt,
                log: new_log,
                leaf_index,
                root,
                inclusion_proof,
            })
        }
        Request::Attest {
            seed,
            attester,
            chain_digest,
            requested_action,
            outcome,
            witnessed_root,
            inclusion_proof,
            role,
        } => {
            let signer = Ed25519Signer::from_seed(seed_from_hex(&seed)?);
            let completion = CompletionAttestation::attest_as(
                role.into(),
                &signer,
                attester,
                digest_from_hex(&chain_digest)?,
                digest_from_hex(&requested_action)?,
                digest_from_hex(&outcome)?,
                digest_from_hex(&witnessed_root)?,
                inclusion_proof,
            );
            Ok(Response::Attest {
                ok: true,
                completion,
            })
        }
        Request::ComposedVerify {
            chain,
            root_key,
            trusted_root,
            action_receipt,
            completion,
            policy,
        } => {
            let trusted_root = digest_from_hex(&trusted_root)?;
            let action = VerifiableAction {
                chain,
                action_receipt,
                completion,
            };
            let verify_policy = VerifyPolicy {
                trusted_attesters: policy.trusted_attesters,
                allow_counter_signed: policy.allow_counter_signed,
            };
            let effective_scope = verify(&action, &root_key, &trusted_root, &verify_policy)
                .map_err(|e| e.to_string())?;
            Ok(Response::Scope {
                ok: true,
                effective_scope,
            })
        }
    }
}

fn main() {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        emit(Response::Error {
            ok: false,
            error: format!("failed to read stdin: {e}"),
        });
        std::process::exit(1);
    }

    let response = serde_json::from_str::<Request>(&input)
        .map_err(|e| format!("invalid request JSON: {e}"))
        .and_then(handle);

    match response {
        Ok(resp) => {
            emit(resp);
        }
        Err(error) => {
            emit(Response::Error { ok: false, error });
            std::process::exit(1);
        }
    }
}

fn emit(resp: Response) {
    let mut out = std::io::stdout();
    let _ = out.write_all(
        serde_json::to_string(&resp)
            .expect("serialize response")
            .as_bytes(),
    );
    let _ = out.write_all(b"\n");
}
