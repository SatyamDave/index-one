//! `indexone-cli` — a thin JSON-over-stdio sidecar over the IndexOne core.
//!
//! Non-Rust SDKs (Python, TypeScript) bind to the real chain + crypto through
//! this binary instead of reimplementing any of it (CLAUDE.md §11: SDKs are thin
//! bindings, not a second implementation). It reads exactly one JSON request
//! object from stdin and writes exactly one JSON response object to stdout.
//!
//! Requests (tagged by `cmd`):
//!   {"cmd":"issue","seed":"<hex32>","principal":{"id":..,"display_name":..},"scope":{..}}
//!     → {"ok":true,"chain":<Chain>,"root_key":<PublicKey>}
//!   {"cmd":"attenuate","chain":<Chain>,"signer_seed":"<hex32>",
//!    "to":{..},"to_seed":"<hex32>","scope":{..},"purpose":".."}
//!     → {"ok":true,"chain":<Chain>,"to_key":<PublicKey>}
//!   {"cmd":"verify","chain":<Chain>,"root_key":<PublicKey>}
//!     → {"ok":true,"effective_scope":<Scope>}   (fail closed → {"ok":false,"error":".."})
//!
//! Key material is a 32-byte hex seed (the client manages its own seeds); the
//! sidecar derives the Ed25519 keypair deterministically. Any error is reported
//! as {"ok":false,"error":".."} with a non-zero exit — never a silent success.

use std::io::{Read, Write};

use indexone_chain::{Chain, Principal, Scope};
use indexone_crypto::{Ed25519Signer, PublicKey, Signer};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
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
}

#[derive(Serialize)]
#[serde(untagged)]
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
    Verify {
        ok: bool,
        effective_scope: Scope,
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
            Ok(Response::Verify {
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
