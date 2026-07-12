//! `indexone-attestation` — independent completion attestation.
//!
//! AIP's completion block is self-reported by default: the very agent whose
//! work is being judged signs "done" (CLAUDE.md §6, the seam). That's marking
//! your own homework. This crate replaces it with a [`CompletionAttestation`]
//! signed by *someone other than the executing agent* — a counter-signing
//! delegator or a third-party attester.
//!
//! An attestation binds, per CLAUDE.md §6 deliverable #2: the requested action
//! digest + the delegation chain + the observed outcome digest + a witness
//! inclusion proof. The **independence** check (attester ≠ executor) lives in
//! [`CompletionAttestation::verify`]; the composed `verifier` crate cross-checks
//! the outcome and inclusion against the chain and witnessed root.
//!
//! Scope boundary (CLAUDE.md §4): an attestation is exactly as strong as the
//! attester's visibility into ground truth. This crate proves *who* signed and
//! *that it wasn't the executor* — not that the outcome is physically true.

use indexone_chain::Principal;
use indexone_crypto::{verify_signature, PublicKey, Signer};
use indexone_witness::{Digest, InclusionProof};
use serde::{Deserialize, Serialize};

/// A completion signed by a party other than the executing agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionAttestation {
    /// Digest of the delegation chain the action ran under (`Chain::digest`).
    pub chain_digest: Digest,
    /// Digest of what was requested.
    pub requested_action_digest: Digest,
    /// Digest of what the attester observed actually happened.
    pub outcome_digest: Digest,
    /// Witness Merkle root this attestation commits to.
    pub witnessed_root: Digest,
    /// Proof the action's receipt is included under `witnessed_root`.
    pub inclusion: InclusionProof,
    /// Who is attesting (must not be the executing agent).
    pub attester: Principal,
    pub attester_key: PublicKey,
    pub signature: indexone_crypto::Signature,
}

/// Errors from checking an attestation.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AttestationError {
    #[error("not independent: completion was signed by the executing agent itself")]
    NotIndependent,
    #[error("attestation signature invalid")]
    SignatureInvalid,
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<indexone_crypto::CryptoError> for AttestationError {
    fn from(e: indexone_crypto::CryptoError) -> Self {
        AttestationError::Crypto(e.to_string())
    }
}

/// Canonical bytes an attestation's signature covers (everything but the
/// signature). TODO(attestation): RFC 8785 JCS before this is a wire format.
#[allow(clippy::too_many_arguments)]
fn signing_payload(
    chain_digest: &Digest,
    requested: &Digest,
    outcome: &Digest,
    witnessed_root: &Digest,
    inclusion: &InclusionProof,
    attester: &Principal,
    attester_key: &PublicKey,
) -> Vec<u8> {
    serde_json::to_vec(&(
        chain_digest,
        requested,
        outcome,
        witnessed_root,
        inclusion,
        attester,
        attester_key,
    ))
    .expect("serializable")
}

impl CompletionAttestation {
    /// Build and sign an attestation with `signer` (the attester's key). Callers
    /// must ensure `signer` is not the executing agent — [`Self::verify`]
    /// enforces it, but the intent belongs at construction time too.
    #[allow(clippy::too_many_arguments)]
    pub fn attest(
        signer: &dyn Signer,
        attester: Principal,
        chain_digest: Digest,
        requested_action_digest: Digest,
        outcome_digest: Digest,
        witnessed_root: Digest,
        inclusion: InclusionProof,
    ) -> Self {
        let attester_key = signer.public_key();
        let payload = signing_payload(
            &chain_digest,
            &requested_action_digest,
            &outcome_digest,
            &witnessed_root,
            &inclusion,
            &attester,
            &attester_key,
        );
        let signature = signer.sign(&payload).expect("sign attestation");
        CompletionAttestation {
            chain_digest,
            requested_action_digest,
            outcome_digest,
            witnessed_root,
            inclusion,
            attester,
            attester_key,
            signature,
        }
    }

    /// Verify the attestation is (a) not self-reported by `executor_key` and
    /// (b) genuinely signed by the named attester. Fails closed.
    ///
    /// Cross-checks of outcome/inclusion against the chain and witnessed root
    /// are the composed verifier's job, not this method's.
    pub fn verify(&self, executor_key: &PublicKey) -> Result<(), AttestationError> {
        if self.attester_key == *executor_key {
            return Err(AttestationError::NotIndependent);
        }
        let payload = signing_payload(
            &self.chain_digest,
            &self.requested_action_digest,
            &self.outcome_digest,
            &self.witnessed_root,
            &self.inclusion,
            &self.attester,
            &self.attester_key,
        );
        if !verify_signature(&payload, &self.signature, &self.attester_key)? {
            return Err(AttestationError::SignatureInvalid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexone_crypto::Ed25519Signer;

    fn principal(id: &str) -> Principal {
        Principal {
            id: id.to_string(),
            display_name: id.to_string(),
        }
    }

    fn dummy_inclusion() -> InclusionProof {
        InclusionProof {
            leaf_index: 0,
            tree_size: 1,
            path: vec![],
        }
    }

    #[test]
    fn independent_attestation_verifies() {
        let executor = Ed25519Signer::from_seed([4u8; 32]); // agent C
        let attester = Ed25519Signer::from_seed([5u8; 32]); // a third party
        let att = CompletionAttestation::attest(
            &attester,
            principal("attester:notary"),
            [1u8; 32],
            [2u8; 32],
            [2u8; 32],
            [3u8; 32],
            dummy_inclusion(),
        );
        assert!(att.verify(&executor.public_key()).is_ok());
    }

    #[test]
    fn self_reported_completion_is_rejected() {
        // Claim targets AIP's admitted non-goal made into a caught property:
        // the executing agent signing its own completion must fail closed.
        let executor = Ed25519Signer::from_seed([4u8; 32]);
        let att = CompletionAttestation::attest(
            &executor, // agent C attests its own work
            principal("agent:c@org3"),
            [1u8; 32],
            [2u8; 32],
            [2u8; 32],
            [3u8; 32],
            dummy_inclusion(),
        );
        assert_eq!(
            att.verify(&executor.public_key()).unwrap_err(),
            AttestationError::NotIndependent
        );
    }

    #[test]
    fn tampered_outcome_breaks_signature() {
        let executor = Ed25519Signer::from_seed([4u8; 32]);
        let attester = Ed25519Signer::from_seed([5u8; 32]);
        let mut att = CompletionAttestation::attest(
            &attester,
            principal("attester:notary"),
            [1u8; 32],
            [2u8; 32],
            [2u8; 32],
            [3u8; 32],
            dummy_inclusion(),
        );
        att.outcome_digest = [9u8; 32]; // forge the reported outcome
        assert_eq!(
            att.verify(&executor.public_key()).unwrap_err(),
            AttestationError::SignatureInvalid
        );
    }
}
