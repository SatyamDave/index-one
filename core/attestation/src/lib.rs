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
use std::collections::HashSet;

/// Which of the two independence flows an attestation represents
/// (CLAUDE.md §6 deliverable #2). Both mean "signed by someone other than the
/// executing agent"; they differ in *who* that someone is — which is exactly
/// the distinction a relying party wants to see recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttesterRole {
    /// The immediate delegator — the agent one hop up the chain — counter-signs
    /// the executor's completion. Independent of the executor, but part of the
    /// delegation chain.
    CounterSigned,
    /// An external party not in the delegation chain (a notary/auditor) attests.
    ThirdParty,
}

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
    /// Which independence flow this attestation represents. Signed, so it can't
    /// be relabelled after the fact.
    pub role: AttesterRole,
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
/// signature), in RFC 8785 (JCS) form for cross-implementation verifiability.
#[allow(clippy::too_many_arguments)]
fn signing_payload(
    chain_digest: &Digest,
    requested: &Digest,
    outcome: &Digest,
    witnessed_root: &Digest,
    inclusion: &InclusionProof,
    attester: &Principal,
    attester_key: &PublicKey,
    role: &AttesterRole,
) -> Vec<u8> {
    serde_jcs::to_vec(&(
        chain_digest,
        requested,
        outcome,
        witnessed_root,
        inclusion,
        attester,
        attester_key,
        role,
    ))
    .expect("serializable")
}

impl CompletionAttestation {
    /// Build and sign an attestation with `signer` (the attester's key),
    /// recording which independence flow it represents. Callers must ensure
    /// `signer` is not the executing agent — [`Self::verify`] enforces it, but
    /// the intent belongs at construction time too.
    #[allow(clippy::too_many_arguments)]
    pub fn attest_as(
        role: AttesterRole,
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
            &role,
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
            role,
            signature,
        }
    }

    /// Build and sign an attestation, defaulting the flow to
    /// [`AttesterRole::ThirdParty`]. Backward-compatible entry point for callers
    /// (e.g. the `verifier` crate) that don't distinguish the flow; use
    /// [`Self::attest_as`] to record a counter-signing delegator explicitly.
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
        Self::attest_as(
            AttesterRole::ThirdParty,
            signer,
            attester,
            chain_digest,
            requested_action_digest,
            outcome_digest,
            witnessed_root,
            inclusion,
        )
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
            &self.role,
        );
        if !verify_signature(&payload, &self.signature, &self.attester_key)? {
            return Err(AttestationError::SignatureInvalid);
        }
        Ok(())
    }
}

/// A k-of-n aggregate completion attestation: the completion holds only if at
/// least `threshold` *distinct, independent* attesters each vouch for the *same*
/// action (CLAUDE.md §6 #2). This raises the bar past a single counter-signer —
/// no lone attester's word decides completion, and one compromised attester
/// can't fabricate it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdAttestation {
    /// The candidate attestations. Order is irrelevant; only distinct,
    /// independently-valid ones over a shared binding count.
    pub attestations: Vec<CompletionAttestation>,
    /// How many independent, distinct attesters must vouch (the `k` in k-of-n).
    pub threshold: usize,
}

/// Why a [`ThresholdAttestation`] failed to hold. Each variant names the exact
/// property that was violated (fail closed).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ThresholdError {
    #[error("not enough independent attestations: have {have}, need {need}")]
    NotEnoughIndependentAttestations { have: usize, need: usize },
    #[error("duplicate attester: two attestations were signed under the same attester key")]
    DuplicateAttester,
    #[error(
        "inconsistent binding: attestations do not all commit to the same \
         (chain, requested action, outcome, witnessed root)"
    )]
    InconsistentBinding,
}

impl ThresholdAttestation {
    /// The (chain, requested action, outcome, witnessed root) tuple every
    /// attestation in the aggregate must agree on.
    fn binding(a: &CompletionAttestation) -> (&Digest, &Digest, &Digest, &Digest) {
        (
            &a.chain_digest,
            &a.requested_action_digest,
            &a.outcome_digest,
            &a.witnessed_root,
        )
    }

    /// Verify the aggregate against the executing agent's key. Holds only if:
    /// 1. every attestation binds the *same* (chain, requested, outcome, root)
    ///    — otherwise they're not about one action ([`ThresholdError::InconsistentBinding`]);
    /// 2. no two share an attester key — one party can't be counted twice
    ///    ([`ThresholdError::DuplicateAttester`]);
    /// 3. at least `threshold` of them *individually* verify — each independent
    ///    of `executor_key` and correctly signed. An executor self-report or a
    ///    bad signature simply doesn't count
    ///    ([`ThresholdError::NotEnoughIndependentAttestations`]).
    ///
    /// Fails closed on the first property violated.
    pub fn verify(&self, executor_key: &PublicKey) -> Result<(), ThresholdError> {
        // 1. All attestations must be about the same action.
        if let Some(first) = self.attestations.first() {
            let binding = Self::binding(first);
            if self
                .attestations
                .iter()
                .any(|a| Self::binding(a) != binding)
            {
                return Err(ThresholdError::InconsistentBinding);
            }
        }

        // 2. Distinct attester keys — padding the set with copies is rejected,
        //    never silently deduped.
        let mut seen = HashSet::new();
        for a in &self.attestations {
            if !seen.insert(&a.attester_key) {
                return Err(ThresholdError::DuplicateAttester);
            }
        }

        // 3. Count only those that individually verify (independent + valid sig).
        let have = self
            .attestations
            .iter()
            .filter(|a| a.verify(executor_key).is_ok())
            .count();
        if have < self.threshold {
            return Err(ThresholdError::NotEnoughIndependentAttestations {
                have,
                need: self.threshold,
            });
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

    // ---- threshold attestation ----

    /// One attester over the shared test binding (chain=1, requested=2,
    /// outcome=2, root=3), so distinct seeds differ only by attester key.
    fn shared(signer: &Ed25519Signer, role: AttesterRole, id: &str) -> CompletionAttestation {
        CompletionAttestation::attest_as(
            role,
            signer,
            principal(id),
            [1u8; 32],
            [2u8; 32],
            [2u8; 32],
            [3u8; 32],
            dummy_inclusion(),
        )
    }

    #[test]
    fn threshold_holds_at_exactly_k_independent_attesters() {
        // Claim: k distinct, independent attesters over the same binding satisfy
        // a k-of-n threshold — completion no longer rests on one party's word.
        let executor = Ed25519Signer::from_seed([4u8; 32]);
        let atts: Vec<_> = [[5u8; 32], [6u8; 32], [7u8; 32]]
            .iter()
            .enumerate()
            .map(|(i, s)| {
                shared(
                    &Ed25519Signer::from_seed(*s),
                    AttesterRole::ThirdParty,
                    &format!("attester:{i}"),
                )
            })
            .collect();
        let agg = ThresholdAttestation {
            attestations: atts,
            threshold: 3,
        };
        assert!(agg.verify(&executor.public_key()).is_ok());
    }

    #[test]
    fn threshold_fails_one_short() {
        // Claim: k-1 independent attesters do NOT meet a k-of-n threshold; it
        // fails closed, naming how many it had versus needed.
        let executor = Ed25519Signer::from_seed([4u8; 32]);
        let a1 = Ed25519Signer::from_seed([5u8; 32]);
        let a2 = Ed25519Signer::from_seed([6u8; 32]);
        let agg = ThresholdAttestation {
            attestations: vec![
                shared(&a1, AttesterRole::ThirdParty, "attester:1"),
                shared(&a2, AttesterRole::ThirdParty, "attester:2"),
            ],
            threshold: 3,
        };
        assert_eq!(
            agg.verify(&executor.public_key()).unwrap_err(),
            ThresholdError::NotEnoughIndependentAttestations { have: 2, need: 3 }
        );
    }

    #[test]
    fn duplicate_attester_key_is_rejected() {
        // Claim: one attester cannot be counted twice — a second signature under
        // the same key is rejected outright, not silently deduped into a pass.
        let executor = Ed25519Signer::from_seed([4u8; 32]);
        let a1 = Ed25519Signer::from_seed([5u8; 32]);
        let agg = ThresholdAttestation {
            attestations: vec![
                shared(&a1, AttesterRole::ThirdParty, "attester:1"),
                shared(&a1, AttesterRole::ThirdParty, "attester:1"), // same key again
            ],
            threshold: 2,
        };
        assert_eq!(
            agg.verify(&executor.public_key()).unwrap_err(),
            ThresholdError::DuplicateAttester
        );
    }

    #[test]
    fn executor_signed_attestation_does_not_count() {
        // Claim: a self-report by the executing agent contributes nothing to the
        // threshold. Three attestations are present but one is the executor's
        // own, so only two are independent — one short of a 3-of-n bar.
        let executor = Ed25519Signer::from_seed([4u8; 32]);
        let a1 = Ed25519Signer::from_seed([5u8; 32]);
        let a2 = Ed25519Signer::from_seed([6u8; 32]);
        let agg = ThresholdAttestation {
            attestations: vec![
                shared(&a1, AttesterRole::ThirdParty, "attester:1"),
                shared(&a2, AttesterRole::ThirdParty, "attester:2"),
                shared(&executor, AttesterRole::ThirdParty, "agent:c@org3"), // self-report
            ],
            threshold: 3,
        };
        assert_eq!(
            agg.verify(&executor.public_key()).unwrap_err(),
            ThresholdError::NotEnoughIndependentAttestations { have: 2, need: 3 }
        );
    }

    #[test]
    fn inconsistent_binding_is_rejected() {
        // Claim: attesters must vouch for the SAME (chain, action, outcome,
        // root). A threshold cannot be assembled from signatures over different
        // outcomes, even if each signature is individually valid.
        let executor = Ed25519Signer::from_seed([4u8; 32]);
        let a1 = Ed25519Signer::from_seed([5u8; 32]);
        let a2 = Ed25519Signer::from_seed([6u8; 32]);
        let att1 = shared(&a1, AttesterRole::ThirdParty, "attester:1");
        // att2 attests a different observed outcome → a different binding.
        let att2 = CompletionAttestation::attest_as(
            AttesterRole::ThirdParty,
            &a2,
            principal("attester:2"),
            [1u8; 32],
            [2u8; 32],
            [9u8; 32], // divergent outcome
            [3u8; 32],
            dummy_inclusion(),
        );
        let agg = ThresholdAttestation {
            attestations: vec![att1, att2],
            threshold: 2,
        };
        assert_eq!(
            agg.verify(&executor.public_key()).unwrap_err(),
            ThresholdError::InconsistentBinding
        );
    }

    #[test]
    fn counter_signed_and_third_party_roles_both_usable() {
        // Claim: both independence flows CLAUDE.md §6 names are expressible and
        // verifiable — a counter-signing delegator and an external third party
        // each stand as an independent attester, together meeting a 2-of-2 bar.
        let executor = Ed25519Signer::from_seed([4u8; 32]);
        let delegator = Ed25519Signer::from_seed([3u8; 32]); // agent B, C's delegator
        let notary = Ed25519Signer::from_seed([8u8; 32]); // outside party
        let counter = shared(&delegator, AttesterRole::CounterSigned, "agent:b@org2");
        let third = shared(&notary, AttesterRole::ThirdParty, "attester:notary");

        // The recorded flow is preserved (and, being signed, tamper-evident).
        assert_eq!(counter.role, AttesterRole::CounterSigned);
        assert_eq!(third.role, AttesterRole::ThirdParty);
        // Each verifies independently of the executor...
        assert!(counter.verify(&executor.public_key()).is_ok());
        assert!(third.verify(&executor.public_key()).is_ok());
        // ...and together satisfy the threshold.
        let agg = ThresholdAttestation {
            attestations: vec![counter, third],
            threshold: 2,
        };
        assert!(agg.verify(&executor.public_key()).is_ok());
    }
}
