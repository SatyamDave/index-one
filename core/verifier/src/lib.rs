//! `indexone-verifier` — the composed `verify()` algorithm, fail-closed.
//!
//! This is where the whole thesis lands. A signed chain (`indexone-chain`)
//! already proves per-hop authenticity and monotonic attenuation — the crowded,
//! mostly-solved part. This crate adds the three things the competing drafts
//! punt (CLAUDE.md §6): completeness against a witnessed root (omission
//! becomes detectable), non-equivocation against a gossip-trusted root, and
//! independent completion attestation (not self-reported).
//!
//! The steps mirror CLAUDE.md §6's `verify()`:
//!   1–2. chain signatures + monotonic attenuation      → `indexone-chain`
//!   3.   action bound to the chain it ran under        → here
//!   4.   inclusion proof against a witnessed root       → here (**omission**)
//!   5.   completion independently attested + outcome    → here
//!   6.   witnessed root matches gossip-trusted root      → here (**equivocation**)
//!   7.   fail closed on any unresolved step             → typed `VerifyError`
//!
//! The `Day-12 kill test` (CLAUDE.md §9) is mechanized in this crate's tests:
//! an all-valid-signatures chain whose action was **omitted** from the witness,
//! or whose completion was **self-reported**, must return `INVALID` here even
//! though the chain alone verifies.

use indexone_attestation::{CompletionAttestation, ThresholdAttestation, ThresholdError};
use indexone_chain::{Chain, ChainError, Scope};
use indexone_crypto::PublicKey;
use indexone_witness::{verify_inclusion, ActionReceipt, Digest};

/// Everything a verifier needs to check one cross-org action end to end.
#[derive(Debug, Clone)]
pub struct VerifiableAction {
    /// The delegation chain the action ran under.
    pub chain: Chain,
    /// The receipt that must be present in the witness for this action.
    pub action_receipt: ActionReceipt,
    /// The independent completion attestation (carries its own witnessed root
    /// and inclusion proof).
    pub completion: CompletionAttestation,
}

/// [`VerifiableAction`] but with a k-of-n [`ThresholdAttestation`] in place of a
/// single completion. Verified by [`verify_threshold`].
#[derive(Debug, Clone)]
pub struct VerifiableThresholdAction {
    /// The delegation chain the action ran under.
    pub chain: Chain,
    /// The receipt that must be present in the witness for this action.
    pub action_receipt: ActionReceipt,
    /// The k-of-n bundle of independent completion attestations (each member
    /// carries its own witnessed root and inclusion proof).
    pub completion: ThresholdAttestation,
}

/// Why a verification failed. Each variant names the exact claimed property
/// that was violated (CLAUDE.md §11: fail closed with a typed reason).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("chain invalid: {0}")]
    Chain(#[from] ChainError),
    /// The action is not provably present in the witnessed log — the headline
    /// property (CLAUDE.md §9, lead with this).
    #[error("omission: the action has no inclusion proof against the witnessed root")]
    Omission,
    #[error("equivocation: the attested witness root does not match the gossip-trusted root")]
    Equivocation,
    #[error("completion not independently attested: {0}")]
    Attestation(#[from] indexone_attestation::AttestationError),
    #[error("outcome mismatch: the attested outcome is not the action recorded in the witness")]
    OutcomeMismatch,
    #[error("chain binding mismatch: receipt/attestation do not bind to this chain")]
    ChainBindingMismatch,
    /// The canonical action digest is not consistent across its views: what the
    /// attestation says was *requested* is not what the witness *recorded* (and,
    /// via the outcome gate, was attested). An executor that did something other
    /// than what was asked — and got it faithfully logged and attested — still
    /// fails here. Guards the "inconsistent canonical action digest" attack
    /// (CLAUDE.md §6 deliverable #3).
    #[error(
        "action digest inconsistent: the requested action is not the one recorded in the witness"
    )]
    ActionDigestInconsistent,
    /// A k-of-n bundle failed its threshold/independence rule.
    #[error("threshold attestation failed: {0}")]
    Threshold(#[from] ThresholdError),
    /// The presenter's k-of-n bundle declares a threshold below the bar this
    /// verifier requires. The sufficiency bar is verifier policy, never
    /// presenter-controlled — a bundle declaring a smaller `k` is rejected
    /// before its signatures are even examined.
    #[error("insufficient attestation: verifier requires {required} independent attesters, presenter declared {declared}")]
    InsufficientAttestation { required: usize, declared: usize },
}

/// Verify a cross-org action against a trusted root key and a gossip-trusted
/// witness root. Returns the effective (narrowest) [`Scope`] on success; fails
/// closed with a typed [`VerifyError`] otherwise.
pub fn verify(
    action: &VerifiableAction,
    root_key: &PublicKey,
    trusted_root: &Digest,
) -> Result<Scope, VerifyError> {
    // 1–2. Signatures + monotonic attenuation across the chain.
    let scope = action.chain.verify(root_key)?;
    let chain_digest = action.chain.digest();

    // 3. The action and the attestation must bind to *this* chain.
    if action.action_receipt.chain_digest != chain_digest
        || action.completion.chain_digest != chain_digest
    {
        return Err(VerifyError::ChainBindingMismatch);
    }

    // 6. Non-equivocation: the root the completion commits to must be the one
    //    gossip agrees on. (Checked before inclusion so a forged-root proof
    //    can't slip through against its own private root.)
    if action.completion.witnessed_root != *trusted_root {
        return Err(VerifyError::Equivocation);
    }

    // 4. Completeness: the action's receipt must be provably included under the
    //    witnessed root. No inclusion proof ⇒ provably omitted.
    if !verify_inclusion(
        &action.action_receipt,
        &action.completion.inclusion,
        trusted_root,
    ) {
        return Err(VerifyError::Omission);
    }

    // 5. Completion is independently attested (not self-reported) and its
    //    outcome is the very action recorded in the witness.
    action.completion.verify(action.chain.executor_key())?;
    if action.completion.outcome_digest != action.action_receipt.action_digest {
        return Err(VerifyError::OutcomeMismatch);
    }

    // 5b. Canonical action-digest consistency: what was *requested* must equal
    //     what the witness recorded (and, via the outcome gate, what was
    //     attested). Blocks an in-scope-but-different-from-requested action that
    //     was faithfully logged and attested from slipping through.
    if action.completion.requested_action_digest != action.action_receipt.action_digest {
        return Err(VerifyError::ActionDigestInconsistent);
    }

    // 7. Nothing unresolved — accept, returning what the final hop may do.
    Ok(scope)
}

/// [`verify`], with a k-of-n [`ThresholdAttestation`] in place of the single
/// completion. Same gates and fail-closed posture, plus a **presenter-cannot-
/// dilute sufficiency bar**: `required_threshold` is *this verifier's* policy,
/// and a bundle whose declared `threshold` is below it is rejected before any
/// signature is examined (CLAUDE.md §6 deliverable #3). Every bundle member must
/// bind this chain, commit to the gossip-trusted root, and carry a valid
/// inclusion proof; the k-of-n independence rule is enforced by
/// [`ThresholdAttestation::verify`].
pub fn verify_threshold(
    action: &VerifiableThresholdAction,
    root_key: &PublicKey,
    trusted_root: &Digest,
    required_threshold: usize,
) -> Result<Scope, VerifyError> {
    // 1–2. Signatures + monotonic attenuation across the chain.
    let scope = action.chain.verify(root_key)?;
    let chain_digest = action.chain.digest();
    let bundle = &action.completion;

    // 5a. Sufficiency bar first: the presenter cannot weaken the verifier's
    //     policy by declaring a smaller k.
    if bundle.threshold < required_threshold {
        return Err(VerifyError::InsufficientAttestation {
            required: required_threshold,
            declared: bundle.threshold,
        });
    }

    // 3. The receipt and every attestation must bind to *this* chain.
    if action.action_receipt.chain_digest != chain_digest
        || bundle
            .attestations
            .iter()
            .any(|a| a.chain_digest != chain_digest)
    {
        return Err(VerifyError::ChainBindingMismatch);
    }

    // 6. Non-equivocation: every attestation must commit to the gossip root.
    if bundle
        .attestations
        .iter()
        .any(|a| a.witnessed_root != *trusted_root)
    {
        return Err(VerifyError::Equivocation);
    }

    // 4. Completeness: every attester's inclusion proof must show the receipt
    //    under the witnessed root. An attester vouching with a proof that does
    //    not verify has attested an unwitnessed action — fail closed.
    for a in &bundle.attestations {
        if !verify_inclusion(&action.action_receipt, &a.inclusion, trusted_root) {
            return Err(VerifyError::Omission);
        }
    }

    // 5. The k-of-n independence rule (distinct keys, none the executor, shared
    //    binding, ≥ threshold individually valid).
    bundle.verify(action.chain.executor_key())?;

    // 5b. Outcome + requested-digest consistency. The bundle's binding
    //     consistency was just enforced, so checking one member covers all.
    for a in &bundle.attestations {
        if a.outcome_digest != action.action_receipt.action_digest {
            return Err(VerifyError::OutcomeMismatch);
        }
        if a.requested_action_digest != action.action_receipt.action_digest {
            return Err(VerifyError::ActionDigestInconsistent);
        }
    }

    Ok(scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexone_chain::{Principal, Scope};
    use indexone_crypto::{Ed25519Signer, Signer};
    use indexone_witness::Witness;

    fn principal(id: &str) -> Principal {
        Principal {
            id: id.to_string(),
            display_name: id.to_string(),
        }
    }

    fn scope(budget: u64, depth: u32) -> Scope {
        Scope {
            permissions: vec!["payments.charge".to_string()],
            budget: Some(budget),
            currency: Some("USD".to_string()),
            max_depth: depth,
            expires_at: 4_102_444_800,
        }
    }

    struct World {
        chain: Chain,
        root_key: PublicKey,
        executor: Ed25519Signer,
        attester: Ed25519Signer,
    }

    /// Human → A(org1) → B(org2) → C(org3); C is the executor.
    fn build_chain() -> World {
        let human = Ed25519Signer::from_seed([1u8; 32]);
        let a = Ed25519Signer::from_seed([2u8; 32]);
        let b = Ed25519Signer::from_seed([3u8; 32]);
        let c = Ed25519Signer::from_seed([4u8; 32]);
        let root_key = human.public_key();

        let mut chain = Chain::issue(&human, principal("human:alice"), scope(10_000, 3));
        chain
            .attenuate(
                &human,
                principal("agent:a@org1"),
                a.public_key(),
                scope(5_000, 2),
                "book travel".into(),
            )
            .unwrap();
        chain
            .attenuate(
                &a,
                principal("agent:b@org2"),
                b.public_key(),
                scope(5_000, 1),
                "charge airline".into(),
            )
            .unwrap();
        chain
            .attenuate(
                &b,
                principal("agent:c@org3"),
                c.public_key(),
                scope(4_000, 0),
                "settle fare".into(),
            )
            .unwrap();

        World {
            chain,
            root_key,
            executor: c,
            attester: b, // the delegator counter-signs — independent of executor C
        }
    }

    /// Append `action_digest` to a fresh witness and produce the receipt +
    /// inclusion proof + trusted root.
    fn record(
        chain: &Chain,
        action_digest: Digest,
    ) -> (ActionReceipt, indexone_witness::InclusionProof, Digest) {
        let mut w = Witness::new();
        let receipt = ActionReceipt {
            chain_digest: chain.digest(),
            action_digest,
            prev_root: w.root(),
        };
        let idx = w.append(&receipt);
        let proof = w.inclusion_proof(idx).unwrap();
        (receipt, proof, w.root())
    }

    #[test]
    fn honest_action_verifies() {
        let world = build_chain();
        let action = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, action);
        let completion = CompletionAttestation::attest(
            &world.attester,
            principal("agent:b@org2"),
            world.chain.digest(),
            action,
            action,
            root,
            proof,
        );
        let va = VerifiableAction {
            chain: world.chain,
            action_receipt: receipt,
            completion,
        };
        assert!(verify(&va, &world.root_key, &root).is_ok());
    }

    #[test]
    fn omitted_action_is_invalid_even_with_valid_signatures() {
        // THE DAY-12 KILL TEST (lead case). Every signature in the chain is
        // valid and attenuation holds — the chain alone verifies. But the acted
        // digest was never appended to the witness: the receipt we present is
        // for an action absent from the log, so no inclusion proof folds to the
        // honest root. Must be INVALID (omission).
        let world = build_chain();
        let recorded = [42u8; 32];
        let (_recorded_receipt, proof, root) = record(&world.chain, recorded);

        // The verifier is asked about a *different* action that was never logged.
        let omitted = [99u8; 32];
        let omitted_receipt = ActionReceipt {
            chain_digest: world.chain.digest(),
            action_digest: omitted,
            prev_root: [0u8; 32],
        };
        let completion = CompletionAttestation::attest(
            &world.attester,
            principal("agent:b@org2"),
            world.chain.digest(),
            omitted,
            omitted,
            root,
            proof, // reusing a real proof — it still won't cover the omitted leaf
        );

        // Sanity: the chain by itself is valid.
        assert!(world.chain.verify(&world.root_key).is_ok());

        let va = VerifiableAction {
            chain: world.chain,
            action_receipt: omitted_receipt,
            completion,
        };
        assert_eq!(
            verify(&va, &world.root_key, &root).unwrap_err(),
            VerifyError::Omission
        );
    }

    #[test]
    fn self_reported_completion_is_invalid() {
        // DAY-12 KILL TEST (supporting case). The executing agent C signs its
        // own completion. Chain + inclusion are fine, but a self-reported
        // completion is not independent — INVALID.
        let world = build_chain();
        let action = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, action);
        let completion = CompletionAttestation::attest(
            &world.executor, // C attests its own work
            principal("agent:c@org3"),
            world.chain.digest(),
            action,
            action,
            root,
            proof,
        );
        let va = VerifiableAction {
            chain: world.chain,
            action_receipt: receipt,
            completion,
        };
        let err = verify(&va, &world.root_key, &root).unwrap_err();
        assert!(matches!(err, VerifyError::Attestation(_)));
    }

    #[test]
    fn equivocated_root_is_invalid() {
        // The attestation commits to a witness root that gossip does not agree
        // on — a forked-log view. INVALID (equivocation).
        let world = build_chain();
        let action = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, action);
        let completion = CompletionAttestation::attest(
            &world.attester,
            principal("agent:b@org2"),
            world.chain.digest(),
            action,
            action,
            root,
            proof,
        );
        let va = VerifiableAction {
            chain: world.chain,
            action_receipt: receipt,
            completion,
        };
        let gossip_root = [123u8; 32]; // what everyone else sees
        assert_eq!(
            verify(&va, &world.root_key, &gossip_root).unwrap_err(),
            VerifyError::Equivocation
        );
    }

    #[test]
    fn dishonest_outcome_is_invalid() {
        // The witness records action X, but the completion attests outcome Y.
        let world = build_chain();
        let logged = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, logged);
        let completion = CompletionAttestation::attest(
            &world.attester,
            principal("agent:b@org2"),
            world.chain.digest(),
            logged,
            [7u8; 32], // attested outcome differs from what's in the log
            root,
            proof,
        );
        let va = VerifiableAction {
            chain: world.chain,
            action_receipt: receipt,
            completion,
        };
        assert_eq!(
            verify(&va, &world.root_key, &root).unwrap_err(),
            VerifyError::OutcomeMismatch
        );
    }

    // A fresh third-party attester key, independent of the chain and executor.
    fn third_party() -> Ed25519Signer {
        Ed25519Signer::from_seed([9u8; 32])
    }

    #[test]
    fn spliced_receipt_from_another_chain_is_rejected() {
        // Receipt-splicing: a receipt minted for a *different* chain is presented
        // against this one. Chain-binding must reject it before anything else.
        let world = build_chain();
        let action = [42u8; 32];
        let (mut receipt, proof, root) = record(&world.chain, action);
        receipt.chain_digest[0] ^= 0xFF; // now bound to a foreign chain
        let completion = CompletionAttestation::attest(
            &world.attester,
            principal("agent:b@org2"),
            world.chain.digest(),
            action,
            action,
            root,
            proof,
        );
        let va = VerifiableAction {
            chain: world.chain,
            action_receipt: receipt,
            completion,
        };
        assert_eq!(
            verify(&va, &world.root_key, &root).unwrap_err(),
            VerifyError::ChainBindingMismatch
        );
    }

    #[test]
    fn spliced_attestation_from_another_chain_is_rejected() {
        // The dual: a completion attestation bound to a different chain digest.
        let world = build_chain();
        let action = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, action);
        let mut foreign = world.chain.digest();
        foreign[0] ^= 0xFF;
        let completion = CompletionAttestation::attest(
            &world.attester,
            principal("agent:b@org2"),
            foreign, // attestation minted against a foreign chain
            action,
            action,
            root,
            proof,
        );
        let va = VerifiableAction {
            chain: world.chain,
            action_receipt: receipt,
            completion,
        };
        assert_eq!(
            verify(&va, &world.root_key, &root).unwrap_err(),
            VerifyError::ChainBindingMismatch
        );
    }

    #[test]
    fn requested_action_differs_from_witnessed_is_rejected() {
        // Inconsistent canonical action digest: the witness recorded (and the
        // attester observed as outcome) action X, but the attestation claims a
        // *different* requested action Y. Faithfully logged and attested, yet a
        // different action than asked — must fail closed.
        let world = build_chain();
        let witnessed = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, witnessed);
        let completion = CompletionAttestation::attest(
            &world.attester,
            principal("agent:b@org2"),
            world.chain.digest(),
            [99u8; 32], // requested != witnessed
            witnessed,  // outcome == witnessed, so the outcome gate passes
            root,
            proof,
        );
        let va = VerifiableAction {
            chain: world.chain,
            action_receipt: receipt,
            completion,
        };
        assert_eq!(
            verify(&va, &world.root_key, &root).unwrap_err(),
            VerifyError::ActionDigestInconsistent
        );
    }

    #[test]
    fn threshold_two_of_two_independent_verifies() {
        // Two distinct attesters independent of the executor (delegator B + an
        // outside third party) over the same action → the k-of-n bundle holds.
        let world = build_chain();
        let action = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, action);
        let cd = world.chain.digest();
        let a1 = CompletionAttestation::attest(
            &world.attester,
            principal("agent:b@org2"),
            cd,
            action,
            action,
            root,
            proof.clone(),
        );
        let a2 = CompletionAttestation::attest(
            &third_party(),
            principal("attester:notary"),
            cd,
            action,
            action,
            root,
            proof,
        );
        let bundle = ThresholdAttestation {
            attestations: vec![a1, a2],
            threshold: 2,
        };
        let vta = VerifiableThresholdAction {
            chain: world.chain,
            action_receipt: receipt,
            completion: bundle,
        };
        let effective = verify_threshold(&vta, &world.root_key, &root, 2).unwrap();
        assert_eq!(effective.budget, Some(4_000));
    }

    #[test]
    fn threshold_below_verifier_bar_is_rejected() {
        // Presenter-controlled sufficiency: a bundle declaring k=1 cannot satisfy
        // a verifier that requires 2, even if that one attestation is valid.
        let world = build_chain();
        let action = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, action);
        let a1 = CompletionAttestation::attest(
            &world.attester,
            principal("agent:b@org2"),
            world.chain.digest(),
            action,
            action,
            root,
            proof,
        );
        let bundle = ThresholdAttestation {
            attestations: vec![a1],
            threshold: 1, // presenter tries to lower the bar
        };
        let vta = VerifiableThresholdAction {
            chain: world.chain,
            action_receipt: receipt,
            completion: bundle,
        };
        assert_eq!(
            verify_threshold(&vta, &world.root_key, &root, 2).unwrap_err(),
            VerifyError::InsufficientAttestation {
                required: 2,
                declared: 1,
            }
        );
    }

    #[test]
    fn threshold_with_a_self_report_lacks_independence() {
        // A 2-of-2 bundle where one "attester" is the executor signing its own
        // work: only one independent attestation counts, so k is unmet.
        let world = build_chain();
        let action = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, action);
        let cd = world.chain.digest();
        let independent = CompletionAttestation::attest(
            &world.attester,
            principal("agent:b@org2"),
            cd,
            action,
            action,
            root,
            proof.clone(),
        );
        let self_report = CompletionAttestation::attest(
            &world.executor, // C attests its own work — does not count
            principal("agent:c@org3"),
            cd,
            action,
            action,
            root,
            proof,
        );
        let bundle = ThresholdAttestation {
            attestations: vec![independent, self_report],
            threshold: 2,
        };
        let vta = VerifiableThresholdAction {
            chain: world.chain,
            action_receipt: receipt,
            completion: bundle,
        };
        assert_eq!(
            verify_threshold(&vta, &world.root_key, &root, 2).unwrap_err(),
            VerifyError::Threshold(ThresholdError::NotEnoughIndependentAttestations {
                have: 1,
                need: 2,
            })
        );
    }
}
