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

use indexone_attestation::{
    AttesterRole, CompletionAttestation, ThresholdAttestation, ThresholdError,
};
use indexone_chain::{Chain, ChainError, Scope};
use indexone_crypto::PublicKey;
use indexone_witness::{verify_inclusion, ActionReceipt, Digest};

/// Verifier-set policy for how strong an attestation must be — the piece that
/// makes "independent attestation" actually mean something (audit Findings 1
/// and 3). The *presenter* supplies the attestation; the *verifier* decides
/// what counts as sufficient, so a presenter can neither pick the weakest bar
/// nor pass a throwaway key off as an independent attester.
///
/// Fail-closed default: no trusted third-party attesters and counter-signing
/// disabled — i.e. nothing is accepted until the verifier names who it trusts.
#[derive(Debug, Clone, Default)]
pub struct VerifyPolicy {
    /// Attester keys the verifier trusts for a [`AttesterRole::ThirdParty`]
    /// attestation. A third-party completion is accepted only if its
    /// `attester_key` is in this set — a fresh/sockpuppet key is not.
    pub trusted_attesters: Vec<PublicKey>,
    /// Accept a [`AttesterRole::CounterSigned`] attestation when its
    /// `attester_key` is a real delegator present in the chain (and, as always,
    /// not the executor). Off by default: counter-signing is the weaker flow (a
    /// colluding delegator), so requiring it is a conscious choice.
    pub allow_counter_signed: bool,
}

impl VerifyPolicy {
    /// Require a third-party attestation from one of `trusted` keys.
    pub fn third_party(trusted: Vec<PublicKey>) -> Self {
        VerifyPolicy {
            trusted_attesters: trusted,
            allow_counter_signed: false,
        }
    }

    /// Accept a counter-signature from any genuine delegator in the chain.
    pub fn counter_signed() -> Self {
        VerifyPolicy {
            trusted_attesters: Vec::new(),
            allow_counter_signed: true,
        }
    }
}

/// Whether `key` is a genuine party in `chain` (the root principal, or any
/// hop's `from`/`to` key) — used to anchor a counter-signer's identity.
fn chain_has_key(chain: &Chain, key: &PublicKey) -> bool {
    chain.root.principal_key == *key
        || chain
            .delegations
            .iter()
            .any(|d| d.from_key == *key || d.to_key == *key)
}

/// Whether the completion's attester identity is anchored to something the
/// verifier trusts — not merely "some key that isn't the executor".
fn attester_is_anchored(
    chain: &Chain,
    completion: &CompletionAttestation,
    policy: &VerifyPolicy,
) -> bool {
    match completion.role {
        AttesterRole::ThirdParty => policy.trusted_attesters.contains(&completion.attester_key),
        AttesterRole::CounterSigned => {
            policy.allow_counter_signed && chain_has_key(chain, &completion.attester_key)
        }
    }
}

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
    #[error("attester not anchored: the attester's identity is not trusted for its role")]
    AttesterNotAnchored,
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
    policy: &VerifyPolicy,
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

    // 5. Completion is independently attested. Two parts, both required:
    //    (a) not self-reported by the executor, and genuinely signed; and
    //    (b) the attester's *identity* is anchored to something the verifier
    //        trusts for its role — a third party the verifier trusts, or a real
    //        delegator in the chain. Without (b), the executor could sign its
    //        own completion under a throwaway key and pass (audit Finding 1).
    action.completion.verify(action.chain.executor_key())?;
    if !attester_is_anchored(&action.chain, &action.completion, policy) {
        return Err(VerifyError::AttesterNotAnchored);
    }

    // 3/5. The attested request AND outcome must both be the action recorded in
    //      the witness — otherwise `requested_action_digest` floats free (audit
    //      Finding 2) and the attested outcome isn't tied to the logged leaf.
    if action.completion.outcome_digest != action.action_receipt.action_digest {
        return Err(VerifyError::OutcomeMismatch);
    }
    if action.completion.requested_action_digest != action.action_receipt.action_digest {
        return Err(VerifyError::ActionDigestInconsistent);
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
    policy: &VerifyPolicy,
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

    // 5c. Identity anchoring applies to the threshold path too (audit Finding 1):
    //     k *fresh* keys are distinct and independent of the executor, yet a
    //     Sybil. Every counted attester must be anchored to something the
    //     verifier trusts. Checked after independence so a bundle padded with the
    //     executor's own self-report still fails as "not enough independent".
    if bundle
        .attestations
        .iter()
        .any(|a| !attester_is_anchored(&action.chain, a, policy))
    {
        return Err(VerifyError::AttesterNotAnchored);
    }

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
            permissions: vec!["payments.charge".into()],
            budget: Some(budget),
            currency: Some("USD".to_string()),
            max_depth: depth,
            expires_at: 4_102_444_800,
        }
    }

    struct World {
        chain: Chain,
        root_key: PublicKey,
        executor: Ed25519Signer,  // agent C (final hop)
        delegator: Ed25519Signer, // agent B (a real hop; can counter-sign)
        notary: Ed25519Signer,    // an independent third-party attester (not in the chain)
    }

    /// Human → A(org1) → B(org2) → C(org3); C is the executor.
    fn build_chain() -> World {
        let human = Ed25519Signer::from_seed([1u8; 32]);
        let a = Ed25519Signer::from_seed([2u8; 32]);
        let b = Ed25519Signer::from_seed([3u8; 32]);
        let c = Ed25519Signer::from_seed([4u8; 32]);
        let notary = Ed25519Signer::from_seed([9u8; 32]);
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
            delegator: b,
            notary,
        }
    }

    /// A policy that trusts this world's notary as a third-party attester.
    fn trusting(world: &World) -> VerifyPolicy {
        VerifyPolicy::third_party(vec![world.notary.public_key()])
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
            nonce: [0xAB; 32],
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
            &world.notary,
            principal("attester:notary"),
            world.chain.digest(),
            action,
            action,
            root,
            proof,
        );
        let policy = trusting(&world);
        let va = VerifiableAction {
            chain: world.chain.clone(),
            action_receipt: receipt,
            completion,
        };
        assert!(verify(&va, &world.root_key, &root, &policy).is_ok());
    }

    #[test]
    fn omitted_action_is_invalid_even_with_valid_signatures() {
        // THE DAY-12 KILL TEST (lead case): an all-valid chain whose acted
        // digest was never witnessed → INVALID (omission).
        let world = build_chain();
        let (_recorded_receipt, proof, root) = record(&world.chain, [42u8; 32]);
        let omitted = [99u8; 32];
        let omitted_receipt = ActionReceipt {
            chain_digest: world.chain.digest(),
            action_digest: omitted,
            nonce: [0xAB; 32],
            prev_root: [0u8; 32],
        };
        let completion = CompletionAttestation::attest(
            &world.notary,
            principal("attester:notary"),
            world.chain.digest(),
            omitted,
            omitted,
            root,
            proof, // a real proof, but not for the omitted leaf
        );
        assert!(world.chain.verify(&world.root_key).is_ok()); // chain alone is valid
        let policy = trusting(&world);
        let va = VerifiableAction {
            chain: world.chain.clone(),
            action_receipt: omitted_receipt,
            completion,
        };
        assert_eq!(
            verify(&va, &world.root_key, &root, &policy).unwrap_err(),
            VerifyError::Omission
        );
    }

    #[test]
    fn self_reported_completion_is_invalid() {
        // The executing agent C signs its own completion (same key) → not
        // independent, INVALID.
        let world = build_chain();
        let action = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, action);
        let completion = CompletionAttestation::attest(
            &world.executor,
            principal("agent:c@org3"),
            world.chain.digest(),
            action,
            action,
            root,
            proof,
        );
        let policy = trusting(&world);
        let va = VerifiableAction {
            chain: world.chain.clone(),
            action_receipt: receipt,
            completion,
        };
        assert!(matches!(
            verify(&va, &world.root_key, &root, &policy).unwrap_err(),
            VerifyError::Attestation(_)
        ));
    }

    #[test]
    fn sockpuppet_key_attestation_is_rejected() {
        // AUDIT FINDING 1 (CRITICAL): the executor generates a fresh throwaway
        // keypair and "independently" attests its own work under a notary
        // principal. Key-inequality alone (attester != executor) accepts it; the
        // verifier must reject it because that key is not a trusted attester.
        let world = build_chain();
        let action = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, action);
        let sockpuppet = Ed25519Signer::from_seed([66u8; 32]); // controlled by the executor
        let completion = CompletionAttestation::attest(
            &sockpuppet,
            principal("attester:notary"), // lies about being a notary
            world.chain.digest(),
            action,
            action,
            root,
            proof,
        );
        // The policy trusts the REAL notary, not the sockpuppet key.
        let policy = trusting(&world);
        let va = VerifiableAction {
            chain: world.chain.clone(),
            action_receipt: receipt,
            completion,
        };
        assert_eq!(
            verify(&va, &world.root_key, &root, &policy).unwrap_err(),
            VerifyError::AttesterNotAnchored
        );
    }

    #[test]
    fn counter_signed_by_real_delegator_verifies() {
        // A genuine delegator (B, a hop in the chain) counter-signs → accepted
        // under a counter-signing policy (its key is anchored to the chain).
        let world = build_chain();
        let action = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, action);
        let completion = CompletionAttestation::attest_as(
            AttesterRole::CounterSigned,
            &world.delegator,
            principal("agent:b@org2"),
            world.chain.digest(),
            action,
            action,
            root,
            proof,
        );
        let policy = VerifyPolicy::counter_signed();
        let va = VerifiableAction {
            chain: world.chain.clone(),
            action_receipt: receipt,
            completion,
        };
        assert!(verify(&va, &world.root_key, &root, &policy).is_ok());
    }

    #[test]
    fn equivocated_root_is_invalid() {
        let world = build_chain();
        let action = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, action);
        let completion = CompletionAttestation::attest(
            &world.notary,
            principal("attester:notary"),
            world.chain.digest(),
            action,
            action,
            root,
            proof,
        );
        let policy = trusting(&world);
        let gossip_root = [123u8; 32];
        let va = VerifiableAction {
            chain: world.chain.clone(),
            action_receipt: receipt,
            completion,
        };
        assert_eq!(
            verify(&va, &world.root_key, &gossip_root, &policy).unwrap_err(),
            VerifyError::Equivocation
        );
    }

    #[test]
    fn dishonest_outcome_is_invalid() {
        let world = build_chain();
        let logged = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, logged);
        let completion = CompletionAttestation::attest(
            &world.notary,
            principal("attester:notary"),
            world.chain.digest(),
            logged,
            [7u8; 32], // attested outcome differs from what's in the log
            root,
            proof,
        );
        let policy = trusting(&world);
        let va = VerifiableAction {
            chain: world.chain.clone(),
            action_receipt: receipt,
            completion,
        };
        assert_eq!(
            verify(&va, &world.root_key, &root, &policy).unwrap_err(),
            VerifyError::OutcomeMismatch
        );
    }

    // A fresh third-party attester key, independent of the chain and executor
    // (distinct from `World::notary`, which uses seed [9; 32]).
    fn third_party() -> Ed25519Signer {
        Ed25519Signer::from_seed([10u8; 32])
    }

    #[test]
    fn spliced_receipt_from_another_chain_is_rejected() {
        // Receipt-splicing: a receipt minted for a *different* chain is presented
        // against this one. Chain-binding must reject it before anything else.
        let world = build_chain();
        let policy = trusting(&world);
        let action = [42u8; 32];
        let (mut receipt, proof, root) = record(&world.chain, action);
        receipt.chain_digest[0] ^= 0xFF; // now bound to a foreign chain
        let completion = CompletionAttestation::attest(
            &world.notary,
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
            verify(&va, &world.root_key, &root, &policy).unwrap_err(),
            VerifyError::ChainBindingMismatch
        );
    }

    #[test]
    fn spliced_attestation_from_another_chain_is_rejected() {
        // The dual: a completion attestation bound to a different chain digest.
        let world = build_chain();
        let action = [42u8; 32];
        let policy = trusting(&world);
        let (receipt, proof, root) = record(&world.chain, action);
        let mut foreign = world.chain.digest();
        foreign[0] ^= 0xFF;
        let completion = CompletionAttestation::attest(
            &world.notary,
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
            verify(&va, &world.root_key, &root, &policy).unwrap_err(),
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
        let policy = trusting(&world);
        let witnessed = [42u8; 32];
        let (receipt, proof, root) = record(&world.chain, witnessed);
        let completion = CompletionAttestation::attest(
            &world.notary,
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
            verify(&va, &world.root_key, &root, &policy).unwrap_err(),
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
            &world.notary,
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
        let policy =
            VerifyPolicy::third_party(vec![world.notary.public_key(), third_party().public_key()]);
        let bundle = ThresholdAttestation {
            attestations: vec![a1, a2],
            threshold: 2,
        };
        let vta = VerifiableThresholdAction {
            chain: world.chain,
            action_receipt: receipt,
            completion: bundle,
        };
        let effective = verify_threshold(&vta, &world.root_key, &root, 2, &policy).unwrap();
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
            &world.notary,
            principal("agent:b@org2"),
            world.chain.digest(),
            action,
            action,
            root,
            proof,
        );
        let policy = trusting(&world);
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
            verify_threshold(&vta, &world.root_key, &root, 2, &policy).unwrap_err(),
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
            &world.notary,
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
        let policy = trusting(&world);
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
            verify_threshold(&vta, &world.root_key, &root, 2, &policy).unwrap_err(),
            VerifyError::Threshold(ThresholdError::NotEnoughIndependentAttestations {
                have: 1,
                need: 2,
            })
        );
    }
}
