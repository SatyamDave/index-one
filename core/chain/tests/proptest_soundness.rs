//! Property-based soundness tests for the delegation chain.
//!
//! The chain's whole promise is "authority only ever narrows, and any tampering
//! is caught." These properties assert that over thousands of random chains:
//! a validly-built chain always verifies; `attenuate` refuses every widening
//! (more budget, a new permission, or non-decreasing depth); mutating *any*
//! signed field of *any* block makes verification fail closed; the wrong root
//! key is rejected; and feeding arbitrary bytes to the deserializer + verifier
//! never panics.

use indexone_chain::{Chain, ChainError, Permission, Principal, Scope};
use indexone_crypto::{Ed25519Signer, PublicKey, Signer};
use proptest::prelude::*;

const FAR: u64 = 4_102_444_800;

fn principal(id: &str) -> Principal {
    Principal {
        id: id.to_string(),
        display_name: id.to_string(),
    }
}

fn scope(budget: u64, depth: u32) -> Scope {
    Scope {
        permissions: vec![Permission::action("payments.charge")],
        budget: Some(budget),
        currency: Some("USD".to_string()),
        max_depth: depth,
        expires_at: FAR,
    }
}

/// A valid `n_hops`-deep chain, budget `base` at every hop (equal budgets are a
/// valid narrowing), depth strictly decreasing to 0. Returns it + its root key.
fn build(n_hops: u32, base: u64) -> (Chain, PublicKey) {
    let human = Ed25519Signer::from_seed([1u8; 32]);
    let root_key = human.public_key();
    let mut chain = Chain::issue(&human, principal("human"), scope(base, n_hops));
    let mut current: Box<dyn Signer> = Box::new(Ed25519Signer::from_seed([1u8; 32]));
    for i in 0..n_hops {
        let next = Ed25519Signer::from_seed([(i + 2) as u8; 32]);
        chain
            .attenuate(
                current.as_ref(),
                principal(&format!("agent{i}")),
                next.public_key(),
                scope(base, n_hops - i - 1),
                format!("hop {i}"),
            )
            .expect("narrowing hop must be accepted");
        current = Box::new(next);
    }
    (chain, root_key)
}

proptest! {
    /// A validly-built chain verifies, and the effective scope is the narrowest
    /// (last) hop's budget.
    #[test]
    fn valid_chain_verifies(n_hops in 0u32..6, base in 1u64..1_000_000) {
        let (chain, root_key) = build(n_hops, base);
        let effective = chain.verify(&root_key).expect("valid chain must verify");
        prop_assert_eq!(effective.budget, Some(base));
    }

    /// `attenuate` refuses every widening: more budget, an unheld permission, or
    /// a non-decreasing depth. Authority can only ever shrink.
    #[test]
    fn attenuate_refuses_widening(base in 1u64..1_000_000, extra in 1u64..1_000_000) {
        let human = Ed25519Signer::from_seed([1u8; 32]);
        let a = Ed25519Signer::from_seed([2u8; 32]);

        // Widen the budget.
        let mut c = Chain::issue(&human, principal("human"), scope(base, 2));
        let widen_budget = c.attenuate(&human, principal("a"), a.public_key(), scope(base + extra, 1), "grab".into());
        prop_assert_eq!(widen_budget.unwrap_err(), ChainError::ScopeWidened);

        // Add a permission the parent never held.
        let mut c = Chain::issue(&human, principal("human"), scope(base, 2));
        let mut wider = scope(base, 1);
        wider.permissions.push(Permission::action("payments.refund"));
        prop_assert_eq!(c.attenuate(&human, principal("a"), a.public_key(), wider, "grab".into()).unwrap_err(), ChainError::ScopeWidened);

        // Depth that does not strictly decrease.
        let mut c = Chain::issue(&human, principal("human"), scope(base, 2));
        prop_assert!(c.attenuate(&human, principal("a"), a.public_key(), scope(base, 2), "grab".into()).is_err());
    }

    /// Mutating any signed field of any block makes verification fail closed.
    #[test]
    fn mutating_any_signed_field_is_rejected(
        n_hops in 1u32..6,
        base in 2u64..1_000_000,
        block in any::<prop::sample::Index>(),
        which in 0u8..3,
    ) {
        let (mut chain, root_key) = build(n_hops, base);
        prop_assert!(chain.verify(&root_key).is_ok(), "sanity: builds valid");

        let n_del = chain.delegations.len();
        let b = block.index(n_del + 1); // 0 = root block, 1.. = delegation b-1
        match (b, which) {
            (0, _) => {
                // Corrupt the root block's signature.
                chain.root.signature.bytes[0] = chain.root.signature.bytes[0].wrapping_add(1);
            }
            (_, 0) => {
                chain.delegations[b - 1].signature.bytes[0] =
                    chain.delegations[b - 1].signature.bytes[0].wrapping_add(1);
            }
            (_, 1) => {
                // Alter a signed scalar: the budget the block carries.
                chain.delegations[b - 1].scope.budget = Some(base - 1);
            }
            (_, _) => {
                // Alter the signed purpose string.
                chain.delegations[b - 1].purpose.push('!');
            }
        }
        prop_assert!(chain.verify(&root_key).is_err(), "any tamper must be rejected");
    }

    /// The wrong root key is always rejected.
    #[test]
    fn wrong_root_key_is_rejected(n_hops in 0u32..6, base in 1u64..1_000_000, seed in any::<[u8; 32]>()) {
        prop_assume!(seed != [1u8; 32]);
        let (chain, _root_key) = build(n_hops, base);
        let attacker = Ed25519Signer::from_seed(seed);
        prop_assert!(chain.verify(&attacker.public_key()).is_err());
    }

    /// Arbitrary bytes must never panic in the deserializer or in `verify`.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..600), seed in any::<[u8; 32]>()) {
        if let Ok(chain) = serde_json::from_slice::<Chain>(&bytes) {
            let key = Ed25519Signer::from_seed(seed).public_key();
            let _ = chain.verify(&key); // must return, not panic
        }
    }
}
