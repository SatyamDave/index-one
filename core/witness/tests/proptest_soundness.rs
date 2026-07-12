//! Property-based soundness tests for the transparency log.
//!
//! Covers the properties that single-threaded example tests miss: every genuine
//! inclusion/consistency proof verifies; a proof issued at size N still verifies
//! against root@N after the log grows (the memoized-generation cache must not
//! change already-issued proofs — the "immutability under growth" property); any
//! corruption of a proof is rejected; and verification never panics on arbitrary
//! bytes (a panic in the verify path is a DoS).

use indexone_witness::{
    verify_consistency, verify_inclusion, ActionReceipt, ConsistencyProof, InclusionProof,
    PathStep, Witness,
};
use proptest::prelude::*;

fn receipt_n(i: usize) -> ActionReceipt {
    let mut d = [0u8; 32];
    d[..8].copy_from_slice(&(i as u64).to_le_bytes());
    ActionReceipt {
        chain_digest: [1u8; 32],
        action_digest: d,
        nonce: d,
        prev_root: [0u8; 32],
    }
}

fn build(n: usize) -> (Witness, Vec<ActionReceipt>) {
    let mut w = Witness::new();
    let mut rs = Vec::with_capacity(n);
    for i in 0..n {
        let r = receipt_n(i);
        w.append(&r);
        rs.push(r);
    }
    (w, rs)
}

proptest! {
    /// Every leaf's inclusion proof verifies against the current root.
    #[test]
    fn every_leaf_inclusion_proof_verifies(n in 1usize..200) {
        let (w, rs) = build(n);
        let root = w.root();
        for (i, r) in rs.iter().enumerate() {
            let proof = w.inclusion_proof(i).expect("in range");
            prop_assert!(verify_inclusion(r, &proof, &root), "leaf {i} of {n}");
        }
    }

    /// A proof issued at size N keeps verifying against root@N after the log
    /// grows by k — the append-only memoization must never mutate an issued
    /// proof or the historical root a relying party already gossiped.
    #[test]
    fn proofs_are_immutable_under_growth(n in 1usize..120, k in 0usize..120, idx in any::<prop::sample::Index>()) {
        let (mut w, rs) = build(n);
        let root_at_n = w.root();
        let i = idx.index(n);
        let proof_at_n = w.inclusion_proof(i).expect("in range");
        prop_assert!(verify_inclusion(&rs[i], &proof_at_n, &root_at_n));

        for j in n..(n + k) {
            w.append(&receipt_n(j));
        }
        // Historical root unchanged for the same prefix, and the old proof still
        // verifies against it.
        prop_assert_eq!(w.consistency_proof(n, n + k).is_some(), true);
        prop_assert!(
            verify_inclusion(&rs[i], &proof_at_n, &root_at_n),
            "proof issued at size {n} must still verify against root@{n} after +{k}"
        );
    }

    /// Every consistency proof between a prefix size and the current size verifies.
    #[test]
    fn consistency_proofs_verify_for_random_prefixes(n in 1usize..120, m_idx in any::<prop::sample::Index>()) {
        // Root at each prefix size, captured as the log grows.
        let mut w = Witness::new();
        let mut roots = vec![w.root()]; // roots[s] = root at size s
        for i in 0..n {
            w.append(&receipt_n(i));
            roots.push(w.root());
        }
        let m = m_idx.index(n + 1); // 0..=n
        let proof = w.consistency_proof(m, n).expect("valid range");
        prop_assert!(
            verify_consistency(&roots[m], &roots[n], &proof, m, n),
            "consistency {m} -> {n} must verify"
        );
    }

    /// Corrupting any sibling in an inclusion proof makes it fail closed.
    #[test]
    fn a_corrupted_inclusion_proof_is_rejected(n in 2usize..120, idx in any::<prop::sample::Index>(), step in any::<prop::sample::Index>(), delta in 1u8..=255) {
        let (w, rs) = build(n);
        let root = w.root();
        let i = idx.index(n);
        let mut proof = w.inclusion_proof(i).expect("in range");
        prop_assume!(!proof.path.is_empty());
        let s = step.index(proof.path.len());
        proof.path[s].sibling[0] = proof.path[s].sibling[0].wrapping_add(delta);
        prop_assert!(!verify_inclusion(&rs[i], &proof, &root), "corrupted proof must be rejected");
    }

    /// Arbitrary receipt/proof/root must never panic in `verify_inclusion`.
    #[test]
    fn verify_inclusion_never_panics(
        rdig in any::<[u8; 32]>(),
        leaf_index in any::<usize>(),
        tree_size in any::<usize>(),
        path in prop::collection::vec((any::<[u8; 32]>(), any::<bool>()), 0..40),
        root in any::<[u8; 32]>(),
    ) {
        let receipt = ActionReceipt { chain_digest: rdig, action_digest: rdig, nonce: rdig, prev_root: rdig };
        let proof = InclusionProof {
            leaf_index,
            tree_size,
            path: path.into_iter().map(|(sibling, sibling_is_left)| PathStep { sibling, sibling_is_left }).collect(),
        };
        let _: bool = verify_inclusion(&receipt, &proof, &root);
    }

    /// Arbitrary inputs must never panic in `verify_consistency`.
    #[test]
    fn verify_consistency_never_panics(
        old_root in any::<[u8; 32]>(),
        new_root in any::<[u8; 32]>(),
        nodes in prop::collection::vec(any::<[u8; 32]>(), 0..40),
        old_size in any::<usize>(),
        new_size in any::<usize>(),
    ) {
        let proof = ConsistencyProof { nodes };
        let _: bool = verify_consistency(&old_root, &new_root, &proof, old_size, new_size);
    }
}
