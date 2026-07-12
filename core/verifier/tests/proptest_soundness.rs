//! Property-based soundness tests for the composed `verify()`.
//!
//! This is the thesis, quantified: over thousands of random actions and
//! mutations, an honest action verifies, and **any** single corruption — a
//! chain signature, the witnessed action, the attested outcome or requested
//! digest, the trusted root, or a self-reported completion — makes `verify()`
//! return `Err`, never `Ok`, and never a panic. "We reject what should be
//! rejected," machine-checked.

use indexone_attestation::CompletionAttestation;
use indexone_chain::{Chain, Permission, Principal, Scope};
use indexone_crypto::{Ed25519Signer, PublicKey, Signer};
use indexone_verifier::{verify, VerifiableAction, VerifyPolicy};
use indexone_witness::{ActionReceipt, Digest, InclusionProof, Witness};
use proptest::prelude::*;

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
        expires_at: 4_102_444_800,
    }
}

struct World {
    chain: Chain,
    root_key: PublicKey,
    executor: Ed25519Signer,
    notary: Ed25519Signer,
}

/// Human → A → B → C (C executes); `notary` is an independent third party.
fn world() -> World {
    let human = Ed25519Signer::from_seed([1u8; 32]);
    let a = Ed25519Signer::from_seed([2u8; 32]);
    let b = Ed25519Signer::from_seed([3u8; 32]);
    let c = Ed25519Signer::from_seed([4u8; 32]);
    let notary = Ed25519Signer::from_seed([9u8; 32]);
    let root_key = human.public_key();
    let mut chain = Chain::issue(&human, principal("human"), scope(10_000, 3));
    chain
        .attenuate(
            &human,
            principal("a"),
            a.public_key(),
            scope(5_000, 2),
            "t".into(),
        )
        .unwrap();
    chain
        .attenuate(
            &a,
            principal("b"),
            b.public_key(),
            scope(5_000, 1),
            "t".into(),
        )
        .unwrap();
    chain
        .attenuate(
            &b,
            principal("c"),
            c.public_key(),
            scope(4_000, 0),
            "t".into(),
        )
        .unwrap();
    World {
        chain,
        root_key,
        executor: c,
        notary,
    }
}

fn record(chain: &Chain, action: Digest) -> (ActionReceipt, InclusionProof, Digest) {
    let mut w = Witness::new();
    let receipt = ActionReceipt {
        chain_digest: chain.digest(),
        action_digest: action,
        nonce: [0xAB; 32],
        prev_root: w.root(),
    };
    let idx = w.append(&receipt);
    (receipt, w.inclusion_proof(idx).unwrap(), w.root())
}

fn attest(
    signer: &Ed25519Signer,
    chain: &Chain,
    requested: Digest,
    outcome: Digest,
    root: Digest,
    proof: InclusionProof,
) -> CompletionAttestation {
    CompletionAttestation::attest(
        signer,
        principal("att"),
        chain.digest(),
        requested,
        outcome,
        root,
        proof,
    )
}

fn bump(mut d: Digest, delta: u8) -> Digest {
    d[0] = d[0].wrapping_add(delta);
    d
}

proptest! {
    /// An honest action always verifies.
    #[test]
    fn honest_action_verifies(action in any::<[u8; 32]>()) {
        let w = world();
        let (receipt, proof, root) = record(&w.chain, action);
        let completion = attest(&w.notary, &w.chain, action, action, root, proof);
        let policy = VerifyPolicy::third_party(vec![w.notary.public_key()]);
        let va = VerifiableAction { chain: w.chain, action_receipt: receipt, completion };
        prop_assert!(verify(&va, &w.root_key, &root, &policy).is_ok());
    }

    /// Any single mutation is rejected — never `Ok`, never a panic.
    #[test]
    fn any_mutation_is_rejected(action in any::<[u8; 32]>(), which in 0u8..6, delta in 1u8..=255) {
        let w = world();
        let (receipt, proof, root) = record(&w.chain, action);
        let policy = VerifyPolicy::third_party(vec![w.notary.public_key()]);

        let mut chain = w.chain.clone();
        let mut receipt = receipt;
        let mut trusted_root = root;
        let mut completion = attest(&w.notary, &w.chain, action, action, root, proof.clone());

        match which {
            0 => {
                // Corrupt a chain-block signature.
                let s = &mut chain.delegations[0].signature.bytes;
                s[0] = s[0].wrapping_add(delta);
            }
            1 => {
                // The witnessed action is not the one presented (omission).
                receipt.action_digest = bump(receipt.action_digest, delta);
            }
            2 => {
                // The attested outcome differs from what was witnessed.
                completion = attest(&w.notary, &w.chain, action, bump(action, delta), root, proof.clone());
            }
            3 => {
                // The trusted root disagrees with the attested root (equivocation).
                trusted_root = bump(trusted_root, delta);
            }
            4 => {
                // Self-report: the executor signs its own completion.
                completion = attest(&w.executor, &w.chain, action, action, root, proof.clone());
            }
            _ => {
                // Requested ≠ witnessed (inconsistent canonical action digest).
                completion = attest(&w.notary, &w.chain, bump(action, delta), action, root, proof.clone());
            }
        }

        let va = VerifiableAction { chain, action_receipt: receipt, completion };
        prop_assert!(
            verify(&va, &w.root_key, &trusted_root, &policy).is_err(),
            "mutation {which} must be rejected"
        );
    }

    /// Arbitrary root key and trusted root must never panic.
    #[test]
    fn never_panics_on_arbitrary_roots_and_keys(action in any::<[u8; 32]>(), tr in any::<[u8; 32]>(), rk in any::<[u8; 32]>()) {
        let w = world();
        let (receipt, proof, root) = record(&w.chain, action);
        let completion = attest(&w.notary, &w.chain, action, action, root, proof);
        let policy = VerifyPolicy::third_party(vec![w.notary.public_key()]);
        let va = VerifiableAction { chain: w.chain, action_receipt: receipt, completion };
        let key = Ed25519Signer::from_seed(rk).public_key();
        let _ = verify(&va, &key, &tr, &policy);
    }
}
