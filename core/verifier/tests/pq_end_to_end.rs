//! Post-quantum agility, end to end (CLAUDE.md §11).
//!
//! The crypto crate unit-tests ML-DSA-87 and the hybrid signer in isolation, but
//! nothing exercised them through the *whole* pipeline. This does: it builds a
//! 3-hop cross-org chain, witnesses an action, independently attests it, and runs
//! the composed `verify()` — entirely under **ML-DSA-87** and under a **hybrid
//! (Ed25519 + ML-DSA-87)** signer. It proves the "algorithm agility from v1"
//! differentiator is real end to end, not latent in one crate: signatures,
//! attenuation, witness inclusion, independent attestation, and the fail-closed
//! kill cases all hold when every key is post-quantum.

use indexone_attestation::CompletionAttestation;
use indexone_chain::{Chain, Principal, Scope};
use indexone_crypto::{Ed25519Signer, HybridSigner, MlDsa87Signer, Signer};
use indexone_verifier::{verify, VerifiableAction, VerifyError, VerifyPolicy};
use indexone_witness::{ActionReceipt, Witness};

const FAR_FUTURE: u64 = 4_102_444_800;

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
        expires_at: FAR_FUTURE,
    }
}

/// Run the full chain → witness → attestation → composed-verify path with every
/// key produced by `make_signer` (the algorithm under test), and assert both the
/// honest-accept and the self-report-reject outcomes hold.
fn run_end_to_end(make_signer: &dyn Fn() -> Box<dyn Signer>) {
    let human = make_signer();
    let a = make_signer();
    let b = make_signer();
    let c = make_signer(); // the executor (final hop)
    let notary = make_signer(); // an independent third-party attester
    let root_key = human.public_key();

    // 1–2. A 3-hop cross-org chain, every hop signed with the PQ algorithm.
    let mut chain = Chain::issue(human.as_ref(), principal("human:alice"), scope(10_000, 3));
    chain
        .attenuate(
            human.as_ref(),
            principal("agent:a@org1"),
            a.public_key(),
            scope(5_000, 2),
            "book travel".into(),
        )
        .expect("attenuate human→A");
    chain
        .attenuate(
            a.as_ref(),
            principal("agent:b@org2"),
            b.public_key(),
            scope(5_000, 1),
            "charge airline".into(),
        )
        .expect("attenuate A→B");
    chain
        .attenuate(
            b.as_ref(),
            principal("agent:c@org3"),
            c.public_key(),
            scope(4_000, 0),
            "settle fare".into(),
        )
        .expect("attenuate B→C");
    assert!(
        chain.verify(&root_key).is_ok(),
        "the chain must verify under PQ signers"
    );

    // 4. Witness the action.
    let action = [42u8; 32];
    let mut witness = Witness::new();
    let receipt = ActionReceipt {
        chain_digest: chain.digest(),
        action_digest: action,
        nonce: [7u8; 32],
        prev_root: witness.root(),
    };
    let idx = witness.append(&receipt);
    let proof = witness.inclusion_proof(idx).expect("just-appended leaf");
    let root = witness.root();

    // 5. Independent completion attestation by the notary (PQ key, not the executor).
    let completion = CompletionAttestation::attest(
        notary.as_ref(),
        principal("attester:notary"),
        chain.digest(),
        action,
        action,
        root,
        proof.clone(),
    );
    let policy = VerifyPolicy::third_party(vec![notary.public_key()]);
    let honest = VerifiableAction {
        chain: chain.clone(),
        action_receipt: receipt.clone(),
        completion,
    };
    assert!(
        verify(&honest, &root_key, &root, &policy).is_ok(),
        "an honest, witnessed, independently-attested PQ action must verify"
    );

    // Kill case: the executor signs its own completion — not independent, INVALID,
    // even with post-quantum keys.
    let self_report = CompletionAttestation::attest(
        c.as_ref(),
        principal("agent:c@org3"),
        chain.digest(),
        action,
        action,
        root,
        proof,
    );
    let self_policy = VerifyPolicy::third_party(vec![c.public_key()]);
    let reported = VerifiableAction {
        chain,
        action_receipt: receipt,
        completion: self_report,
    };
    assert!(
        matches!(
            verify(&reported, &root_key, &root, &self_policy),
            Err(VerifyError::Attestation(_))
        ),
        "a self-reported completion must fail closed under PQ signers too"
    );
}

/// The whole pipeline under pure post-quantum ML-DSA-87 keys.
#[test]
fn ml_dsa_87_end_to_end() {
    run_end_to_end(&|| Box::new(MlDsa87Signer::generate().expect("ML-DSA keygen")));
}

/// The whole pipeline under a hybrid (Ed25519 + ML-DSA-87) key — both a classical
/// and a PQ signature must verify for the block to hold.
#[test]
fn hybrid_ed25519_mldsa_end_to_end() {
    run_end_to_end(&|| {
        let classical = Box::new(Ed25519Signer::generate().expect("Ed25519 keygen"));
        let post_quantum = Box::new(MlDsa87Signer::generate().expect("ML-DSA keygen"));
        Box::new(HybridSigner::new(classical, post_quantum).expect("compose hybrid"))
    });
}
