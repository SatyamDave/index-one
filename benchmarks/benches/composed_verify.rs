//! Composed-verification latency benchmark.
//!
//! `verify_latency.rs` times only `Chain::verify` — the crowded, mostly-solved
//! per-hop signature + monotonic-attenuation part. This benchmark times the
//! full composed `indexone_verifier::verify()`: chain checks PLUS the pieces the
//! competing drafts punt (CLAUDE.md §6) — witness inclusion proof (completeness),
//! gossip-root equivocation gate, independent completion attestation, and the
//! outcome/requested-digest consistency gates. The delta against `verify_latency`
//! at the same hop count is the witness + attestation cost.
//!
//! Also benchmarks `verify_threshold` (k-of-n independent attestation).
//!
//! Everything is built OUTSIDE the timed section from fixed seeds — no clock,
//! no RNG in the hot path — and each built artifact is asserted to VERIFY once
//! before it is timed (fail-closed benches would otherwise time an error path).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use indexone_attestation::{CompletionAttestation, ThresholdAttestation};
use indexone_chain::{Chain, Principal, Scope};
use indexone_crypto::{Ed25519Signer, PublicKey, Signer};
use indexone_verifier::{
    verify, verify_threshold, VerifiableAction, VerifiableThresholdAction, VerifyPolicy,
};
use indexone_witness::{ActionReceipt, Digest, InclusionProof, Witness};

fn principal(id: &str) -> Principal {
    Principal {
        id: id.to_string(),
        display_name: id.to_string(),
    }
}

fn scope(depth: u32) -> Scope {
    Scope {
        permissions: vec!["payments.charge".into()],
        budget: Some(10_000),
        currency: Some("USD".to_string()),
        max_depth: depth,
        expires_at: 4_102_444_800,
    }
}

/// Build a valid `hops`-deep chain (Human → A0 → … → A{hops-1}) and return it
/// with its trust anchor. Mirrors `verify_latency::sample_chain` so the two
/// benchmarks are comparable at the same hop count. Hop signers use seeds
/// `2..=hops+1`; the executor (final hop) uses seed `hops + 1`.
fn sample_chain(hops: u32) -> (Chain, PublicKey) {
    let human = Ed25519Signer::from_seed([1u8; 32]);
    let root_key = human.public_key();
    let mut chain = Chain::issue(&human, principal("human:alice"), scope(hops));

    let mut current: Box<dyn Signer> = Box::new(Ed25519Signer::from_seed([1u8; 32]));
    for i in 0..hops {
        let next = Ed25519Signer::from_seed([(i + 2) as u8; 32]);
        chain
            .attenuate(
                current.as_ref(),
                principal(&format!("agent:{i}@org{i}")),
                next.public_key(),
                scope(hops - i - 1),
                format!("delegation hop {i}"),
            )
            .expect("attenuate");
        current = Box::new(next);
    }
    (chain, root_key)
}

/// Append `action_digest` to a fresh witness and return the receipt, its
/// inclusion proof, and the resulting (trusted) root. Deterministic — no RNG.
fn record(chain: &Chain, action_digest: Digest) -> (ActionReceipt, InclusionProof, Digest) {
    let mut w = Witness::new();
    let receipt = ActionReceipt {
        chain_digest: chain.digest(),
        action_digest,
        nonce: [0xAB; 32],
        prev_root: w.root(),
    };
    let idx = w.append(&receipt);
    let proof = w.inclusion_proof(idx).expect("in range");
    (receipt, proof, w.root())
}

/// A fully-valid, verifying `VerifiableAction` for `hops`, plus the root key,
/// trusted root, and matching third-party policy. Third-party attestation (a
/// notary outside the chain) is the simplest independent-attestation flow; the
/// verifier policy trusts exactly that notary's key.
fn build_action(hops: u32) -> (VerifiableAction, PublicKey, Digest, VerifyPolicy) {
    let (chain, root_key) = sample_chain(hops);
    let action = [42u8; 32];
    let (receipt, proof, root) = record(&chain, action);

    // Notary seed [200] cannot collide with any hop signer (seeds 1..=hops+1).
    let notary = Ed25519Signer::from_seed([200u8; 32]);
    let completion = CompletionAttestation::attest(
        &notary,
        principal("attester:notary"),
        chain.digest(),
        action,
        action,
        root,
        proof,
    );
    let policy = VerifyPolicy::third_party(vec![notary.public_key()]);
    let va = VerifiableAction {
        chain,
        action_receipt: receipt,
        completion,
    };
    (va, root_key, root, policy)
}

/// A verifying `VerifiableThresholdAction` with exactly `k` distinct independent
/// third-party attesters over a shared 3-hop chain, plus the root key, trusted
/// root, and a policy trusting all `k` attester keys. `threshold == k`.
fn build_threshold_action(
    k: usize,
) -> (VerifiableThresholdAction, PublicKey, Digest, VerifyPolicy) {
    let (chain, root_key) = sample_chain(3);
    let action = [42u8; 32];
    let (receipt, proof, root) = record(&chain, action);
    let cd = chain.digest();

    let mut attestations = Vec::with_capacity(k);
    let mut trusted = Vec::with_capacity(k);
    for i in 0..k {
        // Attester seeds [200 + i] cannot collide with hop signers (seeds 1..=4).
        let attester = Ed25519Signer::from_seed([(200 + i) as u8; 32]);
        trusted.push(attester.public_key());
        attestations.push(CompletionAttestation::attest(
            &attester,
            principal(&format!("attester:{i}")),
            cd,
            action,
            action,
            root,
            proof.clone(),
        ));
    }
    let policy = VerifyPolicy::third_party(trusted);
    let vta = VerifiableThresholdAction {
        chain,
        action_receipt: receipt,
        completion: ThresholdAttestation {
            attestations,
            threshold: k,
        },
    };
    (vta, root_key, root, policy)
}

fn bench_composed_verify(c: &mut Criterion) {
    for hops in [1u32, 3, 5, 10] {
        let (va, root_key, root, policy) = build_action(hops);
        // Time only the verifying path.
        verify(&va, &root_key, &root, &policy).expect("action must verify before timing");
        c.bench_function(&format!("composed_verify/{hops}_hops"), |b| {
            b.iter(|| {
                verify(
                    black_box(&va),
                    black_box(&root_key),
                    black_box(&root),
                    black_box(&policy),
                )
                .unwrap()
            })
        });
    }
}

fn bench_verify_threshold(c: &mut Criterion) {
    for k in [1usize, 2, 3] {
        let (vta, root_key, root, policy) = build_threshold_action(k);
        verify_threshold(&vta, &root_key, &root, k, &policy)
            .expect("threshold action must verify before timing");
        c.bench_function(&format!("verify_threshold/{k}"), |b| {
            b.iter(|| {
                verify_threshold(
                    black_box(&vta),
                    black_box(&root_key),
                    black_box(&root),
                    black_box(k),
                    black_box(&policy),
                )
                .unwrap()
            })
        });
    }
}

criterion_group!(benches, bench_composed_verify, bench_verify_threshold);
criterion_main!(benches);
