//! Witness (transparency-log) operation benchmarks.
//!
//! These are the hosted-witness hot paths (CLAUDE.md §6, §7): appending an
//! action receipt, proving/verifying inclusion (the omission-detection
//! primitive), proving/verifying RFC 6962 consistency (the non-equivocation
//! primitive), and producing/verifying a signed tree head (the gossip
//! primitive). We bench each across log sizes S ∈ {100, 1_000, 10_000} so the
//! data room has real numbers for how the anchor scales.
//!
//! Observed scaling (this implementation recomputes subtree roots on demand
//! rather than caching interior nodes): *producing* an inclusion or consistency
//! proof, and producing a signed head, are ~O(S) — they walk the whole tree —
//! and grow ~10x per 10x of S. *Verifying* a prebuilt proof is the cheap path:
//! inclusion-verify folds a ≤⌈log2 S⌉-length path (~9-10 µs, near-flat), and
//! verify-signed-head is a single Ed25519 verification independent of S (~23 µs,
//! flat). A caching/incremental tree would drop the prove paths to O(log S);
//! these numbers are the honest cost of the current construction.
//!
//! Reproduce-before-quote (directive 5): run
//! `cargo bench --manifest-path benchmarks/Cargo.toml --bench witness_ops`.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use indexone_crypto::{Ed25519Signer, Signer};
use indexone_witness::{
    verify_consistency, verify_inclusion, verify_signed_head, ActionReceipt, Witness,
};

/// Deterministic receipt for leaf `i` — only `action_digest` varies with the
/// index, so builds are reproducible and no clock/RNG touches a timed section.
fn receipt(i: usize) -> ActionReceipt {
    let mut action_digest = [0u8; 32];
    action_digest[..8].copy_from_slice(&(i as u64).to_le_bytes());
    ActionReceipt {
        chain_digest: [1u8; 32],
        action_digest,
        nonce: [2u8; 32],
        prev_root: [3u8; 32],
    }
}

/// A size-`s` witness built from deterministic receipts.
fn build_witness(s: usize) -> Witness {
    let mut w = Witness::new();
    for i in 0..s {
        w.append(&receipt(i));
    }
    w
}

const SIZES: [usize; 3] = [100, 1_000, 10_000];

/// Append ONE more receipt to a size-S tree. `iter_batched` clones the prebuilt
/// tree per iteration so every timed append lands on a size-S tree.
fn bench_append(c: &mut Criterion) {
    for s in SIZES {
        let base = build_witness(s);
        let extra = receipt(s);
        c.bench_function(&format!("witness_append/{s}"), |b| {
            b.iter_batched(
                || base.clone(),
                |mut w| black_box(w.append(black_box(&extra))),
                BatchSize::SmallInput,
            )
        });
    }
}

/// Produce an inclusion proof for a mid-tree index on a size-S tree.
fn bench_inclusion_prove(c: &mut Criterion) {
    for s in SIZES {
        let w = build_witness(s);
        let mid = s / 2;
        assert!(w.inclusion_proof(mid).is_some());
        c.bench_function(&format!("inclusion_prove/{s}"), |b| {
            b.iter(|| black_box(w.inclusion_proof(black_box(mid))))
        });
    }
}

/// Verify a prebuilt inclusion proof (proof/root/receipt built outside timing).
fn bench_inclusion_verify(c: &mut Criterion) {
    for s in SIZES {
        let w = build_witness(s);
        let mid = s / 2;
        let proof = w.inclusion_proof(mid).expect("mid in range");
        let root = w.root();
        let r = receipt(mid);
        assert!(
            verify_inclusion(&r, &proof, &root),
            "inclusion proof must verify before benching size {s}"
        );
        c.bench_function(&format!("inclusion_verify/{s}"), |b| {
            b.iter(|| {
                black_box(verify_inclusion(
                    black_box(&r),
                    black_box(&proof),
                    black_box(&root),
                ))
            })
        });
    }
}

/// Produce a consistency proof between size S/2 and size S on a size-S tree.
fn bench_consistency_prove(c: &mut Criterion) {
    for s in SIZES {
        let w = build_witness(s);
        let old = s / 2;
        assert!(w.consistency_proof(old, s).is_some());
        c.bench_function(&format!("consistency_prove/{s}"), |b| {
            b.iter(|| black_box(w.consistency_proof(black_box(old), black_box(s))))
        });
    }
}

/// Verify a prebuilt consistency proof (roots/proof built outside timing).
fn bench_consistency_verify(c: &mut Criterion) {
    for s in SIZES {
        let w = build_witness(s);
        let old = s / 2;
        let old_root = build_witness(old).root();
        let new_root = w.root();
        let proof = w.consistency_proof(old, s).expect("in range");
        assert!(
            verify_consistency(&old_root, &new_root, &proof, old, s),
            "consistency proof must verify before benching size {s}"
        );
        c.bench_function(&format!("consistency_verify/{s}"), |b| {
            b.iter(|| {
                black_box(verify_consistency(
                    black_box(&old_root),
                    black_box(&new_root),
                    black_box(&proof),
                    black_box(old),
                    black_box(s),
                ))
            })
        });
    }
}

/// Produce a signed tree head for a size-S tree (root recompute + one signature).
fn bench_signed_head(c: &mut Criterion) {
    let signer = Ed25519Signer::from_seed([9u8; 32]);
    for s in SIZES {
        let w = build_witness(s);
        c.bench_function(&format!("signed_head/{s}"), |b| {
            b.iter(|| black_box(w.signed_head(black_box(&signer))))
        });
    }
}

/// Verify a prebuilt signed tree head (STH/pubkey built outside timing).
fn bench_verify_signed_head(c: &mut Criterion) {
    let signer = Ed25519Signer::from_seed([9u8; 32]);
    let pubkey = signer.public_key();
    for s in SIZES {
        let w = build_witness(s);
        let sth = w.signed_head(&signer);
        assert!(
            verify_signed_head(&sth, &pubkey),
            "signed head must verify before benching size {s}"
        );
        c.bench_function(&format!("verify_signed_head/{s}"), |b| {
            b.iter(|| black_box(verify_signed_head(black_box(&sth), black_box(&pubkey))))
        });
    }
}

criterion_group!(
    benches,
    bench_append,
    bench_inclusion_prove,
    bench_inclusion_verify,
    bench_consistency_prove,
    bench_consistency_verify,
    bench_signed_head,
    bench_verify_signed_head,
);
criterion_main!(benches);
