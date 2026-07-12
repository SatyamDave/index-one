//! Verification-latency benchmark.
//!
//! Target (per AIP's published numbers, which we're matching — reproduce before
//! quoting, CLAUDE.md directive 5): sub-millisecond chain verification.
//!
//! Benchmarks the real `indexone_chain::Chain::verify` over chains of varying
//! hop count to see how verification time scales with delegation depth.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use indexone_chain::{Chain, Principal, Scope};
use indexone_crypto::{Ed25519Signer, PublicKey, Signer};

fn principal(id: &str) -> Principal {
    Principal {
        id: id.to_string(),
        display_name: id.to_string(),
    }
}

fn scope(depth: u32) -> Scope {
    Scope {
        permissions: vec!["payments.charge".to_string()],
        budget: Some(10_000),
        currency: Some("USD".to_string()),
        max_depth: depth,
        expires_at: 4_102_444_800,
    }
}

/// Build a valid `hops`-deep chain and return it alongside its trust anchor.
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

fn bench_verify(c: &mut Criterion) {
    for hops in [1u32, 3, 5, 10] {
        let (chain, root_key) = sample_chain(hops);
        c.bench_function(&format!("verify/{hops}_hops"), |b| {
            b.iter(|| black_box(&chain).verify(black_box(&root_key)).unwrap())
        });
    }
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
