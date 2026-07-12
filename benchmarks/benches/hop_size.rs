//! Per-hop-size benchmark.
//!
//! Target (matching AIP's published numbers — reproduce before quoting): a
//! compact per-hop wire size. This measures the *current* encoding
//! (deterministic serde_json + real Ed25519 signatures + embedded public keys).
//!
//! NOTE: serde_json is NOT the intended wire format — it's the canonical
//! encoding we sign over today (RFC 8785 JCS is the target). A compact binary
//! encoding (bincode / hand-rolled) will shrink these numbers; this bench
//! exists to track where we actually are, honestly, as the encoding evolves.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use indexone_chain::{Chain, Principal, Scope};
use indexone_crypto::{Ed25519Signer, Signer};

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

/// A one-hop chain: root + a single real, signed delegation block.
fn one_hop_chain() -> Chain {
    let human = Ed25519Signer::from_seed([1u8; 32]);
    let agent = Ed25519Signer::from_seed([2u8; 32]);
    let mut chain = Chain::issue(&human, principal("human:alice"), scope(1));
    chain
        .attenuate(
            &human,
            principal("agent:a@org1"),
            agent.public_key(),
            scope(0),
            "book a flight under $500".into(),
        )
        .expect("attenuate");
    chain
}

fn bench_hop_size(c: &mut Criterion) {
    let chain = one_hop_chain();
    let block = &chain.delegations[0];

    c.bench_function("serialize_delegation_block_json", |b| {
        b.iter(|| {
            let bytes = serde_json::to_vec(black_box(block)).expect("serialize");
            black_box(bytes.len())
        })
    });

    let size = serde_json::to_vec(block).expect("serialize").len();
    println!(
        "current JSON-encoded DelegationBlock size: {size} bytes \
         (real Ed25519 sig + embedded keys; target: compact binary encoding)"
    );
}

criterion_group!(benches, bench_hop_size);
criterion_main!(benches);
