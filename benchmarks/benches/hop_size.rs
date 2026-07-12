//! Per-hop-size benchmark.
//!
//! Target (matching AIP's published numbers): ~340-380 bytes per delegation
//! hop on the wire.
//!
//! TODO(@udaya): once real Ed25519 signatures (64 bytes) and a canonical
//! binary encoding (likely not serde_json -- probably bincode or a
//! hand-rolled compact encoding) are in place, re-measure with those. This
//! currently uses serde_json purely as a placeholder encoding to get a
//! runnable benchmark harness shape in place early; JSON is NOT the intended
//! wire format.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use indexone_chain::{DelegationBlock, Principal, Scope};
use indexone_crypto::{Algorithm, Signature};

fn sample_delegation_block() -> DelegationBlock {
    DelegationBlock {
        from: Principal {
            id: "agent:a@org1".to_string(),
            display_name: "agent-a".to_string(),
        },
        to: Principal {
            id: "agent:b@org2".to_string(),
            display_name: "agent-b".to_string(),
        },
        scope: Scope {
            permissions: vec!["payments.charge".to_string()],
            budget: Some(10_000),
            currency: Some("USD".to_string()),
            max_depth: 2,
            expires_at: 4_102_444_800,
        },
        purpose: "book a flight under $500".to_string(),
        prev_block_hash: vec![0u8; 32],
        signature: Signature {
            algorithm: Algorithm::Ed25519,
            bytes: vec![0u8; 64],
        },
    }
}

fn bench_hop_size(c: &mut Criterion) {
    let block = sample_delegation_block();

    c.bench_function("serialize_delegation_block_json_placeholder", |b| {
        b.iter(|| {
            let bytes = serde_json::to_vec(black_box(&block)).expect("serialize");
            black_box(bytes.len())
        })
    });

    // Not a criterion measurement -- just surfaces the current placeholder
    // size so `cargo bench` output shows how far off the ~340-380 byte
    // target we are with the placeholder (JSON, zeroed signature) encoding.
    let size = serde_json::to_vec(&block).expect("serialize").len();
    println!(
        "placeholder JSON-encoded DelegationBlock size: {size} bytes (target once real: ~340-380 bytes/hop, compact encoding)"
    );
}

criterion_group!(benches, bench_hop_size);
criterion_main!(benches);
