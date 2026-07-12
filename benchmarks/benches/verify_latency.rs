//! Verification-latency benchmark.
//!
//! Target (per AIP's published numbers, which we're matching): sub-millisecond
//! chain verification.
//!
//! TODO(@udaya): once `indexone_chain::Chain::verify` is implemented, replace
//! `placeholder_verify` below with a real call to it, benchmarked over chains
//! of varying hop count (1, 3, 5, 10 hops) to see how verification time scales
//! with chain depth.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use indexone_chain::{Chain, DelegationBlock, Principal, RootBlock, Scope};
use indexone_crypto::{Algorithm, Signature};

fn sample_scope() -> Scope {
    Scope {
        permissions: vec!["payments.charge".to_string()],
        budget: Some(10_000),
        currency: Some("USD".to_string()),
        max_depth: 3,
        expires_at: 4_102_444_800,
    }
}

fn sample_chain(hops: usize) -> Chain {
    let root = RootBlock {
        principal: Principal {
            id: "human:alice".to_string(),
            display_name: "Alice".to_string(),
        },
        scope: sample_scope(),
        signature: Signature {
            algorithm: Algorithm::Ed25519,
            bytes: vec![0u8; 64],
        },
    };

    let delegations = (0..hops)
        .map(|i| DelegationBlock {
            from: Principal {
                id: format!("agent:{i}@org{i}"),
                display_name: format!("agent-{i}"),
            },
            to: Principal {
                id: format!("agent:{}@org{}", i + 1, i + 1),
                display_name: format!("agent-{}", i + 1),
            },
            scope: sample_scope(),
            purpose: "benchmark placeholder hop".to_string(),
            prev_block_hash: vec![0u8; 32],
            signature: Signature {
                algorithm: Algorithm::Ed25519,
                bytes: vec![0u8; 64],
            },
        })
        .collect();

    Chain { root, delegations }
}

/// Placeholder for `Chain::verify`. `Chain::verify` is currently a `todo!()`
/// stub (see `indexone_chain::ChainError::NotImplemented`), so benchmarking
/// it directly would just measure an early return. This walks the chain's
/// blocks the way a real verifier eventually will (touching every block
/// once), so the benchmark harness's shape is already right -- swap the body
/// for a real call once `Chain::verify` exists.
fn placeholder_verify(chain: &Chain) -> bool {
    black_box(&chain.root.signature.bytes);
    for block in &chain.delegations {
        black_box(&block.signature.bytes);
    }
    !chain.root.scope.permissions.is_empty()
}

fn bench_verify(c: &mut Criterion) {
    for hops in [1usize, 3, 5, 10] {
        let chain = sample_chain(hops);
        c.bench_function(&format!("verify_placeholder/{hops}_hops"), |b| {
            b.iter(|| placeholder_verify(black_box(&chain)))
        });
    }
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
