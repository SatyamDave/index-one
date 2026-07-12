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
use indexone_witness::{ActionReceipt, Witness};

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

    // The witness log's storage/bandwidth story: what one leaf costs, and how an
    // inclusion proof grows with log depth (~log2 n siblings).
    let receipt = ActionReceipt {
        chain_digest: [1u8; 32],
        action_digest: [2u8; 32],
        nonce: [3u8; 32],
        prev_root: [0u8; 32],
    };
    let leaf = receipt.canonical_bytes().len();
    let receipt_json = serde_json::to_vec(&receipt).expect("serialize").len();
    println!("ActionReceipt (witness leaf): canonical/JCS {leaf} bytes, JSON {receipt_json} bytes");

    for n in [128usize, 16_384usize] {
        let mut w = Witness::new();
        for i in 0..n {
            let mut d = [0u8; 32];
            d[..8].copy_from_slice(&(i as u64).to_le_bytes());
            w.append(&ActionReceipt {
                chain_digest: [1u8; 32],
                action_digest: d,
                nonce: d,
                prev_root: [0u8; 32],
            });
        }
        let proof = w.inclusion_proof(n / 2).expect("in range");
        let proof_json = serde_json::to_vec(&proof).expect("serialize").len();
        println!(
            "inclusion proof @ {n} leaves: {} siblings, JSON {proof_json} bytes",
            proof.path.len()
        );
    }
}

criterion_group!(benches, bench_hop_size);
criterion_main!(benches);
