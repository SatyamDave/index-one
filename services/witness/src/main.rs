//! Runs the IndexOne witness service.
//!
//!   INDEXONE_WITNESS_SEED  32-byte hex operator seed (else a fresh key is generated)
//!   INDEXONE_WITNESS_ADDR  listen address (default 127.0.0.1:8787)

use indexone_crypto::Ed25519Signer;
use indexone_witness_service::{app, AppState};

#[tokio::main]
async fn main() {
    let signer = match std::env::var("INDEXONE_WITNESS_SEED") {
        Ok(hex_seed) => {
            let bytes: [u8; 32] = hex::decode(hex_seed.trim())
                .ok()
                .and_then(|b| b.try_into().ok())
                .expect("INDEXONE_WITNESS_SEED must be 32 bytes of hex (64 chars)");
            Ed25519Signer::from_seed(bytes)
        }
        Err(_) => Ed25519Signer::generate().expect("OS RNG for a fresh operator key"),
    };

    let addr =
        std::env::var("INDEXONE_WITNESS_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    println!("IndexOne witness listening on http://{addr}");
    axum::serve(listener, app(AppState::new(signer)))
        .await
        .expect("server error");
}
