#![no_main]
//! Feed arbitrary bytes to the chain deserializer, then verify. A remote peer
//! sends a serialized capability chain; neither parsing nor verification may
//! panic, whatever the bytes.
use indexone_chain::Chain;
use indexone_crypto::{Algorithm, PublicKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(chain) = serde_json::from_slice::<Chain>(data) {
        let key = PublicKey { algorithm: Algorithm::Ed25519, bytes: vec![0u8; 32] };
        let _ = chain.verify(&key);
    }
});
