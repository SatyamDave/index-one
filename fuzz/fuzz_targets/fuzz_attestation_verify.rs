#![no_main]
//! Arbitrary bytes → CompletionAttestation → verify against a fixed executor key.
use indexone_attestation::CompletionAttestation;
use indexone_crypto::{Algorithm, PublicKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(att) = serde_json::from_slice::<CompletionAttestation>(data) {
        let key = PublicKey { algorithm: Algorithm::Ed25519, bytes: vec![0u8; 32] };
        let _ = att.verify(&key);
    }
});
