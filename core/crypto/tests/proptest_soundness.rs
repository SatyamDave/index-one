//! Property-based soundness tests for the signature layer.
//!
//! These generate adversarial inputs (arbitrary bytes for payloads, signatures,
//! and keys) and assert two things over thousands of cases: verification never
//! panics (a panic in the trust path is a DoS), and a genuine signature is
//! accepted while any single-byte corruption of the signature or the payload is
//! rejected — `Ok(false)`, never `Ok(true)` and never a panic.

use indexone_crypto::{verify_signature, Algorithm, Ed25519Signer, PublicKey, Signature, Signer};
use proptest::prelude::*;

proptest! {
    /// Arbitrary bytes for every argument must never panic — worst case an
    /// `Err` (couldn't attempt) or `Ok(false)` (checked, invalid).
    #[test]
    fn verify_signature_never_panics_on_arbitrary_bytes(
        payload in prop::collection::vec(any::<u8>(), 0..256),
        sig_bytes in prop::collection::vec(any::<u8>(), 0..256),
        key_bytes in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let sig = Signature { algorithm: Algorithm::Ed25519, bytes: sig_bytes };
        let key = PublicKey { algorithm: Algorithm::Ed25519, bytes: key_bytes };
        // The only requirement: this returns, it does not panic.
        let _ = verify_signature(&payload, &sig, &key);
    }

    /// A real signature verifies; corrupting any one byte of the signature is
    /// rejected (never accepted, never a panic).
    #[test]
    fn a_flipped_signature_byte_is_rejected(
        seed in any::<[u8; 32]>(),
        payload in prop::collection::vec(any::<u8>(), 1..256),
        idx in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let signer = Ed25519Signer::from_seed(seed);
        let pk = signer.public_key();
        let sig = signer.sign(&payload).unwrap();
        prop_assert!(verify_signature(&payload, &sig, &pk).unwrap(), "genuine signature must verify");

        let mut bad = sig.clone();
        let i = idx.index(bad.bytes.len());
        bad.bytes[i] = bad.bytes[i].wrapping_add(delta); // guaranteed different (delta != 0)
        prop_assert!(!verify_signature(&payload, &bad, &pk).unwrap(), "corrupted signature must be rejected");
    }

    /// A real signature over payload P does not verify over a different payload P'.
    #[test]
    fn a_flipped_payload_byte_is_rejected(
        seed in any::<[u8; 32]>(),
        payload in prop::collection::vec(any::<u8>(), 1..256),
        idx in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let signer = Ed25519Signer::from_seed(seed);
        let pk = signer.public_key();
        let sig = signer.sign(&payload).unwrap();

        let mut tampered = payload.clone();
        let i = idx.index(tampered.len());
        tampered[i] = tampered[i].wrapping_add(delta);
        prop_assert!(!verify_signature(&tampered, &sig, &pk).unwrap(), "signature must not verify over tampered payload");
    }

    /// A signature never verifies under an unrelated key.
    #[test]
    fn a_signature_does_not_verify_under_a_wrong_key(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
        payload in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(seed_a != seed_b);
        let a = Ed25519Signer::from_seed(seed_a);
        let b = Ed25519Signer::from_seed(seed_b);
        let sig = a.sign(&payload).unwrap();
        prop_assert!(!verify_signature(&payload, &sig, &b.public_key()).unwrap());
    }
}
