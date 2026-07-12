//! Ed25519 (RFC 8032) signer + verify arm, backed by `ed25519-dalek`.

use ed25519_dalek::{
    Signature as DalekSignature, Signer as _, SigningKey, Verifier as _, VerifyingKey,
    PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};

use crate::{Algorithm, CryptoError, PublicKey, Signature, Signer};

/// An Ed25519 keypair that can sign block payloads.
///
/// The secret scalar lives in `ed25519-dalek`'s `SigningKey`, which zeroizes on
/// drop (its `zeroize` default feature is enabled), so key material is not left
/// in freed memory.
pub struct Ed25519Signer {
    signing_key: SigningKey,
    public_key: PublicKey,
}

impl Ed25519Signer {
    /// Generate a fresh keypair from OS randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|_| CryptoError::Signing("ed25519 key generation: OS RNG failed"))?;
        Ok(Self::from_seed(seed))
    }

    /// Build a signer from a 32-byte secret seed (RFC 8032 secret scalar seed).
    /// Taken by value so the common `from_seed([n; 32])` test/derivation form
    /// reads cleanly; callers with a borrowed array can `*seed` it.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = PublicKey {
            algorithm: Algorithm::Ed25519,
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };
        Self {
            signing_key,
            public_key,
        }
    }
}

impl Signer for Ed25519Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    fn sign(&self, payload: &[u8]) -> Result<Signature, CryptoError> {
        let sig: DalekSignature = self.signing_key.sign(payload);
        Ok(Signature {
            algorithm: Algorithm::Ed25519,
            bytes: sig.to_bytes().to_vec(),
        })
    }
}

/// Verify a raw Ed25519 signature. `Ok(false)` for a well-formed-but-invalid
/// signature; `Err` only when the key or signature bytes are malformed.
pub(crate) fn verify(
    payload: &[u8],
    sig_bytes: &[u8],
    pubkey_bytes: &[u8],
) -> Result<bool, CryptoError> {
    let pk_array: [u8; PUBLIC_KEY_LENGTH] = pubkey_bytes
        .try_into()
        .map_err(|_| CryptoError::MalformedKey(Algorithm::Ed25519))?;
    let verifying_key = VerifyingKey::from_bytes(&pk_array)
        .map_err(|_| CryptoError::MalformedKey(Algorithm::Ed25519))?;

    let sig_array: [u8; SIGNATURE_LENGTH] = sig_bytes
        .try_into()
        .map_err(|_| CryptoError::MalformedSignature(Algorithm::Ed25519))?;
    let signature = DalekSignature::from_bytes(&sig_array);

    Ok(verifying_key.verify(payload, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_signature;

    /// Invariant: a genuine Ed25519 signature round-trips through
    /// `sign` -> `verify_signature` as `Ok(true)`.
    #[test]
    fn ed25519_round_trips() {
        let signer = Ed25519Signer::generate().unwrap();
        let sig = signer.sign(b"payload").unwrap();
        assert_eq!(sig.algorithm, Algorithm::Ed25519);
        assert!(verify_signature(b"payload", &sig, &signer.public_key()).unwrap());
    }

    /// Invariant: a single flipped bit in a well-formed signature verifies as
    /// `Ok(false)` (invalid), not `Err` — it is a forgery, not a broken input.
    #[test]
    fn ed25519_tamper_fails() {
        let signer = Ed25519Signer::generate().unwrap();
        let mut sig = signer.sign(b"payload").unwrap();
        sig.bytes[0] ^= 0x01;
        assert!(!verify_signature(b"payload", &sig, &signer.public_key()).unwrap());
    }

    /// Invariant: verifying against the wrong payload is `Ok(false)`.
    #[test]
    fn ed25519_wrong_payload_fails() {
        let signer = Ed25519Signer::generate().unwrap();
        let sig = signer.sign(b"payload").unwrap();
        assert!(!verify_signature(b"other", &sig, &signer.public_key()).unwrap());
    }

    /// Invariant: a wrong-length key is a structural `Err` (malformed), not a
    /// silent `Ok(false)`.
    #[test]
    fn ed25519_malformed_key_is_err() {
        let signer = Ed25519Signer::generate().unwrap();
        let sig = signer.sign(b"payload").unwrap();
        let bad_key = PublicKey {
            algorithm: Algorithm::Ed25519,
            bytes: vec![0u8; 10],
        };
        assert!(matches!(
            verify_signature(b"payload", &sig, &bad_key),
            Err(CryptoError::MalformedKey(Algorithm::Ed25519))
        ));
    }
}
