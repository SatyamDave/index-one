//! `indexone-crypto` — signature-agility layer for the capability-token chain.
//!
//! Every block in a chain (see `indexone-chain`) carries an [`Algorithm`] tag
//! alongside its signature, so the signing algorithm is swappable *per block*
//! without breaking older blocks in the same chain. That's what lets us ship
//! Ed25519 now and roll in ML-DSA / hybrid signatures later without a flag day
//! (design invariant #5 in `/docs/REFERENCE.md`).
//!
//! Signing is stateful (a [`Signer`] holds key material), so it's a trait —
//! one implementation per algorithm. Verification is a pure dispatch on the
//! signature's algorithm tag, so it's the single free function
//! [`verify_signature`]; adding an algorithm means adding one match arm there.

use serde::{Deserialize, Serialize};

/// Signature algorithms this crate is designed to support.
///
/// Each block in the chain stores one of these alongside its signature bytes,
/// so verification dispatches per-block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    /// Ed25519 (RFC 8032). Default today.
    Ed25519,
    /// ML-DSA-87 (FIPS 204). Post-quantum, not yet implemented.
    MlDsa87,
}

/// Opaque public-key bytes tagged with the algorithm they belong to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey {
    pub algorithm: Algorithm,
    pub bytes: Vec<u8>,
}

/// Opaque signature bytes tagged with the algorithm that produced them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: Algorithm,
    pub bytes: Vec<u8>,
}

/// Errors from signing / verification.
///
/// `Err` means "verification couldn't be attempted" (malformed key, wrong
/// algorithm). A signature that was checked and is *invalid* is `Ok(false)`
/// from [`verify_signature`] — callers must tell "forged" apart from "broken".
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("algorithm not implemented: {0:?}")]
    UnsupportedAlgorithm(Algorithm),
    #[error("malformed key material")]
    MalformedKey,
    #[error("malformed signature bytes")]
    MalformedSignature,
    #[error("could not gather entropy for key generation")]
    Entropy,
}

/// Anything that can produce a [`Signature`] over a payload and name its own
/// public key. `indexone-chain` signs blocks through this trait, never a
/// concrete algorithm, so a chain can hold blocks signed under different
/// schemes.
pub trait Signer {
    fn algorithm(&self) -> Algorithm;

    /// The public key that [`verify_signature`] must be given to check
    /// signatures this signer produces.
    fn public_key(&self) -> PublicKey;

    /// Sign `payload` (the canonical byte encoding of a block, produced by the
    /// calling crate) and return a [`Signature`].
    fn sign(&self, payload: &[u8]) -> Result<Signature, CryptoError>;
}

/// Verify `signature` over `payload` under `public_key`, dispatching on the
/// signature's algorithm tag. This is the single verification entry point for
/// the whole workspace.
///
/// Returns `Ok(true)` for a valid signature, `Ok(false)` for a well-formed but
/// invalid one, and `Err` only when verification couldn't be attempted at all
/// (algorithm/key mismatch, malformed inputs).
pub fn verify_signature(
    payload: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<bool, CryptoError> {
    if signature.algorithm != public_key.algorithm {
        return Err(CryptoError::UnsupportedAlgorithm(signature.algorithm));
    }
    match signature.algorithm {
        Algorithm::Ed25519 => ed25519::verify(payload, &signature.bytes, &public_key.bytes),
        other => Err(CryptoError::UnsupportedAlgorithm(other)),
    }
}

/// Ed25519 signer holding a private key. Construct from a fixed seed (for
/// reproducible tests / deterministic key derivation) or generate a fresh key.
pub struct Ed25519Signer {
    signing: ed25519_dalek::SigningKey,
}

impl Ed25519Signer {
    /// Derive a signer deterministically from a 32-byte seed. Same seed → same
    /// key; used by tests and any deterministic key-derivation path.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Ed25519Signer {
            signing: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    /// Generate a fresh signer from operating-system entropy.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| CryptoError::Entropy)?;
        Ok(Self::from_seed(seed))
    }
}

impl Signer for Ed25519Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn public_key(&self) -> PublicKey {
        PublicKey {
            algorithm: Algorithm::Ed25519,
            bytes: self.signing.verifying_key().to_bytes().to_vec(),
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Signature, CryptoError> {
        use ed25519_dalek::Signer as _;
        Ok(Signature {
            algorithm: Algorithm::Ed25519,
            bytes: self.signing.sign(payload).to_bytes().to_vec(),
        })
    }
}

mod ed25519 {
    use super::CryptoError;
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    pub(super) fn verify(
        payload: &[u8],
        sig_bytes: &[u8],
        key_bytes: &[u8],
    ) -> Result<bool, CryptoError> {
        let key_arr: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| CryptoError::MalformedKey)?;
        let key = VerifyingKey::from_bytes(&key_arr).map_err(|_| CryptoError::MalformedKey)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| CryptoError::MalformedSignature)?;
        let sig = Signature::from_bytes(&sig_arr);
        Ok(key.verify(payload, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_round_trips() {
        let signer = Ed25519Signer::from_seed([7u8; 32]);
        let pk = signer.public_key();
        let sig = signer.sign(b"canonical block bytes").unwrap();
        assert!(verify_signature(b"canonical block bytes", &sig, &pk).unwrap());
    }

    #[test]
    fn tampered_payload_fails_closed() {
        let signer = Ed25519Signer::from_seed([7u8; 32]);
        let pk = signer.public_key();
        let sig = signer.sign(b"authorize $100").unwrap();
        // A forged/altered payload must verify as invalid, not error.
        assert!(!verify_signature(b"authorize $900", &sig, &pk).unwrap());
    }

    #[test]
    fn wrong_key_fails_closed() {
        let signer = Ed25519Signer::from_seed([1u8; 32]);
        let other = Ed25519Signer::from_seed([2u8; 32]);
        let sig = signer.sign(b"payload").unwrap();
        assert!(!verify_signature(b"payload", &sig, &other.public_key()).unwrap());
    }

    #[test]
    fn from_seed_is_deterministic() {
        let a = Ed25519Signer::from_seed([9u8; 32]);
        let b = Ed25519Signer::from_seed([9u8; 32]);
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn algorithm_mismatch_is_an_error_not_a_false() {
        let signer = Ed25519Signer::from_seed([3u8; 32]);
        let sig = signer.sign(b"x").unwrap();
        let mldsa_key = PublicKey {
            algorithm: Algorithm::MlDsa87,
            bytes: signer.public_key().bytes,
        };
        assert!(matches!(
            verify_signature(b"x", &sig, &mldsa_key),
            Err(CryptoError::UnsupportedAlgorithm(_))
        ));
    }
}
