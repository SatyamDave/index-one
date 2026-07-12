//! `indexone-crypto` — signature-agility layer for the capability-token chain.
//!
//! This crate defines the *interfaces* the rest of index-one signs and verifies
//! against. It intentionally contains no cryptographic implementation yet.
//!
//! Design goal: every block in a chain (see `indexone-chain`) carries an
//! `Algorithm` tag alongside its signature, so the signing algorithm is
//! swappable *per block* without breaking older blocks in the same chain.
//! That's what lets us ship Ed25519 now and roll in ML-DSA / hybrid
//! signatures later without a flag day.
//!
//! TODO(crypto, @udaya): everything in this file is a stub. Fill in real
//! implementations behind these same trait signatures — downstream crates
//! (`indexone-chain`, `indexone-revocation`) are written against the traits,
//! not against any concrete algorithm.

use serde::{Deserialize, Serialize};

/// Signature algorithms this crate is designed to support.
///
/// Each `Block` in the chain (see `indexone-chain`) stores one of these
/// alongside its signature bytes, so verification dispatches per-block.
///
/// TODO(crypto): add variants as they're implemented. `Hybrid` should carry
/// both a classical and a post-quantum signature over the same payload so a
/// verifier can require both to pass during the PQ transition period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    /// Ed25519 (RFC 8032). Default for now.
    Ed25519,
    /// ML-DSA-87 (FIPS 204). Post-quantum, not yet implemented.
    MlDsa87,
    /// Classical + post-quantum signature over the same payload, both must verify.
    Hybrid {
        classical: Box<Algorithm>,
        post_quantum: Box<Algorithm>,
    },
}

/// Opaque public key bytes tagged with the algorithm they belong to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub algorithm: Algorithm,
    pub bytes: Vec<u8>,
}

/// Opaque signature bytes tagged with the algorithm that produced them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: Algorithm,
    pub bytes: Vec<u8>,
}

/// A keypair capable of signing under a given algorithm.
///
/// TODO(crypto): back this with real key material (e.g. `ed25519-dalek` for
/// `Ed25519`). Keep key material zeroized on drop once implemented.
pub struct KeyPair {
    pub algorithm: Algorithm,
    pub public: PublicKey,
    // TODO(crypto): private key material. Do not serialize this field.
}

/// Errors from signing / verification.
///
/// TODO(crypto): expand with specific failure modes (malformed key,
/// algorithm mismatch, verification failure, unsupported algorithm) once
/// real implementations exist — callers in `indexone-chain` will match on
/// these to decide whether a chain is invalid vs. a bug in the verifier.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
}

/// Anything that can produce a `Signature` over a payload.
///
/// One `Signer` should exist per algorithm implementation (e.g. an
/// `Ed25519Signer`, later an `MlDsa87Signer`, later a `HybridSigner` that
/// composes two `Signer`s). `indexone-chain` calls this trait, never a
/// concrete algorithm, when it signs a new delegation block.
pub trait Signer {
    fn algorithm(&self) -> Algorithm;

    /// Sign `payload` (the canonical byte encoding of a block, produced by
    /// `indexone-chain`) and return a `Signature`.
    ///
    /// TODO(crypto): implement for Ed25519 first.
    fn sign(&self, payload: &[u8]) -> Result<Signature, CryptoError>;
}

/// Anything that can check a `Signature` over a payload against a `PublicKey`.
///
/// Mirrors `Signer`. `indexone-chain` calls this trait once per block when
/// verifying a chain, dispatching on `Signature::algorithm` /
/// `PublicKey::algorithm` to pick the right `Verifier`.
pub trait Verifier {
    fn algorithm(&self) -> Algorithm;

    /// Verify `signature` over `payload` under `public_key`.
    ///
    /// Must return `Ok(false)` for "verified, and it's invalid" — reserve
    /// `Err` for things that mean verification couldn't be attempted at all
    /// (e.g. algorithm mismatch), so callers can tell "forged" apart from
    /// "broken".
    ///
    /// TODO(crypto): implement for Ed25519 first.
    fn verify(
        &self,
        payload: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<bool, CryptoError>;
}

/// Reference (not-yet-implemented) Ed25519 signer/verifier.
///
/// TODO(crypto): implement using `ed25519-dalek`. This struct exists so
/// downstream code has a concrete type to construct today; every method
/// is a stub.
pub struct Ed25519;

impl Signer for Ed25519 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn sign(&self, _payload: &[u8]) -> Result<Signature, CryptoError> {
        Err(CryptoError::NotImplemented("Ed25519::sign"))
    }
}

impl Verifier for Ed25519 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn verify(
        &self,
        _payload: &[u8],
        _signature: &Signature,
        _public_key: &PublicKey,
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::NotImplemented("Ed25519::verify"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scaffold-level test: types construct and carry the algorithm tag
    /// through. Does NOT exercise real signing/verification — there isn't
    /// any yet. Replace/extend once `Ed25519` is implemented.
    #[test]
    fn algorithm_tag_round_trips_through_signature() {
        let sig = Signature {
            algorithm: Algorithm::Ed25519,
            bytes: vec![0u8; 64],
        };
        assert_eq!(sig.algorithm, Algorithm::Ed25519);
    }

    #[test]
    fn ed25519_stub_reports_not_implemented() {
        let signer = Ed25519;
        let err = signer.sign(b"payload").unwrap_err();
        assert!(matches!(err, CryptoError::NotImplemented(_)));
    }
}
