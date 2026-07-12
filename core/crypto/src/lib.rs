//! `indexone-crypto` — signature-agility layer for the capability-token chain.
//!
//! This crate defines the *interfaces* the rest of index-one signs and verifies
//! against, and the concrete signature schemes behind them.
//!
//! Design goal (CLAUDE.md §11, invariant #5 — crypto-agility from v1): every
//! block in a chain (see `indexone-chain`) carries an [`Algorithm`] tag
//! alongside its signature, so the signing algorithm is swappable *per block*
//! without breaking older blocks in the same chain. That is what lets us ship
//! Ed25519 now and roll in ML-DSA / hybrid signatures without a flag day.
//!
//! Three schemes are implemented today:
//!
//! - [`Algorithm::Ed25519`] — classical EdDSA (RFC 8032), via `ed25519-dalek`.
//! - [`Algorithm::MlDsa87`] — post-quantum ML-DSA-87 (FIPS-204), via `fips204`.
//! - [`Algorithm::Hybrid`] — a classical **and** a post-quantum signature over
//!   the same payload; verification requires **both** to pass (fail closed).
//!   This is the differentiator vs. deferring post-quantum: a hybrid block is
//!   safe the day a large quantum computer arrives *and* the day a lattice
//!   break is announced, because an attacker must forge both schemes at once.
//!
//! Verification is a single free function, [`verify_signature`], that dispatches
//! on the signature's [`Algorithm`] tag. It fails **closed**: anything that
//! means "verification could not be attempted" (algorithm mismatch, malformed
//! key/signature, malformed hybrid framing) is an `Err`, while "verification ran
//! and the signature is invalid" is `Ok(false)` — so callers can tell a forgery
//! apart from a broken verifier.

use serde::{Deserialize, Serialize};

mod ed25519;
mod hybrid;
mod mldsa;

pub use ed25519::Ed25519Signer;
pub use hybrid::HybridSigner;
pub use mldsa::MlDsa87Signer;

/// Signature algorithms this crate supports.
///
/// Each `Block` in the chain (see `indexone-chain`) stores one of these
/// alongside its signature bytes, so verification dispatches per-block.
///
/// `Hybrid` is deliberately a **unit** variant: it does *not* embed the
/// component `Algorithm`s as fields, so `Algorithm` can stay `Copy` (a previous
/// design carried `Box<Algorithm>` fields here, which made `Copy` impossible and
/// broke every crate that passes an `Algorithm` by value). The two component
/// (algorithm, bytes) pairs of a hybrid live inside the `bytes` of the
/// [`PublicKey`] / [`Signature`], under the explicit length-prefixed framing
/// documented in the `hybrid` module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    /// Ed25519 (RFC 8032). Classical default.
    Ed25519,
    /// ML-DSA-87 (FIPS-204). Post-quantum, lattice-based.
    MlDsa87,
    /// Classical + post-quantum signature over the same payload; both must
    /// verify. The component signatures/keys are framed inside the tagged
    /// `bytes` (see the `hybrid` module).
    Hybrid,
}

/// Opaque public key bytes tagged with the algorithm they belong to.
///
/// For `Hybrid`, `bytes` is the length-prefixed framing of the two component
/// public keys (see the `hybrid` module), not a single raw key.
///
/// `Hash` is derived so relying parties can put keys in a set — e.g. the
/// threshold attestation's distinct-attester check.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey {
    pub algorithm: Algorithm,
    pub bytes: Vec<u8>,
}

/// Opaque signature bytes tagged with the algorithm that produced them.
///
/// For `Hybrid`, `bytes` is the length-prefixed framing of the two component
/// signatures (see the `hybrid` module), not a single raw signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: Algorithm,
    pub bytes: Vec<u8>,
}

/// Errors from signing / verification.
///
/// The split between these variants and the `Ok(false)` return of
/// [`verify_signature`] is load-bearing: an `Err` means verification could not
/// be *attempted* (so the caller should treat the input as broken/hostile),
/// while `Ok(false)` means it was attempted and the signature is simply invalid.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The algorithm is not supported in this position (e.g. a `Hybrid` used as
    /// a *component* of another `Hybrid`, which the framing forbids).
    #[error("unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(Algorithm),
    /// The signature's algorithm tag disagrees with the public key's tag.
    #[error("algorithm mismatch: signature is {signature:?} but public key is {public_key:?}")]
    AlgorithmMismatch {
        signature: Algorithm,
        public_key: Algorithm,
    },
    /// The public key bytes are the wrong length or otherwise unparseable.
    #[error("malformed public key for {0:?}")]
    MalformedKey(Algorithm),
    /// The signature bytes are the wrong length or otherwise unparseable.
    #[error("malformed signature for {0:?}")]
    MalformedSignature(Algorithm),
    /// A hybrid signature/key's length-prefixed framing could not be decoded.
    #[error("malformed hybrid framing: {0}")]
    MalformedFraming(&'static str),
    /// Key generation or signing failed inside the underlying scheme.
    #[error("signing failed: {0}")]
    Signing(&'static str),
}

/// Anything that can produce a [`Signature`] over a payload.
///
/// One `Signer` exists per algorithm implementation: [`Ed25519Signer`],
/// [`MlDsa87Signer`], and [`HybridSigner`] (which composes two other `Signer`s).
/// `indexone-chain` calls this trait, never a concrete algorithm, when it signs
/// a new delegation block.
pub trait Signer {
    /// The algorithm this signer signs under.
    fn algorithm(&self) -> Algorithm;

    /// The public key that [`verify_signature`] must be given to check the
    /// signatures this signer produces.
    fn public_key(&self) -> PublicKey;

    /// Sign `payload` (the canonical byte encoding of a block, produced by
    /// `indexone-chain`) and return a [`Signature`].
    fn sign(&self, payload: &[u8]) -> Result<Signature, CryptoError>;
}

/// Verify `signature` over `payload` under `public_key`, dispatching on the
/// algorithm tag.
///
/// Returns:
/// - `Ok(true)`  — verification ran and the signature is valid.
/// - `Ok(false)` — verification ran and the signature is invalid (forged /
///   tampered). For `Hybrid`, `Ok(false)` if *either* component is invalid.
/// - `Err(..)`   — verification could not be attempted: the algorithm tags of
///   the signature and key disagree, the bytes are malformed, or a `Hybrid`
///   component scheme is unavailable. **Fail closed** — never silently treat
///   these as "valid".
pub fn verify_signature(
    payload: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<bool, CryptoError> {
    if signature.algorithm != public_key.algorithm {
        return Err(CryptoError::AlgorithmMismatch {
            signature: signature.algorithm,
            public_key: public_key.algorithm,
        });
    }
    match signature.algorithm {
        Algorithm::Ed25519 => ed25519::verify(payload, &signature.bytes, &public_key.bytes),
        Algorithm::MlDsa87 => mldsa::verify(payload, &signature.bytes, &public_key.bytes),
        Algorithm::Hybrid => hybrid::verify(payload, &signature.bytes, &public_key.bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Invariant: the `Algorithm` tag (including the `Hybrid` unit variant)
    /// survives a serde round-trip, so blocks stored/transmitted by other
    /// crates keep their per-block algorithm.
    #[test]
    fn algorithm_tag_serde_round_trips() {
        for alg in [Algorithm::Ed25519, Algorithm::MlDsa87, Algorithm::Hybrid] {
            let json = serde_json::to_string(&alg).unwrap();
            let back: Algorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(alg, back);
        }
    }

    /// Invariant: `Algorithm` stays `Copy` (the property that broke CI when
    /// `Hybrid` held `Box` fields). This is a compile-time assertion — it only
    /// builds if `Algorithm: Copy`.
    #[test]
    fn algorithm_is_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<Algorithm>();
        let a = Algorithm::Hybrid;
        let _b = a; // moved-by-copy; `a` still usable below
        assert_eq!(a, Algorithm::Hybrid);
    }

    /// Invariant: a signature/public-key algorithm mismatch is an `Err`
    /// (verification could not be attempted), never a silent `Ok(false)`.
    #[test]
    fn algorithm_mismatch_is_err_not_false() {
        let sig = Signature {
            algorithm: Algorithm::Ed25519,
            bytes: vec![0u8; 64],
        };
        let pk = PublicKey {
            algorithm: Algorithm::MlDsa87,
            bytes: vec![0u8; 2592],
        };
        assert!(matches!(
            verify_signature(b"payload", &sig, &pk),
            Err(CryptoError::AlgorithmMismatch { .. })
        ));
    }
}
