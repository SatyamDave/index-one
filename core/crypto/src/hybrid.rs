//! Hybrid (classical + post-quantum) signatures.
//!
//! A [`HybridSigner`] composes two inner [`Signer`]s — conventionally one
//! classical (Ed25519) and one post-quantum (ML-DSA-87) — and signs a payload
//! with **both**. Verification (via [`crate::verify_signature`] with algorithm
//! [`Algorithm::Hybrid`]) requires **both** component signatures to verify:
//! tampering with, or dropping, either one makes the whole thing fail. That is
//! the security bet — an attacker must forge *both* schemes simultaneously.
//!
//! ## Framing
//!
//! [`Algorithm::Hybrid`] is a unit variant (so `Algorithm` stays `Copy`), so the
//! two component (algorithm, bytes) pairs are packed into the `bytes` of the
//! hybrid [`Signature`] / [`PublicKey`] using this explicit, self-describing
//! layout — **exactly two** components, concatenated, each framed as:
//!
//! ```text
//! ┌──────────┬───────────────────────┬─────────────────┐
//! │ tag: u8  │ len: u32 (big-endian) │ payload: [u8]   │
//! │ (1 byte) │ (4 bytes)             │ (`len` bytes)   │
//! └──────────┴───────────────────────┴─────────────────┘
//! ```
//!
//! `tag` is `0` for Ed25519, `1` for ML-DSA-87. A `Hybrid` component is not
//! representable (there is no tag for it), so hybrids cannot nest — encoding one
//! is a typed error. Component order is positional and identical between the
//! signature and the public key: index 0 is the classical signer, index 1 the
//! post-quantum signer.

use crate::{Algorithm, CryptoError, PublicKey, Signature, Signer};

const TAG_ED25519: u8 = 0;
const TAG_MLDSA87: u8 = 1;

/// One decoded component: its algorithm and a borrow of its payload bytes.
type Component<'a> = (Algorithm, &'a [u8]);

/// A signer that emits a signature carrying two component signatures over the
/// same payload; both must later verify.
pub struct HybridSigner {
    classical: Box<dyn Signer>,
    post_quantum: Box<dyn Signer>,
    public_key: PublicKey,
}

impl HybridSigner {
    /// Compose two inner signers into a hybrid signer. `classical` becomes
    /// component 0, `post_quantum` component 1. Errors if either inner signer is
    /// itself a hybrid (hybrids cannot nest).
    pub fn new(
        classical: Box<dyn Signer>,
        post_quantum: Box<dyn Signer>,
    ) -> Result<Self, CryptoError> {
        let c_pk = classical.public_key();
        let q_pk = post_quantum.public_key();
        let bytes = frame_two(&c_pk.algorithm, &c_pk.bytes, &q_pk.algorithm, &q_pk.bytes)?;
        Ok(Self {
            classical,
            post_quantum,
            public_key: PublicKey {
                algorithm: Algorithm::Hybrid,
                bytes,
            },
        })
    }
}

impl Signer for HybridSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Hybrid
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    fn sign(&self, payload: &[u8]) -> Result<Signature, CryptoError> {
        let c_sig = self.classical.sign(payload)?;
        let q_sig = self.post_quantum.sign(payload)?;
        let bytes = frame_two(
            &c_sig.algorithm,
            &c_sig.bytes,
            &q_sig.algorithm,
            &q_sig.bytes,
        )?;
        Ok(Signature {
            algorithm: Algorithm::Hybrid,
            bytes,
        })
    }
}

/// Verify a hybrid signature: both components must verify.
///
/// Fail closed: structural problems (bad framing, missing component, or a
/// component whose signature-tag disagrees with its key-tag) are `Err`; a
/// well-framed hybrid where either component signature is invalid is `Ok(false)`.
pub(crate) fn verify(
    payload: &[u8],
    sig_bytes: &[u8],
    pubkey_bytes: &[u8],
) -> Result<bool, CryptoError> {
    let sig_components = decode_two(sig_bytes)?;
    let key_components = decode_two(pubkey_bytes)?;

    let mut both_valid = true;
    for (&(sig_alg, sig_payload), &(key_alg, key_payload)) in
        sig_components.iter().zip(key_components.iter())
    {
        if sig_alg != key_alg {
            return Err(CryptoError::AlgorithmMismatch {
                signature: sig_alg,
                public_key: key_alg,
            });
        }
        let component_sig = Signature {
            algorithm: sig_alg,
            bytes: sig_payload.to_vec(),
        };
        let component_key = PublicKey {
            algorithm: key_alg,
            bytes: key_payload.to_vec(),
        };
        // Recurses into the Ed25519 / ML-DSA arms; a component is never itself
        // Hybrid (the framing has no tag for it), so this cannot loop.
        if !crate::verify_signature(payload, &component_sig, &component_key)? {
            both_valid = false;
        }
    }
    Ok(both_valid)
}

/// Map an algorithm to its 1-byte component tag. `Hybrid` has no tag (no
/// nesting).
fn algorithm_tag(algorithm: &Algorithm) -> Result<u8, CryptoError> {
    match algorithm {
        Algorithm::Ed25519 => Ok(TAG_ED25519),
        Algorithm::MlDsa87 => Ok(TAG_MLDSA87),
        Algorithm::Hybrid => Err(CryptoError::UnsupportedAlgorithm(Algorithm::Hybrid)),
    }
}

/// Map a 1-byte component tag back to its algorithm.
fn tag_algorithm(tag: u8) -> Result<Algorithm, CryptoError> {
    match tag {
        TAG_ED25519 => Ok(Algorithm::Ed25519),
        TAG_MLDSA87 => Ok(Algorithm::MlDsa87),
        _ => Err(CryptoError::MalformedFraming(
            "unknown component algorithm tag",
        )),
    }
}

/// Frame two components (tag + big-endian u32 length + payload, concatenated).
fn frame_two(
    alg0: &Algorithm,
    payload0: &[u8],
    alg1: &Algorithm,
    payload1: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut out = Vec::with_capacity(10 + payload0.len() + payload1.len());
    encode_component(&mut out, alg0, payload0)?;
    encode_component(&mut out, alg1, payload1)?;
    Ok(out)
}

fn encode_component(
    out: &mut Vec<u8>,
    algorithm: &Algorithm,
    payload: &[u8],
) -> Result<(), CryptoError> {
    out.push(algorithm_tag(algorithm)?);
    let len = u32::try_from(payload.len())
        .map_err(|_| CryptoError::MalformedFraming("component too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Decode exactly two framed components, rejecting trailing bytes.
fn decode_two(input: &[u8]) -> Result<[Component<'_>; 2], CryptoError> {
    let (comp0, rest0) = read_component(input)?;
    let (comp1, rest1) = read_component(rest0)?;
    if !rest1.is_empty() {
        return Err(CryptoError::MalformedFraming(
            "trailing bytes after two components",
        ));
    }
    Ok([comp0, comp1])
}

/// Read one framed component, returning it and the unconsumed remainder.
fn read_component(input: &[u8]) -> Result<(Component<'_>, &[u8]), CryptoError> {
    if input.len() < 5 {
        return Err(CryptoError::MalformedFraming("truncated component header"));
    }
    let algorithm = tag_algorithm(input[0])?;
    let len = u32::from_be_bytes([input[1], input[2], input[3], input[4]]) as usize;
    let start = 5usize;
    let end = start
        .checked_add(len)
        .ok_or(CryptoError::MalformedFraming("component length overflow"))?;
    if end > input.len() {
        return Err(CryptoError::MalformedFraming("truncated component payload"));
    }
    Ok(((algorithm, &input[start..end]), &input[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify_signature, Ed25519Signer, MlDsa87Signer};

    const PAYLOAD: &[u8] = b"delegation block canonical bytes";

    fn hybrid_signer() -> HybridSigner {
        let classical = Box::new(Ed25519Signer::generate().unwrap());
        let post_quantum = Box::new(MlDsa87Signer::generate().unwrap());
        HybridSigner::new(classical, post_quantum).unwrap()
    }

    /// Invariant: a hybrid signature round-trips and verifies only when BOTH
    /// components are the genuine signatures over the same payload.
    #[test]
    fn hybrid_round_trips_when_both_components_valid() {
        let signer = hybrid_signer();
        let sig = signer.sign(PAYLOAD).unwrap();
        assert_eq!(sig.algorithm, Algorithm::Hybrid);
        assert!(verify_signature(PAYLOAD, &sig, &signer.public_key()).unwrap());
    }

    /// Invariant: tampering the CLASSICAL component (leaving the PQ one intact)
    /// makes hybrid verification fail — both are required.
    #[test]
    fn tampering_classical_component_fails() {
        let signer = hybrid_signer();
        let sig = signer.sign(PAYLOAD).unwrap();
        let comps = decode_two(&sig.bytes).unwrap();

        let mut tampered0 = comps[0].1.to_vec();
        tampered0[0] ^= 0x01;
        let bytes = frame_two(&comps[0].0, &tampered0, &comps[1].0, comps[1].1).unwrap();
        let tampered = Signature {
            algorithm: Algorithm::Hybrid,
            bytes,
        };
        assert!(!verify_signature(PAYLOAD, &tampered, &signer.public_key()).unwrap());
    }

    /// Invariant: tampering the POST-QUANTUM component (leaving the classical
    /// one intact) makes hybrid verification fail — both are required.
    #[test]
    fn tampering_post_quantum_component_fails() {
        let signer = hybrid_signer();
        let sig = signer.sign(PAYLOAD).unwrap();
        let comps = decode_two(&sig.bytes).unwrap();

        let mut tampered1 = comps[1].1.to_vec();
        tampered1[0] ^= 0x01;
        let bytes = frame_two(&comps[0].0, comps[0].1, &comps[1].0, &tampered1).unwrap();
        let tampered = Signature {
            algorithm: Algorithm::Hybrid,
            bytes,
        };
        assert!(!verify_signature(PAYLOAD, &tampered, &signer.public_key()).unwrap());
    }

    /// Invariant: verifying a hybrid signature over a DIFFERENT payload fails
    /// (both components are bound to the payload).
    #[test]
    fn hybrid_wrong_payload_fails() {
        let signer = hybrid_signer();
        let sig = signer.sign(PAYLOAD).unwrap();
        assert!(!verify_signature(b"a different payload", &sig, &signer.public_key()).unwrap());
    }

    /// Invariant: a missing/truncated component (only one frame present) is a
    /// structural error — fail closed with `Err`, not a silent `Ok(false)`.
    #[test]
    fn missing_component_is_err() {
        let signer = hybrid_signer();
        let sig = signer.sign(PAYLOAD).unwrap();
        // Keep only the first framed component.
        let (_, rest) = read_component(&sig.bytes).unwrap();
        let first_len = sig.bytes.len() - rest.len();
        let truncated = Signature {
            algorithm: Algorithm::Hybrid,
            bytes: sig.bytes[..first_len].to_vec(),
        };
        assert!(matches!(
            verify_signature(PAYLOAD, &truncated, &signer.public_key()),
            Err(CryptoError::MalformedFraming(_))
        ));
    }

    /// Invariant: hybrids cannot nest — composing a hybrid as a component is a
    /// typed error, not a silently-accepted signature.
    #[test]
    fn nesting_hybrid_is_unsupported() {
        let inner = Box::new(hybrid_signer());
        let other = Box::new(Ed25519Signer::generate().unwrap());
        assert!(matches!(
            HybridSigner::new(inner, other),
            Err(CryptoError::UnsupportedAlgorithm(Algorithm::Hybrid))
        ));
    }
}
