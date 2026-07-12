//! ML-DSA-87 (FIPS-204) signer + verify arm, backed by the pure-Rust `fips204`
//! crate (integritychain/fips204).
//!
//! We use an **empty signing context** (`ctx = &[]`) for every operation. The
//! payload already carries all binding data (it is the canonical block encoding
//! from `indexone-chain`), and both signing and verification here agree on the
//! empty context, so signatures round-trip.

use fips204::ml_dsa_87::{self, PK_LEN, SIG_LEN};
use fips204::traits::{SerDes, Signer as _, Verifier as _};

use crate::{Algorithm, CryptoError, PublicKey, Signature, Signer};

/// Empty FIPS-204 signing context (see module docs).
const CTX: &[u8] = &[];

/// An ML-DSA-87 keypair that can sign block payloads.
///
/// The secret key lives in `fips204`'s `PrivateKey`, which zeroizes on drop.
pub struct MlDsa87Signer {
    secret_key: ml_dsa_87::PrivateKey,
    public_key: PublicKey,
}

impl MlDsa87Signer {
    /// Generate a fresh ML-DSA-87 keypair from OS randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        let (pk, sk) = ml_dsa_87::try_keygen().map_err(CryptoError::Signing)?;
        let public_key = PublicKey {
            algorithm: Algorithm::MlDsa87,
            bytes: pk.into_bytes().to_vec(),
        };
        Ok(Self {
            secret_key: sk,
            public_key,
        })
    }
}

impl Signer for MlDsa87Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::MlDsa87
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    fn sign(&self, payload: &[u8]) -> Result<Signature, CryptoError> {
        let sig = self
            .secret_key
            .try_sign(payload, CTX)
            .map_err(CryptoError::Signing)?;
        Ok(Signature {
            algorithm: Algorithm::MlDsa87,
            bytes: sig.to_vec(),
        })
    }
}

/// Verify a raw ML-DSA-87 signature. `Ok(false)` for a well-formed-but-invalid
/// signature; `Err` only when the key or signature bytes are malformed.
pub(crate) fn verify(
    payload: &[u8],
    sig_bytes: &[u8],
    pubkey_bytes: &[u8],
) -> Result<bool, CryptoError> {
    let pk_array: [u8; PK_LEN] = pubkey_bytes
        .try_into()
        .map_err(|_| CryptoError::MalformedKey(Algorithm::MlDsa87))?;
    let verifying_key = ml_dsa_87::PublicKey::try_from_bytes(pk_array)
        .map_err(|_| CryptoError::MalformedKey(Algorithm::MlDsa87))?;

    let sig_array: [u8; SIG_LEN] = sig_bytes
        .try_into()
        .map_err(|_| CryptoError::MalformedSignature(Algorithm::MlDsa87))?;

    Ok(verifying_key.verify(payload, &sig_array, CTX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_signature;

    /// Invariant: a genuine ML-DSA-87 signature round-trips through
    /// `sign` -> `verify_signature` as `Ok(true)`.
    #[test]
    fn mldsa_round_trips() {
        let signer = MlDsa87Signer::generate().unwrap();
        let sig = signer.sign(b"payload").unwrap();
        assert_eq!(sig.algorithm, Algorithm::MlDsa87);
        assert!(verify_signature(b"payload", &sig, &signer.public_key()).unwrap());
    }

    /// Invariant: a single flipped bit in a well-formed signature verifies as
    /// `Ok(false)` (invalid), not `Err`.
    #[test]
    fn mldsa_tamper_fails() {
        let signer = MlDsa87Signer::generate().unwrap();
        let mut sig = signer.sign(b"payload").unwrap();
        sig.bytes[0] ^= 0x01;
        assert!(!verify_signature(b"payload", &sig, &signer.public_key()).unwrap());
    }

    /// Invariant: verifying against the wrong payload is `Ok(false)`.
    #[test]
    fn mldsa_wrong_payload_fails() {
        let signer = MlDsa87Signer::generate().unwrap();
        let sig = signer.sign(b"payload").unwrap();
        assert!(!verify_signature(b"other", &sig, &signer.public_key()).unwrap());
    }

    /// Invariant: a wrong-length signature is a structural `Err` (malformed),
    /// not a silent `Ok(false)`.
    #[test]
    fn mldsa_malformed_signature_is_err() {
        let signer = MlDsa87Signer::generate().unwrap();
        let bad_sig = Signature {
            algorithm: Algorithm::MlDsa87,
            bytes: vec![0u8; 10],
        };
        assert!(matches!(
            verify_signature(b"payload", &bad_sig, &signer.public_key()),
            Err(CryptoError::MalformedSignature(Algorithm::MlDsa87))
        ));
    }
}
