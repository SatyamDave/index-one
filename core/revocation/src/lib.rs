//! `indexone-revocation` — revocation for capability-token chains.
//!
//! Verification of a `Chain` (see `indexone-chain`) is local, stateless, and
//! per-request: everything needed to check signatures and attenuation
//! invariants travels in the token. Revocation is the one thing that
//! *can't* be purely local — "has this been revoked since it was issued" is
//! inherently a freshness question, so it needs an out-of-band check. This
//! crate isolates that concern instead of folding it into `Chain::verify`.
//!
//! Design (per `/docs/REFERENCE.md`): two complementary mechanisms so that
//! revocation survives partial-chain compromise (an attacker who has
//! compromised one hop's key can't suppress the fact that an earlier or
//! later hop was revoked):
//!
//! - **Short-TTL**: every block is only valid for a short window by default,
//!   so an unrevoked-but-stale token stops working on its own without any
//!   revocation check at all.
//! - **Transparency log**: a revocation, once published, is checkable
//!   out-of-chain (append-only log a verifier can consult), independent of
//!   whichever key material got compromised.
//!
//! TODO(crypto, @udaya): everything here is a stub. No revocation logic,
//! log format, or transport is implemented yet.

use indexone_chain::Chain;
use serde::{Deserialize, Serialize};

/// Identifies a single revocable block within a chain.
///
/// TODO(revocation): decide how this is derived (e.g. hash of the block's
/// signature) — it must be computable by anyone holding the token, without
/// needing the private key that signed the block.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RevocationId(pub Vec<u8>);

/// A single entry in the out-of-chain transparency log.
///
/// TODO(revocation): pin down log construction (Merkle log? append-only
/// signed list?) and how a verifier obtains/audits an inclusion or
/// non-inclusion proof without trusting the log operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyLogEntry {
    pub revoked: RevocationId,
    /// Unix timestamp (seconds) the revocation was published.
    pub revoked_at: u64,
    /// Why it was revoked, for audit purposes.
    pub reason: String,
}

/// Errors from revocation checks.
///
/// TODO(revocation): expand once real checks exist (log unreachable, proof
/// invalid, entry found = revoked, etc). `Err` should mean "couldn't
/// determine", distinct from `Ok(true)` meaning "confirmed revoked".
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
}

/// Anything that can answer "has this block been revoked" — implementations
/// might check a local short-TTL cache, a remote transparency log, or both.
pub trait RevocationChecker {
    /// Returns `Ok(true)` if `id` is confirmed revoked, `Ok(false)` if
    /// confirmed live, `Err` if the check itself couldn't be completed
    /// (e.g. log unreachable) — callers decide the fail-open/fail-closed
    /// policy, this trait just reports what it knows.
    ///
    /// TODO(revocation): implement.
    fn is_revoked(&self, id: &RevocationId) -> Result<bool, RevocationError>;
}

/// Checks every block in a chain for revocation via the given checker.
///
/// This is the entry point the rest of index-one calls: `Chain::verify`
/// (local, stateless) proves the chain is well-formed and signed; this
/// function is the separate, explicit "and none of these hops were pulled"
/// check layered on top.
///
/// TODO(revocation, @udaya): implement — derive each block's
/// `RevocationId` and consult `checker` for each.
pub fn check_chain_revocation(
    _chain: &Chain,
    _checker: &dyn RevocationChecker,
) -> Result<(), RevocationError> {
    Err(RevocationError::NotImplemented("check_chain_revocation"))
}

/// Short-TTL revocation: a block is treated as revoked once it's older than
/// its own declared TTL, with no log lookup required.
///
/// TODO(revocation): implement against `RootBlock`/`DelegationBlock` expiry
/// semantics in `indexone-chain` — likely just "is `now` past this block's
/// short-lived freshness window", distinct from the long-lived `Scope`
/// expiry.
pub struct ShortTtlChecker {
    pub ttl_seconds: u64,
}

impl RevocationChecker for ShortTtlChecker {
    fn is_revoked(&self, _id: &RevocationId) -> Result<bool, RevocationError> {
        Err(RevocationError::NotImplemented("ShortTtlChecker::is_revoked"))
    }
}

/// Transparency-log-backed revocation: consults an append-only log that's
/// independent of any single hop's key material, so revocation survives
/// partial-chain compromise.
///
/// TODO(revocation): implement log fetch/verification. Likely needs an
/// async client (HTTP fetch of a signed log segment) — this stub is
/// synchronous only as a placeholder for the trait shape.
pub struct TransparencyLogChecker {
    pub log_url: String,
}

impl RevocationChecker for TransparencyLogChecker {
    fn is_revoked(&self, _id: &RevocationId) -> Result<bool, RevocationError> {
        Err(RevocationError::NotImplemented(
            "TransparencyLogChecker::is_revoked",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_id_can_be_constructed_and_compared() {
        let a = RevocationId(vec![1, 2, 3]);
        let b = RevocationId(vec![1, 2, 3]);
        assert_eq!(a, b);
    }

    #[test]
    fn short_ttl_checker_stub_reports_not_implemented() {
        let checker = ShortTtlChecker { ttl_seconds: 300 };
        let err = checker.is_revoked(&RevocationId(vec![])).unwrap_err();
        assert!(matches!(err, RevocationError::NotImplemented(_)));
    }
}
