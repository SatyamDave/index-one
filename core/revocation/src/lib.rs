//! `indexone-revocation` — revocation for capability-token chains.
//!
//! Verification of a `Chain` (see `indexone-chain`) is local, stateless, and
//! per-request: everything needed to check signatures and attenuation
//! invariants travels in the token. Revocation is the one thing that
//! *can't* be purely local — "has this been revoked since it was issued" is
//! inherently a freshness question, so it needs an out-of-band check. This
//! crate isolates that concern instead of folding it into `Chain::verify`.
//!
//! Design (per `/docs/REFERENCE.md` §5 invariant #4): two complementary
//! mechanisms so that revocation survives partial-chain compromise (an
//! attacker who has compromised one hop's key can't suppress the fact that an
//! earlier or later hop was revoked):
//!
//! - **Short-TTL** ([`ShortTtlChecker`]): every block is only valid for a
//!   short window by default, so an unrevoked-but-stale token stops working on
//!   its own without any revocation check at all.
//! - **Transparency log** ([`TransparencyLogChecker`]): a revocation, once
//!   published, is checkable out-of-chain (append-only log a verifier can
//!   consult), independent of whichever key material got compromised.
//!
//! Both are consulted through the [`RevocationChecker`] trait, and
//! [`check_chain_revocation`] derives a keyless [`RevocationId`] for every
//! block ([`revocation_ids_for_chain`]) and fails closed on the first hop that
//! is revoked, stale, or undeterminable.

use std::collections::HashMap;
use std::fmt;

use indexone_chain::Chain;
use indexone_crypto::Signature;
use serde::{Deserialize, Serialize};

/// Domain-separation prefix mixed into every [`RevocationId`] so the hash is
/// bound to this crate's use and can't collide with some other blake3 hash of
/// the same signature bytes computed elsewhere in the system.
const REVOCATION_ID_DOMAIN: &[u8] = b"indexone-revocation/RevocationId/v1";

/// Identifies a single revocable block within a chain.
///
/// Derived deterministically from the block's *signature bytes* via blake3
/// (see [`RevocationId::from_signature`]). Two properties matter:
///
/// - **Keyless**: any token holder can compute it — it needs only the
///   signature that already travels in the token, never the private key that
///   produced that signature. That is what lets a downstream verifier, or a
///   revoker who never held the signing key, name a specific block.
/// - **Deterministic**: the same signature always yields the same id, so a
///   revocation published against an id matches on every future check.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RevocationId(pub Vec<u8>);

impl RevocationId {
    /// Derive the id for a block from its signature, keyless and
    /// deterministic: `blake3(DOMAIN || signature.bytes)`.
    pub fn from_signature(signature: &Signature) -> RevocationId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(REVOCATION_ID_DOMAIN);
        hasher.update(&signature.bytes);
        RevocationId(hasher.finalize().as_bytes().to_vec())
    }
}

impl fmt::Display for RevocationId {
    /// Lowercase hex, for audit/error messages. Kept dependency-free.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Collect the [`RevocationId`] of every revocable block in `chain`: the root
/// block first, then each delegation block in chain order.
///
/// This is the keyless enumeration a verifier uses to ask "was *any* hop
/// pulled" — the ids can be computed by anyone holding the token.
pub fn revocation_ids_for_chain(chain: &Chain) -> Vec<RevocationId> {
    let mut ids = Vec::with_capacity(1 + chain.delegations.len());
    ids.push(RevocationId::from_signature(&chain.root.signature));
    for block in &chain.delegations {
        ids.push(RevocationId::from_signature(&block.signature));
    }
    ids
}

/// A single entry in the out-of-chain transparency log.
///
/// TODO(revocation): pin down log construction (Merkle log? append-only
/// signed list?) and how a verifier obtains/audits an inclusion or
/// non-inclusion proof without trusting the log operator. The in-memory core
/// in [`TransparencyLogChecker`] is real and testable; the proof machinery is
/// still open.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyLogEntry {
    pub revoked: RevocationId,
    /// Unix timestamp (seconds) the revocation was published.
    pub revoked_at: u64,
    /// Why it was revoked, for audit purposes.
    pub reason: String,
}

/// Outcome of a revocation lookup that *completed* — distinct from a
/// [`RevocationError`], which means the lookup itself couldn't be completed.
///
/// A `Live` result means "this checker confirms the id is not revoked". Both
/// `Revoked` and `Stale` are definite denials: they are returned as `Ok`
/// (the check ran and produced an answer), and it is [`check_chain_revocation`]
/// that turns them into a fail-closed [`RevocationError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    /// The id is confirmed not revoked by this checker.
    Live,
    /// The id is confirmed revoked, with the reason recorded against it.
    Revoked { reason: String },
    /// The id's block is older than its short-TTL freshness window and is
    /// therefore treated as revoked (revocation-by-default over time).
    Stale { ttl_seconds: u64 },
}

/// Errors from revocation checks.
///
/// The trait boundary ([`RevocationChecker::is_revoked`]) reserves `Err` for
/// "couldn't determine" — only [`RevocationError::LogUnreachable`] is returned
/// that way. The definite-denial variants ([`RevocationError::Revoked`],
/// [`RevocationError::Stale`]) are produced by [`check_chain_revocation`] when
/// it lifts a [`RevocationStatus`] into a fail-closed chain-level error, and
/// each names the specific id that failed so callers can report *why* a chain
/// was rejected, not just that it was.
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    /// A hop is definitely revoked (e.g. published in the transparency log).
    #[error("block {id} is revoked: {reason}")]
    Revoked { id: RevocationId, reason: String },
    /// A hop is older than its short-TTL freshness window (stale-by-default).
    #[error("block {id} is stale: older than the {ttl_seconds}s freshness window")]
    Stale { id: RevocationId, ttl_seconds: u64 },
    /// The out-of-chain log couldn't be consulted, so revocation status is
    /// undeterminable. Callers fail closed. (This is the *only* "couldn't
    /// determine" outcome, kept distinct from a definite revocation.)
    #[error("transparency log unreachable: {0}")]
    LogUnreachable(String),
}

/// Anything that can answer "has this block been revoked" — implementations
/// might check a local short-TTL registry, a transparency log, or both.
pub trait RevocationChecker {
    /// Report what this checker knows about `id`.
    ///
    /// `Ok(RevocationStatus::Live)` = confirmed live;
    /// `Ok(RevocationStatus::Revoked { .. } | RevocationStatus::Stale { .. })`
    /// = confirmed revoked; `Err` = the check itself couldn't be completed
    /// (e.g. log unreachable). Callers decide the fail-open/fail-closed policy
    /// — this trait just reports what it knows, keeping "definitely revoked"
    /// distinct from "couldn't find out".
    fn is_revoked(&self, id: &RevocationId) -> Result<RevocationStatus, RevocationError>;
}

/// A clock injected into freshness checks so behaviour is deterministic and
/// testable — no implicit reads of the system clock anywhere in this crate.
///
/// Production callers implement this over their own trusted time source;
/// tests use [`FixedClock`].
pub trait Clock {
    /// Current time as Unix seconds.
    fn now_unix(&self) -> u64;
}

/// A [`Clock`] pinned to a fixed instant. The injection point that makes
/// short-TTL checks reproducible.
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

/// Short-TTL revocation: a block is treated as revoked once it is older than
/// `ttl_seconds`, with no log lookup required (revocation-by-default over
/// time, invariant #4's first mechanism).
///
/// Chain blocks carry no per-block issued-at field (and we must not add one),
/// so this checker is self-contained: it holds its own registry of
/// `RevocationId -> issued_at` and reads "now" from an injected [`Clock`].
/// Fail-closed by default — an id with no registered issued-at cannot be
/// vouched fresh, so it is treated as stale.
pub struct ShortTtlChecker<C: Clock> {
    ttl_seconds: u64,
    clock: C,
    issued_at: HashMap<RevocationId, u64>,
}

impl<C: Clock> ShortTtlChecker<C> {
    /// Create a checker with a freshness window of `ttl_seconds`, reading time
    /// from `clock`.
    pub fn new(ttl_seconds: u64, clock: C) -> ShortTtlChecker<C> {
        ShortTtlChecker {
            ttl_seconds,
            clock,
            issued_at: HashMap::new(),
        }
    }

    /// Record when a block was issued so its freshness can be judged.
    pub fn register(&mut self, id: RevocationId, issued_at: u64) {
        self.issued_at.insert(id, issued_at);
    }
}

impl<C: Clock> RevocationChecker for ShortTtlChecker<C> {
    fn is_revoked(&self, id: &RevocationId) -> Result<RevocationStatus, RevocationError> {
        let stale = RevocationStatus::Stale {
            ttl_seconds: self.ttl_seconds,
        };
        match self.issued_at.get(id) {
            // Fail closed: we can't prove freshness for a block we never saw
            // issued, so we do not vouch for it.
            None => Ok(stale),
            Some(&issued) => {
                let age = self.clock.now_unix().saturating_sub(issued);
                if age > self.ttl_seconds {
                    Ok(stale)
                } else {
                    Ok(RevocationStatus::Live)
                }
            }
        }
    }
}

/// Transparency-log-backed revocation: consults an append-only revocation set
/// that is independent of any single hop's key material, so revocation
/// survives partial-chain compromise (invariant #4's second mechanism).
///
/// The in-memory `entries` set is the real, testable core: revocations are
/// appended and looked up here with no key involved. The remote `log_url`
/// fetch is a documented TODO — a checker configured with a remote source it
/// hasn't synced fails closed with [`RevocationError::LogUnreachable`] rather
/// than silently reporting "live".
/// A source of published transparency-log revocations — an HTTP fetch, a
/// signed log segment, a local mirror. Injected so the remote path is real and
/// testable without a network (mirrors how the runtime crypto is injected at
/// the edges). `Err` means "couldn't reach the log" — the caller fails closed —
/// distinct from `Ok(empty)` meaning "reached it, nothing revoked".
pub trait LogTransport {
    fn fetch(&self) -> Result<Vec<TransparencyLogEntry>, String>;
}

pub struct TransparencyLogChecker {
    entries: HashMap<RevocationId, TransparencyLogEntry>,
    /// A pluggable remote source. `Some` → each lookup fetches through it (fail
    /// closed on a fetch error); `None` → the in-memory `entries` are authoritative.
    transport: Option<Box<dyn LogTransport>>,
    /// A remote URL with **no** wired transport — a checker configured this way
    /// fails closed (`LogUnreachable`) rather than silently reporting "live".
    /// TODO(revocation): a concrete HTTP `LogTransport` + inclusion /
    /// non-inclusion proofs over the fetched signed segment.
    log_url: Option<String>,
}

impl TransparencyLogChecker {
    /// A purely in-memory log — the real, testable core. Start empty and
    /// [`append`](Self::append) revocations.
    pub fn in_memory() -> TransparencyLogChecker {
        TransparencyLogChecker {
            entries: HashMap::new(),
            transport: None,
            log_url: None,
        }
    }

    /// A checker backed by an injected [`LogTransport`] — the real remote path.
    /// Each lookup fetches the published revocations through `transport` and
    /// fails closed if the fetch errors.
    pub fn with_transport(transport: Box<dyn LogTransport>) -> TransparencyLogChecker {
        TransparencyLogChecker {
            entries: HashMap::new(),
            transport: Some(transport),
            log_url: None,
        }
    }

    /// A checker naming a remote log at `url` but with no wired transport yet.
    /// Every lookup fails closed with [`RevocationError::LogUnreachable`] — use
    /// [`with_transport`](Self::with_transport) to make it real.
    pub fn remote(url: impl Into<String>) -> TransparencyLogChecker {
        TransparencyLogChecker {
            entries: HashMap::new(),
            transport: None,
            log_url: Some(url.into()),
        }
    }

    /// Append a revocation. The log is append-only: there is deliberately no
    /// removal API, because "un-revoking" by dropping an entry is exactly the
    /// suppression invariant #4 forbids.
    pub fn append(&mut self, entry: TransparencyLogEntry) {
        self.entries.insert(entry.revoked.clone(), entry);
    }
}

impl RevocationChecker for TransparencyLogChecker {
    fn is_revoked(&self, id: &RevocationId) -> Result<RevocationStatus, RevocationError> {
        if let Some(transport) = &self.transport {
            let fetched = transport.fetch().map_err(RevocationError::LogUnreachable)?;
            return match fetched.into_iter().find(|e| &e.revoked == id) {
                Some(entry) => Ok(RevocationStatus::Revoked {
                    reason: entry.reason,
                }),
                None => Ok(RevocationStatus::Live),
            };
        }
        if let Some(url) = &self.log_url {
            return Err(RevocationError::LogUnreachable(format!(
                "no transport wired for remote log {url}"
            )));
        }
        match self.entries.get(id) {
            Some(entry) => Ok(RevocationStatus::Revoked {
                reason: entry.reason.clone(),
            }),
            None => Ok(RevocationStatus::Live),
        }
    }
}

/// Consults several checkers, so short-TTL and transparency-log revocation can
/// be enforced together.
///
/// A definite revocation from *any* checker wins immediately — that is the
/// partial-compromise-survival property at the checker level: one checker
/// being unable to answer (or one hop's key being compromised) cannot mask
/// another checker's definite revocation. Only if no checker reports a
/// revocation and at least one couldn't determine do we fail closed with that
/// undeterminable error.
pub struct CompositeChecker {
    checkers: Vec<Box<dyn RevocationChecker>>,
}

impl CompositeChecker {
    /// Build a composite from a set of checkers, consulted in order.
    pub fn new(checkers: Vec<Box<dyn RevocationChecker>>) -> CompositeChecker {
        CompositeChecker { checkers }
    }
}

impl RevocationChecker for CompositeChecker {
    fn is_revoked(&self, id: &RevocationId) -> Result<RevocationStatus, RevocationError> {
        let mut undeterminable: Option<RevocationError> = None;
        for checker in &self.checkers {
            match checker.is_revoked(id) {
                Ok(RevocationStatus::Live) => {}
                // A definite revocation from any checker is authoritative and
                // is never masked by another checker that couldn't answer.
                Ok(revoked) => return Ok(revoked),
                Err(err) => undeterminable = Some(err),
            }
        }
        match undeterminable {
            Some(err) => Err(err),
            None => Ok(RevocationStatus::Live),
        }
    }
}

/// Checks every block in a chain for revocation via the given checker.
///
/// This is the entry point the rest of index-one calls: `Chain::verify`
/// (local, stateless) proves the chain is well-formed and signed; this
/// function is the separate, explicit "and none of these hops were pulled"
/// check layered on top.
///
/// Derives each block's [`RevocationId`] via [`revocation_ids_for_chain`] and
/// consults `checker`. Fails closed: returns the first hop that is revoked or
/// stale as a typed [`RevocationError`] naming that id, propagates a checker's
/// "couldn't determine" ([`RevocationError::LogUnreachable`]) rather than
/// treating it as live, and only returns `Ok(())` when every hop is confirmed
/// live.
pub fn check_chain_revocation(
    chain: &Chain,
    checker: &dyn RevocationChecker,
) -> Result<(), RevocationError> {
    for id in revocation_ids_for_chain(chain) {
        match checker.is_revoked(&id)? {
            RevocationStatus::Live => {}
            RevocationStatus::Revoked { reason } => {
                return Err(RevocationError::Revoked { id, reason })
            }
            RevocationStatus::Stale { ttl_seconds } => {
                return Err(RevocationError::Stale { id, ttl_seconds })
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexone_chain::{DelegationBlock, Principal, RootBlock, Scope};
    use indexone_crypto::{Algorithm, PublicKey};

    // 2100-01-01; scope expiry is irrelevant to these revocation tests (that's
    // the chain crate's concern), so it's pinned far in the future.
    const FAR_FUTURE: u64 = 4_102_444_800;

    fn principal(id: &str) -> Principal {
        Principal {
            id: id.to_string(),
            display_name: id.to_string(),
        }
    }

    fn scope() -> Scope {
        Scope {
            permissions: vec!["payments.charge".into()],
            budget: Some(10_000),
            currency: Some("USD".to_string()),
            max_depth: 5,
            expires_at: FAR_FUTURE,
        }
    }

    // Deterministic, distinct signature bytes per block. RevocationId derives
    // purely from these bytes (blake3), with no private key involved — which is
    // exactly the keyless property under test — so a fixed `tag` gives a fixed,
    // reproducible id. Synthetic (rather than real Ed25519) signatures keep the
    // id assertions below deterministic; revocation never verifies the
    // signature, only fingerprints its bytes.
    fn sig(tag: u8) -> Signature {
        Signature {
            algorithm: Algorithm::Ed25519,
            bytes: vec![tag; 64],
        }
    }

    // Dummy per-block public key. Revocation never verifies signatures, so the
    // embedded keys only need to satisfy the block shape; their contents don't
    // affect any RevocationId.
    fn pubkey(tag: u8) -> PublicKey {
        PublicKey {
            algorithm: Algorithm::Ed25519,
            bytes: vec![tag; 32],
        }
    }

    // A 3-hop chain: root (human) + three signed delegation hops, each with
    // distinct signature bytes so each has a distinct RevocationId. Blocks are
    // indexed by their signature tag: root=0, hop1=1, hop2=2, hop3=3, so
    // `ids[2]` is the middle hop.
    fn three_hop_chain() -> Chain {
        let delegation = |from: &str, to: &str, tag: u8, purpose: &str| DelegationBlock {
            from: principal(from),
            from_key: pubkey(tag),
            to: principal(to),
            to_key: pubkey(tag + 1),
            scope: scope(),
            purpose: purpose.to_string(),
            prev_block_hash: vec![tag; 32],
            signature: sig(tag),
        };
        Chain {
            root: RootBlock {
                principal: principal("human:alice"),
                principal_key: pubkey(0),
                scope: scope(),
                signature: sig(0),
            },
            delegations: vec![
                delegation("human:alice", "agent:a@org1", 1, "hop1: dispatch"),
                delegation("agent:a@org1", "agent:b@org2", 2, "hop2: book flight"),
                delegation("agent:b@org2", "agent:c@org3", 3, "hop3: charge card"),
            ],
        }
    }

    fn log_entry(id: RevocationId, reason: &str) -> TransparencyLogEntry {
        TransparencyLogEntry {
            revoked: id,
            revoked_at: 1_000,
            reason: reason.to_string(),
        }
    }

    /// Keyless + deterministic derivation: the id is a pure function of the
    /// signature bytes (no private key), so equal signatures give equal ids and
    /// different signatures give different ids.
    #[test]
    fn revocation_id_is_deterministic_and_keyless() {
        assert_eq!(
            RevocationId::from_signature(&sig(7)),
            RevocationId::from_signature(&sig(7)),
            "same signature bytes must yield the same id"
        );
        assert_ne!(
            RevocationId::from_signature(&sig(7)),
            RevocationId::from_signature(&sig(8)),
            "different signature bytes must yield different ids"
        );
        // blake3 output is 32 bytes — the id is the hash, not the raw signature.
        assert_eq!(RevocationId::from_signature(&sig(7)).0.len(), 32);
    }

    /// `revocation_ids_for_chain` must cover the root block *and* every
    /// delegation block, in order — otherwise a revoked hop could be silently
    /// skipped.
    #[test]
    fn revocation_ids_cover_root_and_all_delegations() {
        let chain = three_hop_chain();
        let ids = revocation_ids_for_chain(&chain);
        assert_eq!(ids.len(), 4, "root + 3 delegation hops");
        assert_eq!(ids[0], RevocationId::from_signature(&chain.root.signature));
        assert_eq!(ids[2], RevocationId::from_signature(&sig(2)), "middle hop");
    }

    /// Invariant #4: a revoked MIDDLE hop must be caught by the chain check.
    #[test]
    fn revoked_middle_hop_is_caught() {
        let chain = three_hop_chain();
        let middle = RevocationId::from_signature(&sig(2));

        let mut log = TransparencyLogChecker::in_memory();
        log.append(log_entry(middle.clone(), "hop2 key compromised"));

        let err = check_chain_revocation(&chain, &log).unwrap_err();
        match err {
            RevocationError::Revoked { id, reason } => {
                assert_eq!(id, middle, "must name the revoked middle hop");
                assert_eq!(reason, "hop2 key compromised");
            }
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    /// A chain with no revoked hops and an empty log passes cleanly.
    #[test]
    fn fresh_chain_passes() {
        let chain = three_hop_chain();
        let log = TransparencyLogChecker::in_memory();
        assert!(check_chain_revocation(&chain, &log).is_ok());
    }

    /// Short-TTL staleness triggers deterministically with an injected clock:
    /// a block issued more than `ttl_seconds` before "now" is treated as
    /// revoked, with no log lookup. No system-clock/random nondeterminism.
    #[test]
    fn short_ttl_staleness_is_deterministic() {
        let chain = three_hop_chain();
        let ttl = 300;
        let issued_at = 10_000;

        // Fresh: now is within the window for every hop -> passes.
        let mut fresh = ShortTtlChecker::new(ttl, FixedClock(issued_at + ttl));
        for id in revocation_ids_for_chain(&chain) {
            fresh.register(id, issued_at);
        }
        assert!(check_chain_revocation(&chain, &fresh).is_ok());

        // Stale: now is one second past the window -> definite Stale error.
        let mut stale = ShortTtlChecker::new(ttl, FixedClock(issued_at + ttl + 1));
        for id in revocation_ids_for_chain(&chain) {
            stale.register(id, issued_at);
        }
        let err = check_chain_revocation(&chain, &stale).unwrap_err();
        assert!(
            matches!(err, RevocationError::Stale { ttl_seconds, .. } if ttl_seconds == ttl),
            "expected Stale with the checker's ttl, got {err:?}"
        );
    }

    /// Fail closed: a block the short-TTL checker never saw issued cannot be
    /// vouched fresh, so it is treated as stale rather than silently allowed.
    #[test]
    fn short_ttl_unregistered_block_is_stale() {
        let chain = three_hop_chain();
        let checker = ShortTtlChecker::new(300, FixedClock(10_000)); // nothing registered
        let err = check_chain_revocation(&chain, &checker).unwrap_err();
        assert!(matches!(err, RevocationError::Stale { .. }));
    }

    /// The transparency log's in-memory core answers lookups directly:
    /// Revoked for an appended id, Live otherwise.
    #[test]
    fn transparency_log_revocation_is_found() {
        let revoked = RevocationId::from_signature(&sig(3));
        let live = RevocationId::from_signature(&sig(1));

        let mut log = TransparencyLogChecker::in_memory();
        log.append(log_entry(revoked.clone(), "leaked"));

        assert_eq!(
            log.is_revoked(&revoked).unwrap(),
            RevocationStatus::Revoked {
                reason: "leaked".to_string()
            }
        );
        assert_eq!(log.is_revoked(&live).unwrap(), RevocationStatus::Live);
    }

    /// Invariant #4 (partial-chain compromise): revoking hop 1 is still
    /// detected even when the verifier is checking from a later hop's vantage
    /// point. The transparency log is keyed by the block's *signature-derived*
    /// id, independent of any hop's private key, so compromising hop 2's key
    /// cannot suppress hop 1's revocation.
    #[test]
    fn revoking_hop_one_survives_hop_two_compromise() {
        let chain = three_hop_chain();
        let hop1 = RevocationId::from_signature(&sig(1));

        // The log entry against hop 1 was created by whoever revoked hop 1,
        // using only hop 1's public signature bytes — never hop 2's key.
        let mut log = TransparencyLogChecker::in_memory();
        log.append(log_entry(hop1.clone(), "hop1 delegation withdrawn"));

        // A verifier operating from hop 2 onward still derives the same hop-1
        // id from the token it holds and finds the revocation.
        let err = check_chain_revocation(&chain, &log).unwrap_err();
        assert!(
            matches!(err, RevocationError::Revoked { ref id, .. } if *id == hop1),
            "hop 1's revocation must be detectable regardless of hop 2, got {err:?}"
        );
    }

    /// Fail closed: an unreachable log yields a "couldn't determine" error, not
    /// a false "Ok/live". The undeterminable case stays distinct from a
    /// definite revocation.
    #[test]
    fn unreachable_log_fails_closed() {
        let chain = three_hop_chain();
        let checker = TransparencyLogChecker::remote("https://log.example/segment");
        let err = check_chain_revocation(&chain, &checker).unwrap_err();
        assert!(matches!(err, RevocationError::LogUnreachable(_)));
    }

    /// The composite consults both mechanisms: a revocation in *either* the
    /// short-TTL registry or the transparency log is caught. Here every hop is
    /// registered fresh, so only the log's entry against the middle hop fires.
    #[test]
    fn composite_catches_revocation_from_either_mechanism() {
        let chain = three_hop_chain();
        let ids = revocation_ids_for_chain(&chain);
        let middle = ids[2].clone();

        let mut ttl = ShortTtlChecker::new(300, FixedClock(10_100));
        for id in &ids {
            ttl.register(id.clone(), 10_000); // all fresh
        }
        let mut log = TransparencyLogChecker::in_memory();
        log.append(log_entry(middle.clone(), "revoked out-of-band"));

        let composite = CompositeChecker::new(vec![Box::new(ttl), Box::new(log)]);
        let err = check_chain_revocation(&chain, &composite).unwrap_err();
        assert!(
            matches!(err, RevocationError::Revoked { ref id, .. } if *id == middle),
            "composite must surface the log's revocation, got {err:?}"
        );
    }

    /// A definite revocation from one checker must not be masked by another
    /// checker that can't answer (unreachable). Fail-closed, but a real
    /// revocation still wins.
    #[test]
    fn composite_revocation_beats_unreachable_checker() {
        let live = RevocationId::from_signature(&sig(9));
        let revoked = RevocationId::from_signature(&sig(1));

        let mut log = TransparencyLogChecker::in_memory();
        log.append(log_entry(revoked.clone(), "pulled"));
        let composite = CompositeChecker::new(vec![
            Box::new(TransparencyLogChecker::remote("https://down.example")),
            Box::new(log),
        ]);

        // Revoked id: the reachable log's definite answer wins over the
        // unreachable one.
        assert!(matches!(
            composite.is_revoked(&revoked),
            Ok(RevocationStatus::Revoked { .. })
        ));
        // Unknown id: no definite answer anywhere, so the undeterminable error
        // surfaces (fail closed).
        assert!(matches!(
            composite.is_revoked(&live),
            Err(RevocationError::LogUnreachable(_))
        ));
    }

    /// An injected transport makes the remote path real: a revocation published
    /// through it is found, and a fetch error fails closed (LogUnreachable),
    /// distinct from "reached the log, nothing revoked".
    #[test]
    fn transport_backed_checker_is_real_and_fails_closed() {
        struct OkTransport(Vec<TransparencyLogEntry>);
        impl LogTransport for OkTransport {
            fn fetch(&self) -> Result<Vec<TransparencyLogEntry>, String> {
                Ok(self.0.clone())
            }
        }
        struct DownTransport;
        impl LogTransport for DownTransport {
            fn fetch(&self) -> Result<Vec<TransparencyLogEntry>, String> {
                Err("connection refused".to_string())
            }
        }

        let revoked = RevocationId::from_signature(&sig(2));
        let live = RevocationId::from_signature(&sig(5));

        let reachable =
            TransparencyLogChecker::with_transport(Box::new(OkTransport(vec![log_entry(
                revoked.clone(),
                "leaked over the wire",
            )])));
        assert!(matches!(
            reachable.is_revoked(&revoked).unwrap(),
            RevocationStatus::Revoked { .. }
        ));
        assert_eq!(reachable.is_revoked(&live).unwrap(), RevocationStatus::Live);

        let down = TransparencyLogChecker::with_transport(Box::new(DownTransport));
        assert!(matches!(
            down.is_revoked(&revoked),
            Err(RevocationError::LogUnreachable(_))
        ));
    }
}
