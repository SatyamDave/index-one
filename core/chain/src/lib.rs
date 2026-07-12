//! `indexone-chain` — the append-only signed delegation-block chain.
//!
//! This is the core object of index-one: a capability token that grows one
//! signed block per delegation hop.
//!
//! - **Block 0** is the human root authority: scope, budget, depth limit, and
//!   expiry, signed by the human principal (or their device key).
//! - **Block N** (N >= 1) is one agent's delegation to the next agent in the
//!   chain. Each block may only *narrow* the scope/budget/depth/expiry it
//!   inherited, must carry the delegating principal's signature, and must
//!   carry a mandatory `purpose` field — the whole point is that verifying
//!   Block N tells you not just "was this signed" but "under what stated
//!   purpose did authority flow here".
//!
//! Verification is local and stateless: everything needed to verify the
//! chain travels inside the token itself (see the design invariants in
//! `/docs/REFERENCE.md`). There is no central database and no blockchain —
//! the token *is* the proof.
//!
//! Built on the Biscuit model (biscuit-auth/biscuit): public-key
//! (`indexone-crypto`) capability tokens with offline attenuation and
//! datalog-style policies. We differentiate on cross-org attribution: every
//! hop names the delegating org/agent and the purpose, so Block N can be
//! traced all the way back to Block 0 across organization boundaries.
//!
//! TODO(crypto, @udaya): every operation that touches signing, attenuation
//! math, or verification is a stub in this file. Fill in real logic behind
//! these signatures.

use indexone_crypto::{Algorithm, Signature};
use serde::{Deserialize, Serialize};

/// Monotonically narrowing permission envelope carried by every block.
///
/// Invariant: a `DelegationBlock`'s `Scope` must be a subset of the scope it
/// was delegated from. Scope only narrows down a chain, never widens.
///
/// TODO(crypto/chain): decide the concrete scope representation. Likely a
/// small datalog-ish permission set (à la Biscuit) rather than a flat list,
/// so scopes can express structured constraints (e.g. "spend <= $X on
/// category Y before date Z"), not just string tags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// Opaque permission strings for now (e.g. "payments.charge").
    /// TODO(crypto/chain): replace with a real structured/datalog scope type.
    pub permissions: Vec<String>,
    /// Maximum spend this scope authorizes, in minor units of `currency`.
    pub budget: Option<u64>,
    pub currency: Option<String>,
    /// Maximum remaining delegation depth (hops) this scope allows.
    pub max_depth: u32,
    /// Unix timestamp (seconds) after which this scope is no longer valid.
    /// Expiry may only move earlier down the chain, never later.
    pub expires_at: u64,
}

/// Identifies a principal: a human, or an agent acting for an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Stable identifier for the principal (DID, org-scoped agent ID, etc).
    /// TODO(chain): pin down the identity format — likely needs to compose
    /// with whatever AP2 / MCP / A2A use so cross-rail attribution works.
    pub id: String,
    /// Human-readable org/agent name, for audit trails and debugging.
    pub display_name: String,
}

/// Block 0: the human root of authority.
///
/// Signed by the human principal (or a device/key acting on their behalf).
/// Every `DelegationBlock` in the chain must trace back to exactly one of
/// these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootBlock {
    pub principal: Principal,
    pub scope: Scope,
    pub signature: Signature,
}

/// Block N: one agent's signed, scope-narrowing delegation to the next
/// agent in the chain.
///
/// The `purpose` field is mandatory — this is what makes the chain useful
/// for cross-org attribution instead of just cross-org authentication: a
/// verifier can see not only *that* Org B's agent delegated to Org C's
/// agent, but *why*.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationBlock {
    /// The principal delegating authority *from* (must match the previous
    /// block's `to` principal / the root principal for the first hop).
    pub from: Principal,
    /// The principal authority is delegated *to*.
    pub to: Principal,
    /// Narrowed scope for this hop. Must be a subset of the previous
    /// block's scope (see `Chain::attenuate`).
    pub scope: Scope,
    /// Why this delegation happened. Mandatory: an empty/missing purpose
    /// makes a block invalid, by design.
    pub purpose: String,
    /// Hash of the previous block, binding this block into the chain.
    /// TODO(crypto/chain): pick the hash function (blake3 likely) and
    /// canonical encoding used to compute it.
    pub prev_block_hash: Vec<u8>,
    pub signature: Signature,
}

/// A complete capability-token chain: one `RootBlock` plus zero or more
/// `DelegationBlock`s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub root: RootBlock,
    pub delegations: Vec<DelegationBlock>,
}

/// Errors returned while building or verifying a chain.
///
/// TODO(chain): expand with specific, distinguishable variants (scope
/// widened, expiry extended, depth exceeded, missing purpose, broken hash
/// link, signature invalid, algorithm unsupported) so callers can report
/// *why* a chain failed verification, not just that it did.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
}

impl Chain {
    /// Start a new chain from a signed human root authority.
    ///
    /// TODO(chain): validate `root.signature` against `root.principal`'s
    /// public key before accepting it (needs a `Verifier` from
    /// `indexone-crypto`, and a way to resolve principal -> public key).
    pub fn new(_root: RootBlock) -> Result<Chain, ChainError> {
        Err(ChainError::NotImplemented("Chain::new"))
    }

    /// Append a new delegation hop, narrowing scope from the current tail
    /// of the chain and signing it with `signer`.
    ///
    /// Enforces (once implemented) the core chain invariants:
    /// - `new_scope` must be a subset of the current tail scope (never wider).
    /// - `new_scope.expires_at` must be <= the current tail's expiry.
    /// - `new_scope.max_depth` must be strictly less than the current tail's,
    ///   and the chain must reject the append once depth reaches zero.
    /// - `purpose` must be non-empty.
    ///
    /// TODO(chain, @udaya): implement narrowing checks + signing via a
    /// `indexone_crypto::Signer`. This is the heart of "attenuation".
    pub fn attenuate(
        &mut self,
        _to: Principal,
        _new_scope: Scope,
        _purpose: String,
        _algorithm: Algorithm,
    ) -> Result<(), ChainError> {
        Err(ChainError::NotImplemented("Chain::attenuate"))
    }

    /// Verify the entire chain: every block's signature, every hash link,
    /// and every attenuation invariant (scope only narrows, expiry only
    /// shortens, depth only decreases, purpose present).
    ///
    /// This must be a pure function of the token's own bytes — no network
    /// call, no shared database lookup — that's the "local, stateless,
    /// per-request" property. (Revocation freshness, which *does* need an
    /// out-of-band check, is layered on top via `indexone-revocation`, not
    /// folded into this call.)
    ///
    /// TODO(chain, @udaya): implement. Should return the effective
    /// (narrowest) `Scope` on success so callers know what the final hop is
    /// actually authorized to do.
    pub fn verify(&self) -> Result<Scope, ChainError> {
        Err(ChainError::NotImplemented("Chain::verify"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_principal(id: &str) -> Principal {
        Principal {
            id: id.to_string(),
            display_name: id.to_string(),
        }
    }

    fn sample_scope() -> Scope {
        Scope {
            permissions: vec!["payments.charge".to_string()],
            budget: Some(10_000),
            currency: Some("USD".to_string()),
            max_depth: 3,
            expires_at: 4_102_444_800, // 2100-01-01, arbitrary far future
        }
    }

    /// Scaffold-level test: the data structures for Block 0 / Block N
    /// construct and hold the fields the spec requires (scope, budget,
    /// depth, expiry on the root; scope-narrowing + mandatory purpose on
    /// delegation blocks). Does NOT exercise real signing/verification.
    #[test]
    fn root_block_carries_required_fields() {
        let root = RootBlock {
            principal: sample_principal("human:alice"),
            scope: sample_scope(),
            signature: Signature {
                algorithm: Algorithm::Ed25519,
                bytes: vec![],
            },
        };
        assert_eq!(root.scope.max_depth, 3);
        assert!(root.scope.expires_at > 0);
    }

    #[test]
    fn delegation_block_purpose_is_a_required_field() {
        let block = DelegationBlock {
            from: sample_principal("agent:a@org1"),
            to: sample_principal("agent:b@org2"),
            scope: sample_scope(),
            purpose: "book a flight under $500".to_string(),
            prev_block_hash: vec![0u8; 32],
            signature: Signature {
                algorithm: Algorithm::Ed25519,
                bytes: vec![],
            },
        };
        assert!(!block.purpose.is_empty());
    }

    #[test]
    fn verify_is_unimplemented_stub() {
        let chain = Chain {
            root: RootBlock {
                principal: sample_principal("human:alice"),
                scope: sample_scope(),
                signature: Signature {
                    algorithm: Algorithm::Ed25519,
                    bytes: vec![],
                },
            },
            delegations: vec![],
        };
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, ChainError::NotImplemented(_)));
    }
}
