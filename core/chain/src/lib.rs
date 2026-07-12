//! `indexone-chain` — the append-only, cryptographically-bound delegation chain.
//!
//! This is the substrate object of index-one: a capability token that grows
//! one signed block per delegation hop.
//!
//! - **Block 0** ([`RootBlock`]) is the human root authority: scope, budget,
//!   depth limit, expiry, signed by the human principal's key.
//! - **Block N** ([`DelegationBlock`], N ≥ 1) is one agent delegating to the
//!   next. Each block may only *narrow* the scope/budget/depth/expiry it
//!   inherited, carries a mandatory `purpose`, and is hash-linked to the block
//!   before it.
//!
//! **Cross-org binding.** Every block embeds the public key of its signer, and
//! continuity is cryptographic: block N must be signed by the key that block
//! N−1 designated as its delegatee (`to_key`). So [`Chain::verify`] against a
//! trusted root key proves the *entire* chain of authority hop-by-hop back to
//! Block 0 — across organization boundaries — with no callback and no shared
//! database. The token is the proof (design invariant #1 in
//! `/docs/REFERENCE.md`).
//!
//! What this crate does **not** do: prove the action set was complete
//! (omission), that the log didn't fork (equivocation), or that completion was
//! honestly reported. Those are the seams the `witness`, `verifier`, and
//! `attestation` crates close — see CLAUDE.md §6.

use indexone_crypto::{verify_signature, PublicKey, Signer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A typed constraint that bounds where or how much a [`Permission`] applies.
///
/// Constraints only ever *tighten* down a chain. Each variant is one dimension
/// of authority; a permission with no constraint on a dimension is unbounded on
/// it. Serializes externally-tagged, e.g. `{"amount_max": 500}`,
/// `{"resource_in": ["airlines"]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Constraint {
    /// Maximum amount (minor units) this permission authorizes per use. A child
    /// may only lower it. Absent ⇒ unbounded on amount.
    AmountMax(u64),
    /// This permission applies only to resources in this set (e.g. merchant
    /// categories, account ids). A child may only take a subset. Absent ⇒ any
    /// resource. Multiple `ResourceIn` on one permission intersect.
    ResourceIn(Vec<String>),
}

/// One permission in a [`Scope`]: an action plus optional typed [`Constraint`]s.
///
/// A bare permission (no constraints) is the common case and (de)serializes as a
/// plain JSON string, so `"payments.charge"` — and every existing token,
/// signature, and SDK call — keeps working byte-for-byte. A constrained
/// permission serializes as `{"action": ..., "constraints": [...]}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permission {
    pub action: String,
    pub constraints: Vec<Constraint>,
}

impl Permission {
    /// A bare permission: an action, unbounded on every dimension.
    pub fn action(action: impl Into<String>) -> Self {
        Permission {
            action: action.into(),
            constraints: Vec::new(),
        }
    }

    /// A permission carrying constraints.
    pub fn with(action: impl Into<String>, constraints: Vec<Constraint>) -> Self {
        Permission {
            action: action.into(),
            constraints,
        }
    }

    /// This permission's amount ceiling (minor units), or `u64::MAX` if
    /// unbounded. Multiple `AmountMax` take the tightest (min).
    fn amount_max(&self) -> u64 {
        self.constraints
            .iter()
            .filter_map(|c| match c {
                Constraint::AmountMax(n) => Some(*n),
                _ => None,
            })
            .min()
            .unwrap_or(u64::MAX)
    }

    /// The resource set this permission is confined to, or `None` for "any
    /// resource". Multiple `ResourceIn` intersect (each further narrows).
    fn resource_set(&self) -> Option<BTreeSet<&str>> {
        let mut sets = self.constraints.iter().filter_map(|c| match c {
            Constraint::ResourceIn(rs) => {
                Some(rs.iter().map(String::as_str).collect::<BTreeSet<_>>())
            }
            _ => None,
        });
        let first = sets.next()?;
        Some(sets.fold(first, |acc, s| acc.intersection(&s).copied().collect()))
    }

    /// Whether `self` authorizes a subset of `parent`'s authority: same action,
    /// amount ceiling no higher, resource set no broader. A child may *add*
    /// constraints (tighter) but never loosen one the parent imposed.
    pub fn authorizes_subset_of(&self, parent: &Permission) -> bool {
        if self.action != parent.action {
            return false;
        }
        if self.amount_max() > parent.amount_max() {
            return false;
        }
        match parent.resource_set() {
            // Parent unbounded on resource ⇒ any child is a subset.
            None => true,
            // Parent confined ⇒ child must be confined to a subset of it.
            Some(parent_set) => match self.resource_set() {
                Some(child_set) => child_set.is_subset(&parent_set),
                None => false, // child unbounded on resource, parent bounded ⇒ broader
            },
        }
    }
}

impl From<&str> for Permission {
    fn from(s: &str) -> Self {
        Permission::action(s)
    }
}

impl From<String> for Permission {
    fn from(s: String) -> Self {
        Permission::action(s)
    }
}

impl Serialize for Permission {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Bare permission ⇒ a plain string (backward-compatible wire form).
        if self.constraints.is_empty() {
            serializer.serialize_str(&self.action)
        } else {
            use serde::ser::SerializeStruct;
            let mut st = serializer.serialize_struct("Permission", 2)?;
            st.serialize_field("action", &self.action)?;
            st.serialize_field("constraints", &self.constraints)?;
            st.end()
        }
    }
}

impl<'de> Deserialize<'de> for Permission {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Bare(String),
            Full {
                action: String,
                #[serde(default)]
                constraints: Vec<Constraint>,
            },
        }
        Ok(match Repr::deserialize(deserializer)? {
            Repr::Bare(action) => Permission {
                action,
                constraints: Vec::new(),
            },
            Repr::Full {
                action,
                constraints,
            } => Permission {
                action,
                constraints,
            },
        })
    }
}

/// Monotonically narrowing permission envelope carried by every block.
///
/// Invariant: a child block's `Scope` must be a subset of the scope it was
/// delegated from — permissions narrow, budget shrinks, expiry shortens, depth
/// decreases. Never the reverse. See [`Scope::is_narrowing_of`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// The actions this scope authorizes, each optionally carrying typed
    /// [`Constraint`]s (amount ceilings, resource sets). Narrows monotonically:
    /// every child permission must authorize a subset of *some* parent
    /// permission ([`Permission::authorizes_subset_of`]). Bare permissions
    /// (de)serialize as plain strings, so `["payments.charge"]` is unchanged.
    pub permissions: Vec<Permission>,
    /// Maximum spend authorized, in minor units of `currency`. `None` = the
    /// scope places no budget ceiling.
    pub budget: Option<u64>,
    pub currency: Option<String>,
    /// Maximum remaining delegation depth (hops) this scope allows.
    pub max_depth: u32,
    /// Unix timestamp (seconds) after which this scope is invalid. May only
    /// move earlier down the chain, never later.
    pub expires_at: u64,
}

impl Scope {
    /// Whether `self` is a valid narrowing of `parent`: every permission is
    /// also in `parent`, the budget is no larger, expiry is no later, and the
    /// currency (when both budgets are set) matches. Depth is checked
    /// separately at append time because it must *strictly* decrease.
    pub fn is_narrowing_of(&self, parent: &Scope) -> Result<(), ChainError> {
        // Every child permission must authorize a subset of some parent
        // permission: same action, no higher amount ceiling, no broader resource
        // set. A child may add or tighten constraints, never loosen them.
        for perm in &self.permissions {
            if !parent
                .permissions
                .iter()
                .any(|p| perm.authorizes_subset_of(p))
            {
                return Err(ChainError::ScopeWidened);
            }
        }
        match (self.budget, parent.budget) {
            // Parent bounded, child must be bounded and no larger.
            (Some(child), Some(parent_budget)) if child > parent_budget => {
                return Err(ChainError::ScopeWidened)
            }
            (None, Some(_)) => return Err(ChainError::ScopeWidened),
            _ => {}
        }
        if self.budget.is_some() && parent.budget.is_some() && self.currency != parent.currency {
            return Err(ChainError::ScopeWidened);
        }
        if self.expires_at > parent.expires_at {
            return Err(ChainError::ExpiryExtended);
        }
        Ok(())
    }
}

/// Identifies a principal: a human, or an agent acting for an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Stable identifier (DID, org-scoped agent ID, etc).
    /// TODO(chain): pin down the identity format so it composes with AP2 / MCP
    /// / A2A identifiers for cross-rail attribution.
    pub id: String,
    /// Human-readable org/agent name, for audit trails.
    pub display_name: String,
}

/// Block 0: the human root of authority. Every block in the chain traces back
/// to exactly one of these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootBlock {
    pub principal: Principal,
    /// The root principal's public key — the trust anchor a verifier checks
    /// the chain against.
    pub principal_key: PublicKey,
    pub scope: Scope,
    pub signature: indexone_crypto::Signature,
}

/// Block N: one agent's signed, scope-narrowing delegation to the next agent.
///
/// `purpose` is mandatory — that's what makes the chain useful for
/// *attribution* (why authority flowed here), not just authentication. The
/// embedded `from_key`/`to_key` bind the hop cryptographically to its
/// neighbours (see the module docs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationBlock {
    /// Principal delegating authority *from* (must equal the previous block's
    /// `to` / the root principal for the first hop).
    pub from: Principal,
    /// Public key of `from`. Must equal the previous block's `to_key` (or the
    /// root's `principal_key` for the first hop) — this is the cryptographic
    /// link that stops an unrelated key from splicing itself into the chain.
    pub from_key: PublicKey,
    /// Principal authority is delegated *to*.
    pub to: Principal,
    /// Public key the delegatee must sign the *next* hop with.
    pub to_key: PublicKey,
    /// Narrowed scope for this hop. Must be a subset of the previous scope.
    pub scope: Scope,
    /// Why this delegation happened. Empty/missing = invalid, by design.
    pub purpose: String,
    /// blake3 hash of the previous block's canonical bytes, binding this block
    /// into the chain.
    pub prev_block_hash: Vec<u8>,
    pub signature: indexone_crypto::Signature,
}

/// A complete capability-token chain: one [`RootBlock`] plus zero or more
/// [`DelegationBlock`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub root: RootBlock,
    pub delegations: Vec<DelegationBlock>,
}

/// Errors returned while building or verifying a chain. Each names the exact
/// property that failed, so a verifier fails closed with a typed reason
/// (CLAUDE.md §11 conventions).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("scope widened: a block granted authority its parent did not hold")]
    ScopeWidened,
    #[error("expiry extended: a block outlives the authority it was delegated from")]
    ExpiryExtended,
    #[error("delegation depth exceeded: no remaining hops were authorized")]
    DepthExceeded,
    #[error("missing purpose: delegation blocks must state why authority flowed")]
    MissingPurpose,
    #[error("broken hash link: a block does not reference its predecessor")]
    BrokenHashLink,
    #[error("signature invalid on block {0}")]
    SignatureInvalid(usize),
    #[error("wrong signer: a block was not signed by the key its predecessor delegated to")]
    WrongSigner,
    #[error("principal/key mismatch: a block's principal does not match its predecessor")]
    PrincipalMismatch,
    #[error("root key mismatch: the chain does not trace to the trusted root key")]
    RootKeyMismatch,
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<indexone_crypto::CryptoError> for ChainError {
    fn from(e: indexone_crypto::CryptoError) -> Self {
        ChainError::Crypto(e.to_string())
    }
}

/// Canonical bytes a `RootBlock`'s signature covers (everything but the
/// signature), in RFC 8785 (JCS) form — so an independent encoder recomputes the
/// same bytes and the signature verifies cross-implementation.
fn root_signing_payload(principal: &Principal, key: &PublicKey, scope: &Scope) -> Vec<u8> {
    serde_jcs::to_vec(&(principal, key, scope)).expect("serializable")
}

/// Canonical bytes a `DelegationBlock`'s signature covers (everything but the
/// signature).
#[allow(clippy::too_many_arguments)]
fn delegation_signing_payload(
    from: &Principal,
    from_key: &PublicKey,
    to: &Principal,
    to_key: &PublicKey,
    scope: &Scope,
    purpose: &str,
    prev_block_hash: &[u8],
) -> Vec<u8> {
    serde_jcs::to_vec(&(from, from_key, to, to_key, scope, purpose, prev_block_hash))
        .expect("serializable")
}

/// blake3 over a block's full canonical encoding (signature included), used as
/// the `prev_block_hash` link.
fn hash_bytes(bytes: &[u8]) -> Vec<u8> {
    blake3::hash(bytes).as_bytes().to_vec()
}

fn root_hash(root: &RootBlock) -> Vec<u8> {
    hash_bytes(&serde_jcs::to_vec(root).expect("serializable"))
}

fn delegation_hash(block: &DelegationBlock) -> Vec<u8> {
    hash_bytes(&serde_jcs::to_vec(block).expect("serializable"))
}

impl Chain {
    /// Issue a fresh chain from a human root authority, signing Block 0 with
    /// `signer` (whose public key becomes the chain's trust anchor).
    pub fn issue(signer: &dyn Signer, principal: Principal, scope: Scope) -> Chain {
        let key = signer.public_key();
        let payload = root_signing_payload(&principal, &key, &scope);
        let signature = signer.sign(&payload).expect("sign root");
        Chain {
            root: RootBlock {
                principal,
                principal_key: key,
                scope,
                signature,
            },
            delegations: Vec::new(),
        }
    }

    /// Adopt an already-signed root block, checking its signature first.
    pub fn from_root(root: RootBlock) -> Result<Chain, ChainError> {
        let payload = root_signing_payload(&root.principal, &root.principal_key, &root.scope);
        if !verify_signature(&payload, &root.signature, &root.principal_key)? {
            return Err(ChainError::SignatureInvalid(0));
        }
        Ok(Chain {
            root,
            delegations: Vec::new(),
        })
    }

    /// Scope and signing key at the current tail of the chain — what the next
    /// hop must narrow from and be signed under.
    fn tail(&self) -> (&Scope, &PublicKey, &Principal, Vec<u8>) {
        match self.delegations.last() {
            None => (
                &self.root.scope,
                &self.root.principal_key,
                &self.root.principal,
                root_hash(&self.root),
            ),
            Some(last) => (&last.scope, &last.to_key, &last.to, delegation_hash(last)),
        }
    }

    /// Append a delegation hop, narrowing scope from the current tail and
    /// signing it with `signer`.
    ///
    /// `signer` must be the key the current tail delegated to (the root key for
    /// the first hop, else the previous block's `to_key`) — this is what makes
    /// the appended chain verifiable end-to-end. Enforces the attenuation
    /// invariants: scope subset, expiry no later, depth strictly decreasing
    /// (and > 0), purpose non-empty.
    pub fn attenuate(
        &mut self,
        signer: &dyn Signer,
        to: Principal,
        to_key: PublicKey,
        new_scope: Scope,
        purpose: String,
    ) -> Result<(), ChainError> {
        if purpose.trim().is_empty() {
            return Err(ChainError::MissingPurpose);
        }
        let (tail_scope, tail_key, _tail_principal, prev_hash) = self.tail();
        if signer.public_key() != *tail_key {
            return Err(ChainError::WrongSigner);
        }
        if tail_scope.max_depth == 0 {
            return Err(ChainError::DepthExceeded);
        }
        new_scope.is_narrowing_of(tail_scope)?;
        if new_scope.max_depth >= tail_scope.max_depth {
            return Err(ChainError::ScopeWidened);
        }

        let from_principal = _tail_principal.clone();
        let from_key = tail_key.clone();
        let payload = delegation_signing_payload(
            &from_principal,
            &from_key,
            &to,
            &to_key,
            &new_scope,
            &purpose,
            &prev_hash,
        );
        let signature = signer.sign(&payload)?;
        self.delegations.push(DelegationBlock {
            from: from_principal,
            from_key,
            to,
            to_key,
            scope: new_scope,
            purpose,
            prev_block_hash: prev_hash,
            signature,
        });
        Ok(())
    }

    /// Verify the entire chain against a trusted root key: every signature,
    /// every hash link, cryptographic hop-to-hop continuity, and every
    /// attenuation invariant. Returns the effective (narrowest) [`Scope`] the
    /// final hop is authorized for.
    ///
    /// Pure function of the token's own bytes — no network, no shared database.
    /// Revocation freshness (which *does* need an out-of-band check) is layered
    /// on top via `indexone-revocation`, not folded in here.
    pub fn verify(&self, root_key: &PublicKey) -> Result<Scope, ChainError> {
        if self.root.principal_key != *root_key {
            return Err(ChainError::RootKeyMismatch);
        }
        let root_payload = root_signing_payload(
            &self.root.principal,
            &self.root.principal_key,
            &self.root.scope,
        );
        if !verify_signature(
            &root_payload,
            &self.root.signature,
            &self.root.principal_key,
        )? {
            return Err(ChainError::SignatureInvalid(0));
        }

        let mut prev_scope = &self.root.scope;
        let mut expected_signer_key = &self.root.principal_key;
        let mut expected_from = &self.root.principal;
        let mut prev_hash = root_hash(&self.root);

        for (i, block) in self.delegations.iter().enumerate() {
            let block_index = i + 1;
            // Cryptographic continuity: this block must be signed by the key the
            // previous hop delegated to, by the principal it named.
            if block.from_key != *expected_signer_key {
                return Err(ChainError::WrongSigner);
            }
            if block.from != *expected_from {
                return Err(ChainError::PrincipalMismatch);
            }
            if block.prev_block_hash != prev_hash {
                return Err(ChainError::BrokenHashLink);
            }
            if block.purpose.trim().is_empty() {
                return Err(ChainError::MissingPurpose);
            }
            // Attenuation invariants.
            if prev_scope.max_depth == 0 {
                return Err(ChainError::DepthExceeded);
            }
            block.scope.is_narrowing_of(prev_scope)?;
            if block.scope.max_depth >= prev_scope.max_depth {
                return Err(ChainError::ScopeWidened);
            }
            // Signature.
            let payload = delegation_signing_payload(
                &block.from,
                &block.from_key,
                &block.to,
                &block.to_key,
                &block.scope,
                &block.purpose,
                &block.prev_block_hash,
            );
            if !verify_signature(&payload, &block.signature, &block.from_key)? {
                return Err(ChainError::SignatureInvalid(block_index));
            }

            prev_scope = &block.scope;
            expected_signer_key = &block.to_key;
            expected_from = &block.to;
            prev_hash = delegation_hash(block);
        }

        Ok(prev_scope.clone())
    }

    /// blake3 digest of the whole chain's canonical bytes — a stable identifier
    /// for "the authority this action ran under", committed to by witness
    /// receipts and completion attestations.
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&serde_jcs::to_vec(self).expect("serializable")).as_bytes()
    }

    /// The public key of the agent at the end of the chain — the party that
    /// actually executes the final action. A completion attestation signed by
    /// *this* key is self-reported (not independent); the verifier rejects it.
    pub fn executor_key(&self) -> &PublicKey {
        match self.delegations.last() {
            Some(last) => &last.to_key,
            None => &self.root.principal_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexone_crypto::Ed25519Signer;

    fn principal(id: &str) -> Principal {
        Principal {
            id: id.to_string(),
            display_name: id.to_string(),
        }
    }

    fn scope(perms: &[&str], budget: u64, depth: u32) -> Scope {
        Scope {
            permissions: perms.iter().map(|s| Permission::action(*s)).collect(),
            budget: Some(budget),
            currency: Some("USD".to_string()),
            max_depth: depth,
            expires_at: 4_102_444_800,
        }
    }

    /// Build the canonical happy-path 3-hop cross-org chain:
    /// Human → Agent A (org1) → Agent B (org2) → Agent C (org3).
    fn three_hop() -> (Chain, PublicKey) {
        let human = Ed25519Signer::from_seed([1u8; 32]);
        let a = Ed25519Signer::from_seed([2u8; 32]);
        let b = Ed25519Signer::from_seed([3u8; 32]);
        let c = Ed25519Signer::from_seed([4u8; 32]);
        let root_key = human.public_key();

        let mut chain = Chain::issue(
            &human,
            principal("human:alice"),
            scope(&["payments.charge"], 10_000, 3),
        );
        chain
            .attenuate(
                &human,
                principal("agent:a@org1"),
                a.public_key(),
                scope(&["payments.charge"], 5_000, 2),
                "book travel under $50".into(),
            )
            .unwrap();
        chain
            .attenuate(
                &a,
                principal("agent:b@org2"),
                b.public_key(),
                scope(&["payments.charge"], 5_000, 1),
                "charge the airline".into(),
            )
            .unwrap();
        chain
            .attenuate(
                &b,
                principal("agent:c@org3"),
                c.public_key(),
                scope(&["payments.charge"], 4_000, 0),
                "settle fare".into(),
            )
            .unwrap();
        (chain, root_key)
    }

    #[test]
    fn valid_three_hop_chain_verifies() {
        let (chain, root_key) = three_hop();
        let effective = chain.verify(&root_key).unwrap();
        assert_eq!(effective.budget, Some(4_000));
        assert_eq!(effective.max_depth, 0);
    }

    #[test]
    fn widening_scope_is_rejected() {
        // Claim targets invariant #2 (scope only narrows). A hop that tries to
        // grant a permission its parent never held must fail closed.
        let a = Ed25519Signer::from_seed([2u8; 32]);
        let human = Ed25519Signer::from_seed([1u8; 32]);
        let mut chain = Chain::issue(
            &human,
            principal("human:alice"),
            scope(&["payments.charge"], 10_000, 2),
        );
        let err = chain
            .attenuate(
                &human,
                principal("agent:a@org1"),
                a.public_key(),
                scope(&["payments.charge", "payments.refund"], 10_000, 1),
                "grab extra authority".into(),
            )
            .unwrap_err();
        assert_eq!(err, ChainError::ScopeWidened);
    }

    #[test]
    fn empty_purpose_is_rejected() {
        let human = Ed25519Signer::from_seed([1u8; 32]);
        let a = Ed25519Signer::from_seed([2u8; 32]);
        let mut chain = Chain::issue(
            &human,
            principal("human:alice"),
            scope(&["payments.charge"], 10_000, 2),
        );
        let err = chain
            .attenuate(
                &human,
                principal("agent:a@org1"),
                a.public_key(),
                scope(&["payments.charge"], 5_000, 1),
                "   ".into(),
            )
            .unwrap_err();
        assert_eq!(err, ChainError::MissingPurpose);
    }

    #[test]
    fn wrong_signer_cannot_extend_chain() {
        // A key the previous hop never delegated to must not be able to append.
        let human = Ed25519Signer::from_seed([1u8; 32]);
        let a = Ed25519Signer::from_seed([2u8; 32]);
        let impostor = Ed25519Signer::from_seed([99u8; 32]);
        let mut chain = Chain::issue(
            &human,
            principal("human:alice"),
            scope(&["payments.charge"], 10_000, 2),
        );
        let err = chain
            .attenuate(
                &impostor,
                principal("agent:a@org1"),
                a.public_key(),
                scope(&["payments.charge"], 5_000, 1),
                "splice in".into(),
            )
            .unwrap_err();
        assert_eq!(err, ChainError::WrongSigner);
    }

    #[test]
    fn tampered_scope_after_signing_fails_verification() {
        // Mutating a signed block's scope must break its signature.
        let (mut chain, root_key) = three_hop();
        chain.delegations[1].scope.budget = Some(9_999);
        assert!(chain.verify(&root_key).is_err());
    }

    #[test]
    fn wrong_root_key_is_rejected() {
        let (chain, _) = three_hop();
        let attacker = Ed25519Signer::from_seed([250u8; 32]);
        assert_eq!(
            chain.verify(&attacker.public_key()).unwrap_err(),
            ChainError::RootKeyMismatch
        );
    }

    // Claim: RFC 8785 (JCS) canonicalization is key-order-independent — two
    // structurally-equal values with different key insertion order produce
    // identical bytes. This is what lets an independent encoder recompute the
    // exact bytes a signature was made over.
    #[test]
    fn canonicalization_is_key_order_independent() {
        let a = serde_json::json!({"b": 1, "a": {"y": 2, "x": 3}});
        let b = serde_json::json!({"a": {"x": 3, "y": 2}, "b": 1});
        assert_eq!(
            serde_jcs::to_vec(&a).unwrap(),
            serde_jcs::to_vec(&b).unwrap()
        );
    }

    // --- structured scope: constraint-entailment narrowing ---

    fn cperm(action: &str, cs: Vec<Constraint>) -> Permission {
        Permission::with(action, cs)
    }

    /// A scope whose single permission is `p` (budget/expiry equal so only the
    /// permission dimension is under test).
    fn scope_with(p: Permission) -> Scope {
        let mut s = scope(&[], 10_000, 3);
        s.permissions = vec![p];
        s
    }

    #[test]
    fn tightening_an_amount_cap_narrows() {
        let parent = scope_with(cperm("payments.charge", vec![Constraint::AmountMax(500)]));
        let child = scope_with(cperm("payments.charge", vec![Constraint::AmountMax(300)]));
        assert!(child.is_narrowing_of(&parent).is_ok());
    }

    #[test]
    fn raising_an_amount_cap_is_rejected() {
        let parent = scope_with(cperm("payments.charge", vec![Constraint::AmountMax(300)]));
        let child = scope_with(cperm("payments.charge", vec![Constraint::AmountMax(500)]));
        assert_eq!(
            child.is_narrowing_of(&parent).unwrap_err(),
            ChainError::ScopeWidened
        );
    }

    #[test]
    fn adding_a_constraint_to_a_bare_parent_narrows() {
        // Parent unbounded on amount + resource; child confines both → tighter.
        let parent = scope_with(Permission::action("payments.charge"));
        let child = scope_with(cperm(
            "payments.charge",
            vec![
                Constraint::AmountMax(500),
                Constraint::ResourceIn(vec!["airlines".into()]),
            ],
        ));
        assert!(child.is_narrowing_of(&parent).is_ok());
    }

    #[test]
    fn dropping_a_parent_constraint_is_rejected() {
        // Parent caps the amount; a bare child is unbounded again → broader.
        let parent = scope_with(cperm("payments.charge", vec![Constraint::AmountMax(500)]));
        let child = scope_with(Permission::action("payments.charge"));
        assert_eq!(
            child.is_narrowing_of(&parent).unwrap_err(),
            ChainError::ScopeWidened
        );
    }

    #[test]
    fn resource_subset_narrows_but_superset_is_rejected() {
        let parent = scope_with(cperm(
            "payments.charge",
            vec![Constraint::ResourceIn(vec![
                "airlines".into(),
                "hotels".into(),
            ])],
        ));
        let subset = scope_with(cperm(
            "payments.charge",
            vec![Constraint::ResourceIn(vec!["airlines".into()])],
        ));
        assert!(subset.is_narrowing_of(&parent).is_ok());
        let superset = scope_with(cperm(
            "payments.charge",
            vec![Constraint::ResourceIn(vec![
                "airlines".into(),
                "hotels".into(),
                "casinos".into(),
            ])],
        ));
        assert_eq!(
            superset.is_narrowing_of(&parent).unwrap_err(),
            ChainError::ScopeWidened
        );
    }

    #[test]
    fn a_different_action_never_narrows() {
        let parent = scope_with(Permission::action("payments.charge"));
        let child = scope_with(Permission::action("payments.refund"));
        assert_eq!(
            child.is_narrowing_of(&parent).unwrap_err(),
            ChainError::ScopeWidened
        );
    }

    #[test]
    fn bare_permission_serializes_as_a_plain_string() {
        // Backward compatibility: a bare permission is a JSON string, so existing
        // ["payments.charge"] tokens and the signatures over them are byte-identical.
        let bare = Permission::action("payments.charge");
        assert_eq!(serde_json::to_string(&bare).unwrap(), "\"payments.charge\"");
        let back: Permission = serde_json::from_str("\"payments.charge\"").unwrap();
        assert_eq!(back, bare);
    }

    #[test]
    fn constrained_permission_round_trips_as_object() {
        let p = Permission::with(
            "payments.charge",
            vec![
                Constraint::AmountMax(500),
                Constraint::ResourceIn(vec!["airlines".into()]),
            ],
        );
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"action\"") && json.contains("amount_max"));
        let back: Permission = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn structured_narrowing_holds_through_a_signed_chain() {
        // End-to-end: a constrained permission attenuated down a real signed hop.
        let human = Ed25519Signer::from_seed([1u8; 32]);
        let a = Ed25519Signer::from_seed([2u8; 32]);
        let root_key = human.public_key();
        let mut root_scope = scope(&[], 10_000, 2);
        root_scope.permissions = vec![cperm(
            "payments.charge",
            vec![
                Constraint::AmountMax(500),
                Constraint::ResourceIn(vec!["airlines".into(), "hotels".into()]),
            ],
        )];
        let mut chain = Chain::issue(&human, principal("human:alice"), root_scope);
        let mut child_scope = scope(&[], 5_000, 1);
        child_scope.permissions = vec![cperm(
            "payments.charge",
            vec![
                Constraint::AmountMax(300),
                Constraint::ResourceIn(vec!["airlines".into()]),
            ],
        )];
        chain
            .attenuate(
                &human,
                principal("agent:a@org1"),
                a.public_key(),
                child_scope,
                "book a flight under $3".into(),
            )
            .unwrap();
        assert!(chain.verify(&root_key).is_ok());
    }
}
