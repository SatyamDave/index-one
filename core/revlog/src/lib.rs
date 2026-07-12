//! `indexone-revlog` — a **log-backed** revocation map (v2 part b).
//!
//! `indexone-revmap` gives a sparse Merkle map with non-inclusion proofs against
//! a root. But a bare signed root has no append-only guarantee: an operator can
//! **equivocate** (serve a different root to different observers) or **roll
//! back** (silently un-revoke by publishing an earlier root). This crate closes
//! that gap the way Trillian's log-derived map does — without changing either
//! `revmap` or `witness`:
//!
//! 1. Each epoch, a [`MapCheckpoint`] `{epoch, map_root, prev_log_root}` is
//!    committed as one leaf in the RFC 6962 [`Witness`] we already run.
//! 2. A client's status proof ([`LogBackedProof`]) then binds three facts: the
//!    map (non-)inclusion of the key against `map_root`, that the *exact*
//!    `map_root` is the one committed in the signed log (via the leaf's
//!    inclusion proof), and — across two heads — that the log only appended
//!    (via the witness's consistency proof).
//!
//! The map root a client checks against is therefore pinned into an append-only
//! log: the operator cannot present a second, contradictory root without it
//! being a second, *detectable* leaf, and cannot roll back without breaking a
//! consistency proof.
//!
//! Honest boundary (CLAUDE.md §4): this makes equivocation and rollback
//! **detectable** — it does **not** make the set *complete*. An operator that
//! never inserts a revocation still produces a valid, consistent proof; catching
//! that needs an out-of-band monitor. A witness anchors what was reported.

use serde::{Deserialize, Serialize};

use indexone_crypto::{PublicKey, Signer};
use indexone_revmap::{
    verify_inclusion as verify_map_inclusion, verify_non_inclusion, Hash, MapProof, RevocationMap,
};
use indexone_witness::{
    verify_inclusion as verify_log_inclusion, ActionReceipt, Digest, InclusionProof, Witness,
};

// Re-export the witness primitives a client needs (consistency for rollback
// detection, the signed head to anchor against) so this crate is a single
// facade — the log only ever appends.
pub use indexone_witness::{
    verify_consistency, verify_signed_head, ConsistencyProof, SignedTreeHead,
};

/// Domain tag marking a witness leaf as a revocation-map checkpoint (kept in the
/// receipt's `chain_digest` slot, so these leaves are distinguishable and a
/// verifier can insist on it).
const CHECKPOINT_DOMAIN: &[u8] = b"indexone-revlog/MapCheckpoint/v1";
const NONCE_DOMAIN: &[u8] = b"indexone-revlog/checkpoint-nonce/v1";

/// The fixed digest stamped into a checkpoint leaf's `chain_digest`.
fn checkpoint_leaf_tag() -> Digest {
    *blake3::hash(CHECKPOINT_DOMAIN).as_bytes()
}

/// A commitment to the revocation map's state at one epoch. Its digest is what
/// gets bound into the append-only log, so the `map_root` a client trusts is
/// exactly the one the log recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapCheckpoint {
    /// Monotonic epoch (one per published checkpoint).
    pub epoch: u64,
    /// The sparse-Merkle map root this checkpoint freezes.
    pub map_root: Hash,
    /// The witness root this checkpoint was appended on top of — chains
    /// checkpoints so a rewrite of the checkpoint history is detectable.
    pub prev_log_root: Digest,
}

impl MapCheckpoint {
    /// Domain-separated digest committed as the log leaf's `action_digest`.
    /// Binds every field, so altering `map_root` (equivocation) changes the
    /// digest and breaks the leaf's inclusion proof.
    pub fn digest(&self) -> Digest {
        let mut h = blake3::Hasher::new();
        h.update(CHECKPOINT_DOMAIN);
        h.update(&self.epoch.to_be_bytes());
        h.update(&self.map_root);
        h.update(&self.prev_log_root);
        *h.finalize().as_bytes()
    }

    /// The witness leaf that commits this checkpoint. `action_digest` carries the
    /// checkpoint digest (its documented caller-defined role); `nonce` is
    /// epoch-and-root derived so distinct checkpoints never share a leaf.
    fn receipt(&self) -> ActionReceipt {
        let mut nonce = blake3::Hasher::new();
        nonce.update(NONCE_DOMAIN);
        nonce.update(&self.epoch.to_be_bytes());
        nonce.update(&self.map_root);
        ActionReceipt {
            chain_digest: checkpoint_leaf_tag(),
            action_digest: self.digest(),
            nonce: *nonce.finalize().as_bytes(),
            prev_root: self.prev_log_root,
        }
    }
}

/// A revocation map whose successive roots are committed into an append-only
/// witness log.
pub struct LogBackedRevocation {
    map: RevocationMap,
    witness: Witness,
    epoch: u64,
    latest: Option<Committed>,
}

struct Committed {
    checkpoint: MapCheckpoint,
    leaf_index: usize,
}

impl Default for LogBackedRevocation {
    fn default() -> Self {
        LogBackedRevocation::new()
    }
}

impl LogBackedRevocation {
    pub fn new() -> LogBackedRevocation {
        LogBackedRevocation {
            map: RevocationMap::new(),
            witness: Witness::new(),
            epoch: 0,
            latest: None,
        }
    }

    /// Mark `key` revoked in the map. Takes effect for clients only once a new
    /// checkpoint is published (so a proof is always against a *logged* root).
    pub fn revoke(&mut self, key: Hash) {
        self.map.revoke(key);
    }

    /// Freeze the current map root into the log as a new checkpoint and return
    /// the freshly signed tree head. Monotonic epoch; append-only.
    pub fn publish_checkpoint(&mut self, log_signer: &dyn Signer) -> SignedTreeHead {
        let checkpoint = MapCheckpoint {
            epoch: self.epoch,
            map_root: self.map.root(),
            prev_log_root: self.witness.root(),
        };
        let leaf_index = self.witness.append(&checkpoint.receipt());
        self.latest = Some(Committed {
            checkpoint,
            leaf_index,
        });
        self.epoch += 1;
        self.witness.signed_head(log_signer)
    }

    /// The current signed tree head (for gossip / a client's last-seen anchor).
    pub fn signed_head(&self, log_signer: &dyn Signer) -> SignedTreeHead {
        self.witness.signed_head(log_signer)
    }

    /// A consistency proof `old_size → new_size`, for a client to confirm the
    /// checkpoint log only appended (rollback/equivocation detection).
    pub fn consistency_proof(&self, old_size: usize, new_size: usize) -> Option<ConsistencyProof> {
        self.witness.consistency_proof(old_size, new_size)
    }

    /// Build a log-backed status proof for `key` against the latest checkpoint.
    /// Fails closed (`None`) if no checkpoint has been published, or if the map
    /// has changed since the last checkpoint (so a proof is never served against
    /// an unlogged root — publish a checkpoint after revoking).
    pub fn prove(&self, key: &Hash, log_signer: &dyn Signer) -> Option<LogBackedProof> {
        let committed = self.latest.as_ref()?;
        if self.map.root() != committed.checkpoint.map_root {
            return None;
        }
        let inclusion = self.witness.inclusion_proof(committed.leaf_index)?;
        Some(LogBackedProof {
            checkpoint: committed.checkpoint.clone(),
            map_proof: self.map.prove(key),
            inclusion,
            sth: self.witness.signed_head(log_signer),
        })
    }
}

/// Everything a relying party needs to check a key's revocation status offline
/// against a *logged* map root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogBackedProof {
    pub checkpoint: MapCheckpoint,
    pub map_proof: MapProof,
    /// Inclusion of the checkpoint's leaf in the signed log.
    pub inclusion: InclusionProof,
    pub sth: SignedTreeHead,
}

/// Whether the proof's `map_root` is genuinely the one committed in the signed,
/// append-only log: the checkpoint leaf is well-formed, its digest binds this
/// exact checkpoint, the tree head is validly signed, and the leaf is included.
fn map_root_is_logged(proof: &LogBackedProof, log_key: &PublicKey) -> bool {
    let receipt = proof.checkpoint.receipt();
    receipt.chain_digest == checkpoint_leaf_tag()
        && receipt.action_digest == proof.checkpoint.digest()
        && verify_signed_head(&proof.sth, log_key)
        && verify_log_inclusion(&receipt, &proof.inclusion, &proof.sth.root)
}

/// Verify that `key` is **not** revoked, against a map root pinned in the log.
/// Fails closed on any broken link.
pub fn verify_not_revoked(proof: &LogBackedProof, key: &Hash, log_key: &PublicKey) -> bool {
    map_root_is_logged(proof, log_key)
        && verify_non_inclusion(&proof.checkpoint.map_root, key, &proof.map_proof)
}

/// Verify that `key` **is** revoked, against a map root pinned in the log.
pub fn verify_revoked(proof: &LogBackedProof, key: &Hash, log_key: &PublicKey) -> bool {
    map_root_is_logged(proof, log_key)
        && verify_map_inclusion(&proof.checkpoint.map_root, key, &proof.map_proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexone_crypto::{Ed25519Signer, Signer};

    fn key(tag: u8) -> Hash {
        *blake3::hash(&[tag]).as_bytes()
    }

    /// Happy path: a revoked key verifies as revoked and a live key as
    /// not-revoked, both against a map root committed in the signed log.
    #[test]
    fn logged_status_verifies_both_directions() {
        let signer = Ed25519Signer::from_seed([1u8; 32]);
        let log_key = signer.public_key();
        let mut rl = LogBackedRevocation::new();
        let revoked = key(1);
        let live = key(2);
        rl.revoke(revoked);
        rl.publish_checkpoint(&signer);

        let p_live = rl.prove(&live, &signer).unwrap();
        assert!(verify_not_revoked(&p_live, &live, &log_key));
        assert!(!verify_revoked(&p_live, &live, &log_key));

        let p_rev = rl.prove(&revoked, &signer).unwrap();
        assert!(verify_revoked(&p_rev, &revoked, &log_key));
        assert!(!verify_not_revoked(&p_rev, &revoked, &log_key));
    }

    /// Equivocation is caught: swapping the checkpoint's `map_root` for a forged
    /// one breaks the binding — the forged root is not the logged one, so the
    /// leaf inclusion no longer holds.
    #[test]
    fn forged_map_root_is_rejected() {
        let signer = Ed25519Signer::from_seed([2u8; 32]);
        let log_key = signer.public_key();
        let mut rl = LogBackedRevocation::new();
        let victim = key(9);
        rl.revoke(victim);
        rl.publish_checkpoint(&signer);

        // The operator wants `victim` to look live: build a proof, then swap in a
        // map where `victim` is absent. The map_proof would verify non-inclusion
        // against that forged root, but the forged root isn't the logged one.
        let forged_map = RevocationMap::new(); // victim absent
        let forged_root = forged_map.root();
        let mut proof = rl.prove(&victim, &signer).unwrap();
        proof.checkpoint.map_root = forged_root;
        proof.map_proof = forged_map.prove(&victim);

        // Non-inclusion against the forged root is internally consistent...
        assert!(verify_non_inclusion(
            &forged_root,
            &victim,
            &proof.map_proof
        ));
        // ...but the log-backed check rejects it: that root was never committed.
        assert!(!verify_not_revoked(&proof, &victim, &log_key));
    }

    /// A tree head signed by the wrong key is rejected (fail closed).
    #[test]
    fn wrong_log_key_is_rejected() {
        let signer = Ed25519Signer::from_seed([3u8; 32]);
        let impostor = Ed25519Signer::from_seed([4u8; 32]);
        let mut rl = LogBackedRevocation::new();
        rl.revoke(key(1));
        rl.publish_checkpoint(&signer);
        let proof = rl.prove(&key(2), &signer).unwrap();
        assert!(!verify_not_revoked(&proof, &key(2), &impostor.public_key()));
    }

    /// The checkpoint sequence is append-only: successive heads produce a valid
    /// consistency proof, and a rollback (old_size > new_size) is refused.
    #[test]
    fn checkpoint_log_is_append_only() {
        let signer = Ed25519Signer::from_seed([5u8; 32]);
        let mut rl = LogBackedRevocation::new();

        let sth0 = rl.publish_checkpoint(&signer); // size 1
        rl.revoke(key(7));
        let sth1 = rl.publish_checkpoint(&signer); // size 2

        let proof = rl
            .consistency_proof(sth0.tree_size, sth1.tree_size)
            .unwrap();
        assert!(verify_consistency(
            &sth0.root,
            &sth1.root,
            &proof,
            sth0.tree_size,
            sth1.tree_size
        ));
        // Rollback (serving the smaller, older tree as if newer) is refused: a
        // client tracking sth1 will never accept a consistency proof to sth0.
        assert!(!verify_consistency(
            &sth1.root,
            &sth0.root,
            &proof,
            sth1.tree_size,
            sth0.tree_size
        ));
    }

    /// Fail closed: no proof is served against an unlogged root — if the map is
    /// mutated after a checkpoint without republishing, `prove` returns `None`.
    #[test]
    fn no_proof_against_an_unlogged_root() {
        let signer = Ed25519Signer::from_seed([6u8; 32]);
        let mut rl = LogBackedRevocation::new();
        rl.revoke(key(1));
        rl.publish_checkpoint(&signer);
        // Mutate the map without a new checkpoint → the current root no longer
        // matches the logged one.
        rl.revoke(key(2));
        assert!(rl.prove(&key(3), &signer).is_none());
    }
}
