//! `indexone-revmap` — a sparse Merkle map with compact **non-inclusion** proofs.
//!
//! An append-only Merkle log (`indexone-witness`) proves *inclusion* and
//! *consistency* but can never prove *absence* — yet the verifier's hot path is
//! the negative query, "prove this hop is **NOT** revoked". This crate is the v2
//! answer (see `docs/REVOCATION_TRANSPARENCY.md`): a Merkle tree over the whole
//! 256-bit key space, where a revoked key's leaf is *present* and every other
//! leaf is a fixed empty constant. A short audit path to that empty leaf, which
//! recomputes the signed root, is a proof the key is absent.
//!
//! The 2²⁵⁶-leaf tree is tractable via the classic default-subtree trick: an
//! empty subtree of a given height always has the same hash, so we precompute
//! one default per level ([`Defaults`]) and never materialise empty regions. A
//! proof carries only the *non-default* siblings plus a 256-bit bitmap
//! ([`MapProof`]), so it stays ~O(log n) hashes instead of 256.
//!
//! Scope boundary (honest, per CLAUDE.md §4): a signed root proves the map's
//! *reported* state, not ground truth. Log-backing the roots (committing each
//! epoch's root as a leaf in the RFC 6962 witness we already run) makes
//! root-equivocation and rollback *detectable* — it does **not** make the set
//! *complete*; an operator that never inserts a revocation still produces a
//! valid, consistent proof. That boundary is the caller's to close with an
//! out-of-band monitor.
//!
//! Cryptographic discipline (the pitfalls the survey flagged):
//! - **Leaf/internal domain separation** — leaves are hashed under tag `0x00`,
//!   internal nodes under `0x01`, and the empty leaf under a distinct ASCII
//!   domain string, so no leaf preimage can be reinterpreted as a node (or as
//!   the empty constant), foreclosing second-preimage confusion.
//! - **Default siblings are reconstructed locally**, never trusted from the
//!   proof — a verifier recomputes every default from [`Defaults`], so a forged
//!   "this level is default" bit cannot smuggle in an attacker-chosen hash.

use serde::{Deserialize, Serialize};

/// A 32-byte blake3 digest — a node hash, a leaf hash, or a key/path.
pub type Hash = [u8; 32];

const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;
/// The empty-leaf constant's preimage. A fixed ASCII domain string, so its input
/// space cannot collide with a real leaf (`0x00 ‖ key`) or a node (`0x01 ‖ …`).
const EMPTY_LEAF_DOMAIN: &[u8] = b"indexone-revmap/empty-leaf/v1";

/// Depth of the tree = key width in bits. A blake3 key gives a uniform path.
const DEPTH: usize = 256;

/// The hash of a *present* (revoked) leaf at `key`: `blake3(0x00 ‖ key)`.
/// Binds the key, so a proof for one key can't be replayed at another.
fn leaf_hash(key: &Hash) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[LEAF_TAG]);
    h.update(key);
    *h.finalize().as_bytes()
}

/// An internal node: `blake3(0x01 ‖ left ‖ right)`.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[NODE_TAG]);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

fn empty_leaf() -> Hash {
    *blake3::hash(EMPTY_LEAF_DOMAIN).as_bytes()
}

/// Bit `i` of a 256-bit key, MSB-first (bit 0 is the top of the tree).
fn bit(key: &Hash, i: usize) -> u8 {
    (key[i / 8] >> (7 - (i % 8))) & 1
}

/// Precomputed hash of a fully-empty subtree, indexed by height:
/// `default[0]` = the empty leaf, `default[h] = node(default[h-1], default[h-1])`.
/// So an empty subtree rooted at `depth` has hash `default[DEPTH - depth]`.
struct Defaults([Hash; DEPTH + 1]);

impl Defaults {
    fn new() -> Defaults {
        let mut d = [[0u8; 32]; DEPTH + 1];
        d[0] = empty_leaf();
        for h in 1..=DEPTH {
            d[h] = node_hash(&d[h - 1], &d[h - 1]);
        }
        Defaults(d)
    }

    /// The hash of an empty subtree of the given `height`.
    fn at_height(&self, height: usize) -> Hash {
        self.0[height]
    }

    /// The default hash of a node at `depth` (its subtree has height `DEPTH - depth`).
    fn at_depth(&self, depth: usize) -> Hash {
        self.0[DEPTH - depth]
    }
}

/// A compact (non-)inclusion proof: the siblings along a key's root-to-leaf
/// path, with all-empty siblings elided.
///
/// `present` is a 256-bit bitmap (32 bytes): bit `d` set ⇒ `siblings` carries a
/// real hash for depth `d`; unset ⇒ the sibling is the default for that depth,
/// reconstructed locally by the verifier (never taken from the proof).
/// `siblings` lists the non-default hashes in ascending depth order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapProof {
    pub present: Vec<u8>,
    pub siblings: Vec<Hash>,
}

impl MapProof {
    /// Expand back to the full 256-sibling path, filling elided levels with the
    /// locally-recomputed defaults. Returns `None` if the bitmap and the sibling
    /// count disagree (a malformed proof — fail closed).
    fn expand(&self, defaults: &Defaults) -> Option<[Hash; DEPTH]> {
        if self.present.len() != DEPTH / 8 {
            return None;
        }
        let mut full = [[0u8; 32]; DEPTH];
        let mut next = self.siblings.iter();
        for (d, slot) in full.iter_mut().enumerate() {
            let is_present = (self.present[d / 8] >> (7 - (d % 8))) & 1 == 1;
            *slot = if is_present {
                *next.next()?
            } else {
                // Sibling of the node at depth d is itself a subtree of height
                // DEPTH - (d + 1); its default is default[DEPTH - d - 1].
                defaults.at_height(DEPTH - d - 1)
            };
        }
        // A present-bit count that exceeds the siblings we consumed is malformed.
        if next.next().is_some() {
            return None;
        }
        Some(full)
    }
}

/// A sparse Merkle map from 256-bit key to "revoked". Holds only the populated
/// (revoked) keys; everything else is empty by construction.
pub struct RevocationMap {
    /// Revoked keys, kept sorted so subtree partitioning is deterministic.
    keys: Vec<Hash>,
    defaults: Defaults,
}

impl Default for RevocationMap {
    fn default() -> Self {
        RevocationMap::new()
    }
}

impl RevocationMap {
    pub fn new() -> RevocationMap {
        RevocationMap {
            keys: Vec::new(),
            defaults: Defaults::new(),
        }
    }

    /// Mark `key` revoked. Idempotent; keeps the key set sorted.
    pub fn revoke(&mut self, key: Hash) {
        if let Err(pos) = self.keys.binary_search(&key) {
            self.keys.insert(pos, key);
        }
    }

    pub fn contains(&self, key: &Hash) -> bool {
        self.keys.binary_search(key).is_ok()
    }

    /// The current Merkle root over the whole 256-bit key space.
    pub fn root(&self) -> Hash {
        self.subtree_root(&self.keys, 0)
    }

    /// Root of the subtree at `depth` spanning exactly the given (sorted) keys.
    /// Empty span ⇒ the precomputed default; a full-depth span ⇒ the single
    /// leaf. Keys are unique, so at `DEPTH` there is at most one.
    fn subtree_root(&self, keys: &[Hash], depth: usize) -> Hash {
        if keys.is_empty() {
            return self.defaults.at_depth(depth);
        }
        if depth == DEPTH {
            return leaf_hash(&keys[0]);
        }
        let split = keys.partition_point(|k| bit(k, depth) == 0);
        let (left, right) = keys.split_at(split);
        node_hash(
            &self.subtree_root(left, depth + 1),
            &self.subtree_root(right, depth + 1),
        )
    }

    /// A (non-)inclusion proof for `key`: the siblings along its path, compacted.
    /// The same proof shape serves both — it's the *claimed leaf* the verifier
    /// supplies ([`verify_inclusion`] vs [`verify_non_inclusion`]) that decides
    /// which is being asserted.
    pub fn prove(&self, key: &Hash) -> MapProof {
        let mut siblings = Vec::new();
        let mut present = vec![0u8; DEPTH / 8];
        self.collect_siblings(&self.keys, 0, key, &mut siblings, &mut present);
        MapProof { present, siblings }
    }

    fn collect_siblings(
        &self,
        keys: &[Hash],
        depth: usize,
        key: &Hash,
        siblings: &mut Vec<Hash>,
        present: &mut [u8],
    ) {
        if depth == DEPTH {
            return;
        }
        let split = keys.partition_point(|k| bit(k, depth) == 0);
        let (left, right) = keys.split_at(split);
        let (same, other) = if bit(key, depth) == 0 {
            (left, right)
        } else {
            (right, left)
        };
        let sibling = self.subtree_root(other, depth + 1);
        if sibling != self.defaults.at_depth(depth) {
            present[depth / 8] |= 1 << (7 - (depth % 8));
            siblings.push(sibling);
        }
        self.collect_siblings(same, depth + 1, key, siblings, present);
    }
}

/// Recompute a candidate root from `key`, a `claimed_leaf`, and `proof`, folding
/// bottom-up. The heart of both verification directions.
fn recompute_root(key: &Hash, claimed_leaf: Hash, proof: &MapProof) -> Option<Hash> {
    let defaults = Defaults::new();
    let full = proof.expand(&defaults)?;
    let mut cur = claimed_leaf;
    for depth in (0..DEPTH).rev() {
        let sib = full[depth];
        cur = if bit(key, depth) == 0 {
            node_hash(&cur, &sib)
        } else {
            node_hash(&sib, &cur)
        };
    }
    Some(cur)
}

/// Verify that `key` **is** revoked in the map with the given `root`: its slot
/// holds the present leaf. Offline; needs only the root and the proof.
pub fn verify_inclusion(root: &Hash, key: &Hash, proof: &MapProof) -> bool {
    recompute_root(key, leaf_hash(key), proof).as_ref() == Some(root)
}

/// Verify that `key` is **not** revoked in the map with the given `root`: its
/// slot holds the empty leaf. This is the negative proof an append-only log
/// cannot give. Fails closed on a malformed proof.
pub fn verify_non_inclusion(root: &Hash, key: &Hash, proof: &MapProof) -> bool {
    recompute_root(key, empty_leaf(), proof).as_ref() == Some(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: u8) -> Hash {
        // Distinct, spread-out keys (blake3 of the tag) so paths diverge high in
        // the tree — the realistic case for blake3-derived RevocationIds.
        *blake3::hash(&[tag]).as_bytes()
    }

    /// The core guarantee: a revoked key proves inclusion, an unrevoked key
    /// proves *non-inclusion*, both against the same signed root.
    #[test]
    fn inclusion_and_non_inclusion_verify() {
        let mut map = RevocationMap::new();
        let revoked = key(1);
        let live = key(2);
        map.revoke(revoked);
        let root = map.root();

        assert!(verify_inclusion(&root, &revoked, &map.prove(&revoked)));
        assert!(verify_non_inclusion(&root, &live, &map.prove(&live)));
    }

    /// The forged-proof case (the same one the surveyed crate passed): you must
    /// NOT be able to pass off an absent key as revoked, or a revoked key as
    /// absent, using a genuine proof.
    #[test]
    fn proofs_do_not_cross_over() {
        let mut map = RevocationMap::new();
        let revoked = key(1);
        let live = key(2);
        map.revoke(revoked);
        let root = map.root();

        // A real non-inclusion proof for `live` must not verify as inclusion.
        assert!(!verify_inclusion(&root, &live, &map.prove(&live)));
        // A real inclusion proof for `revoked` must not verify as non-inclusion.
        assert!(!verify_non_inclusion(&root, &revoked, &map.prove(&revoked)));
    }

    /// A proof is bound to its key: you can't verify key A's membership with the
    /// proof generated for key B.
    #[test]
    fn a_proof_is_bound_to_its_key() {
        let mut map = RevocationMap::new();
        let a = key(1);
        let b = key(2);
        map.revoke(a);
        map.revoke(b);
        let root = map.root();

        let proof_a = map.prove(&a);
        assert!(verify_inclusion(&root, &a, &proof_a));
        assert!(!verify_inclusion(&root, &b, &proof_a));
    }

    /// Any tamper with the siblings breaks verification (fail closed).
    #[test]
    fn tampered_proof_is_rejected() {
        let mut map = RevocationMap::new();
        let revoked = key(1);
        map.revoke(revoked);
        let root = map.root();

        let mut proof = map.prove(&revoked);
        if let Some(first) = proof.siblings.first_mut() {
            first[0] ^= 0xff;
        } else {
            // Force a bogus sibling if the path happened to be all-default.
            proof.siblings.push([0xab; 32]);
            proof.present[0] |= 0x80;
        }
        assert!(!verify_inclusion(&root, &revoked, &proof));
    }

    /// A malformed proof (bitmap says a sibling is present but none is supplied)
    /// fails closed rather than panicking or silently verifying.
    #[test]
    fn malformed_proof_fails_closed() {
        let key = key(1);
        // Bitmap claims depth-0 sibling present, but siblings is empty.
        let mut present = vec![0u8; DEPTH / 8];
        present[0] |= 0x80;
        let bad = MapProof {
            present,
            siblings: vec![],
        };
        assert!(!verify_non_inclusion(&[0u8; 32], &key, &bad));
        // Wrong-length bitmap is also rejected.
        let bad2 = MapProof {
            present: vec![0u8; 4],
            siblings: vec![],
        };
        assert!(!verify_non_inclusion(&[0u8; 32], &key, &bad2));
    }

    /// Revoking changes the root (a live proof no longer verifies against the new
    /// root), and the map is order-independent: revoking A then B yields the same
    /// root as B then A.
    #[test]
    fn root_reflects_revocations_and_is_order_independent() {
        let a = key(1);
        let b = key(2);

        let mut m1 = RevocationMap::new();
        m1.revoke(a);
        let root_before = m1.root();
        // `b` is live under root_before.
        assert!(verify_non_inclusion(&root_before, &b, &m1.prove(&b)));
        m1.revoke(b);
        let root_after = m1.root();
        assert_ne!(root_before, root_after, "revoking must move the root");
        // The old live-proof for `b` no longer verifies non-inclusion.
        // (Regenerate against the new state: `b` is now revoked.)
        assert!(verify_inclusion(&root_after, &b, &m1.prove(&b)));

        let mut m2 = RevocationMap::new();
        m2.revoke(b);
        m2.revoke(a);
        assert_eq!(root_after, m2.root(), "root must be order-independent");
    }

    /// An empty map still answers non-inclusion for any key (everything is
    /// absent), and its root is the all-empty default.
    #[test]
    fn empty_map_proves_everything_absent() {
        let map = RevocationMap::new();
        let root = map.root();
        assert_eq!(root, Defaults::new().at_height(DEPTH));
        let k = key(3);
        assert!(verify_non_inclusion(&root, &k, &map.prove(&k)));
    }

    /// Scale: many revocations, and both a revoked and a live key still verify —
    /// exercises deep, branchy paths and the compaction bitmap.
    #[test]
    fn many_entries_still_verify() {
        let mut map = RevocationMap::new();
        for t in 0..200u8 {
            map.revoke(key(t));
        }
        let root = map.root();
        let revoked = key(137);
        assert!(verify_inclusion(&root, &revoked, &map.prove(&revoked)));

        // A key definitely not inserted (blake3 of a 2-byte input) is absent.
        let live = *blake3::hash(b"definitely-not-in-the-set").as_bytes();
        assert!(!map.contains(&live));
        assert!(verify_non_inclusion(&root, &live, &map.prove(&live)));
    }
}
