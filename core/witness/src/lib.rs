//! `indexone-witness` — the cross-organization transparency log.
//!
//! This is the headline seam (CLAUDE.md §3, §6). A signed delegation chain
//! proves what it *contains* is authentic; it says nothing about what was
//! silently left out. You cannot detect the absence of an action by reading a
//! log that doesn't contain it — that's a theoretical boundary, not a bug, and
//! it's exactly why every competing draft punts "completeness" to an external
//! log nobody has built cross-org.
//!
//! The witness is that log. Each action emits an [`ActionReceipt`] committing
//! to (a) the delegation chain it ran under, (b) a digest of the action, and
//! (c) the previous Merkle root. Receipts are appended to an append-only
//! Merkle tree. An action with **no inclusion proof against the current root**
//! is *provably missing* — omission becomes detectable.
//!
//! Hashing follows RFC 6962 (Certificate Transparency) discipline: leaves and
//! interior nodes are domain-separated so a leaf can never be reinterpreted as
//! an interior node. blake3 is the hash.
//!
//! Implemented here: append, root, inclusion proof + verification, and RFC 6962
//! §2.1.2 consistency proofs (a forked/rewritten log cannot prove consistency
//! against an honest earlier root → non-equivocation).
//! TODO(witness, @udaya): the gossip transport that distributes signed tree
//! heads so observers actually compare roots — the other half of §6 #1.

use serde::{Deserialize, Serialize};

/// A 32-byte blake3 digest.
pub type Digest = [u8; 32];

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

fn hash_leaf(data: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

fn hash_node(left: &Digest, right: &Digest) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// A receipt committing one agent action to the witness. The exact object
/// whose inclusion (or absence) the verifier checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionReceipt {
    /// Digest of the delegation chain the action ran under (`Chain::digest`).
    pub chain_digest: Digest,
    /// Digest of the action itself (request/params/outcome — caller-defined).
    pub action_digest: Digest,
    /// The Merkle root this receipt was appended on top of, chaining receipts
    /// so a rewrite of history is detectable.
    pub prev_root: Digest,
}

impl ActionReceipt {
    /// Canonical bytes committed as the Merkle leaf, in RFC 8785 (JCS) form so an
    /// independent encoder computes the same leaf hash.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_jcs::to_vec(self).expect("serializable")
    }
}

/// One sibling on an inclusion (audit) path: its digest and which side it sits
/// on relative to the running hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathStep {
    pub sibling: Digest,
    /// True if `sibling` is the *left* input to the parent node (so the running
    /// hash is the right input).
    pub sibling_is_left: bool,
}

/// A proof that a specific leaf is included in a tree of a given size, rooted
/// at a specific digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: usize,
    pub tree_size: usize,
    pub path: Vec<PathStep>,
}

/// An RFC 6962 §2.1.2 consistency proof that a size-`old_size` root is a prefix
/// of a size-`new_size` root — i.e. the log only *appended* between the two,
/// never rewrote or reordered history. This is the non-equivocation primitive:
/// a forked/rewritten log cannot produce a proof that regenerates the genuine
/// earlier root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Proof node hashes, in RFC 6962 order.
    pub nodes: Vec<Digest>,
}

/// Append-only Merkle transparency log over [`ActionReceipt`] leaves.
#[derive(Debug, Clone, Default)]
pub struct Witness {
    /// Canonical bytes of each appended receipt, in order.
    entries: Vec<Vec<u8>>,
}

/// Empty-tree root (RFC 6962: hash of the empty string, domain-separated as a
/// leaf so it can't collide with a node).
fn empty_root() -> Digest {
    hash_leaf(&[])
}

/// Largest power of two strictly less than `n` (for `n > 1`). RFC 6962 split.
fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Root of `leaves[..]` (each entry is raw leaf data, hashed here).
fn subtree_root(leaves: &[Vec<u8>]) -> Digest {
    let hashes: Vec<Digest> = leaves.iter().map(|d| hash_leaf(d)).collect();
    merkle_root_of_hashes(&hashes)
}

/// Root over already-hashed leaves — the shared core used by both
/// [`subtree_root`] and the RFC 6962 consistency-proof machinery below, so the
/// two never diverge on tree shape.
fn merkle_root_of_hashes(leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            hash_node(
                &merkle_root_of_hashes(&leaves[..k]),
                &merkle_root_of_hashes(&leaves[k..]),
            )
        }
    }
}

/// Audit path (leaf-up) for `index` within `leaves[..]`.
fn subtree_path(leaves: &[Vec<u8>], index: usize) -> Vec<PathStep> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split_point(n);
    if index < k {
        let mut path = subtree_path(&leaves[..k], index);
        path.push(PathStep {
            sibling: subtree_root(&leaves[k..]),
            sibling_is_left: false,
        });
        path
    } else {
        let mut path = subtree_path(&leaves[k..], index - k);
        path.push(PathStep {
            sibling: subtree_root(&leaves[..k]),
            sibling_is_left: true,
        });
        path
    }
}

impl Witness {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current Merkle root — the value receipts and attestations commit to.
    pub fn root(&self) -> Digest {
        subtree_root(&self.entries)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Append a receipt, returning its leaf index. Callers should build the
    /// receipt with `prev_root = witness.root()` *before* appending so receipts
    /// chain.
    pub fn append(&mut self, receipt: &ActionReceipt) -> usize {
        let index = self.entries.len();
        self.entries.push(receipt.canonical_bytes());
        index
    }

    /// Inclusion proof for the leaf at `index`, or `None` if out of range.
    pub fn inclusion_proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.entries.len() {
            return None;
        }
        Some(InclusionProof {
            leaf_index: index,
            tree_size: self.entries.len(),
            path: subtree_path(&self.entries, index),
        })
    }

    /// RFC 6962 §2.1.2 consistency proof that the size-`old_size` tree is a
    /// prefix of the current tree. `new_size` must equal the current length —
    /// you prove consistency *up to* the log's current head. Returns `None`
    /// (fail closed) unless `old_size <= new_size == len`.
    pub fn consistency_proof(&self, old_size: usize, new_size: usize) -> Option<ConsistencyProof> {
        if new_size != self.entries.len() || old_size > new_size {
            return None;
        }
        let mut nodes = Vec::new();
        if old_size != 0 && old_size != new_size {
            let hashes: Vec<Digest> = self.entries.iter().map(|e| hash_leaf(e)).collect();
            subproof(old_size, &hashes[..new_size], true, &mut nodes);
        }
        Some(ConsistencyProof { nodes })
    }
}

/// RFC 6962 `SUBPROOF(m, D[n], b)`, appending nodes to `out` in proof order.
fn subproof(m: usize, leaves: &[Digest], b: bool, out: &mut Vec<Digest>) {
    let n = leaves.len();
    if m == n {
        // MTH(D[0:m]) is a known root iff `b`; otherwise it must be supplied.
        if !b {
            out.push(merkle_root_of_hashes(leaves));
        }
        return;
    }
    let k = split_point(n);
    if m <= k {
        subproof(m, &leaves[..k], b, out);
        out.push(merkle_root_of_hashes(&leaves[k..]));
    } else {
        subproof(m - k, &leaves[k..], false, out);
        out.push(merkle_root_of_hashes(&leaves[..k]));
    }
}

/// Verify an RFC 6962 §2.1.2 consistency proof: that `old_root` (size
/// `old_size`) is a prefix of `new_root` (size `new_size`). Returns `true` only
/// if `proof` reconstructs *both* roots — a log that rewrote or forked any leaf
/// below `old_size` cannot regenerate the genuine `old_root`, so it fails.
/// Fails closed on every malformed / short / extra input.
pub fn verify_consistency(
    old_root: &Digest,
    new_root: &Digest,
    proof: &ConsistencyProof,
    old_size: usize,
    new_size: usize,
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == new_size {
        // Identical trees: empty proof, equal roots.
        return proof.nodes.is_empty() && old_root == new_root;
    }
    if old_size == 0 {
        // The empty tree is a prefix of every tree; no nodes needed.
        return proof.nodes.is_empty();
    }

    // 0 < old_size < new_size. Walk up from the split between the shared prefix
    // and the appended suffix, reconstructing old and new roots in lockstep.
    let mut node = old_size - 1;
    let mut last = new_size - 1;
    while node & 1 == 1 {
        node >>= 1;
        last >>= 1;
    }

    let mut proof = proof.nodes.as_slice();
    let (mut old_hash, mut new_hash) = if node > 0 {
        // old_size is not a power of two: the seed comes from the proof.
        let Some((seed, rest)) = proof.split_first() else {
            return false;
        };
        proof = rest;
        (*seed, *seed)
    } else {
        // old_size is a power of two: the old root itself seeds the walk.
        (*old_root, *old_root)
    };

    while node > 0 {
        if node & 1 == 1 {
            // Right child: sibling is on the left of both trees.
            let Some((sibling, rest)) = proof.split_first() else {
                return false;
            };
            proof = rest;
            old_hash = hash_node(sibling, &old_hash);
            new_hash = hash_node(sibling, &new_hash);
        } else if node < last {
            // Left child with a right sibling that exists only in the new tree.
            let Some((sibling, rest)) = proof.split_first() else {
                return false;
            };
            proof = rest;
            new_hash = hash_node(&new_hash, sibling);
        }
        node >>= 1;
        last >>= 1;
    }

    // Absorb the remaining right-spine nodes that extend the new tree.
    while last > 0 {
        let Some((sibling, rest)) = proof.split_first() else {
            return false;
        };
        proof = rest;
        new_hash = hash_node(&new_hash, sibling);
        last >>= 1;
    }

    proof.is_empty() && new_hash == *new_root && old_hash == *old_root
}

/// Verify that `receipt` is included in a tree whose root is `root`, using
/// `proof`. Pure and stateless — the verifier checks this without touching the
/// witness's storage. Returns `false` for any mismatch (fail closed).
pub fn verify_inclusion(receipt: &ActionReceipt, proof: &InclusionProof, root: &Digest) -> bool {
    let mut acc = hash_leaf(&receipt.canonical_bytes());
    for step in &proof.path {
        acc = if step.sibling_is_left {
            hash_node(&step.sibling, &acc)
        } else {
            hash_node(&acc, &step.sibling)
        };
    }
    acc == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(action: u8) -> ActionReceipt {
        ActionReceipt {
            chain_digest: [1u8; 32],
            action_digest: [action; 32],
            prev_root: [0u8; 32],
        }
    }

    #[test]
    fn inclusion_proof_verifies_for_every_leaf() {
        // Exercise a range of tree sizes, including non-powers-of-two where the
        // RFC 6962 split matters.
        for size in 1..=9usize {
            let mut w = Witness::new();
            let receipts: Vec<_> = (0..size).map(|i| receipt(i as u8)).collect();
            for r in &receipts {
                w.append(r);
            }
            let root = w.root();
            for (i, r) in receipts.iter().enumerate() {
                let proof = w.inclusion_proof(i).expect("in range");
                assert!(
                    verify_inclusion(r, &proof, &root),
                    "leaf {i} of {size} should verify"
                );
            }
        }
    }

    #[test]
    fn omitted_action_has_no_valid_inclusion_proof() {
        // The headline property: an action that was never appended cannot be
        // shown included against the honest root. This is what makes omission
        // *detectable* rather than a matter of trust.
        let mut w = Witness::new();
        w.append(&receipt(1));
        w.append(&receipt(2));
        let root = w.root();

        let never_recorded = receipt(99);
        // Even reusing a real proof structure, the omitted receipt won't fold
        // to the honest root.
        let borrowed = w.inclusion_proof(0).unwrap();
        assert!(!verify_inclusion(&never_recorded, &borrowed, &root));
    }

    #[test]
    fn wrong_root_is_rejected() {
        let mut w = Witness::new();
        w.append(&receipt(1));
        let proof = w.inclusion_proof(0).unwrap();
        let forged_root = [7u8; 32];
        assert!(!verify_inclusion(&receipt(1), &proof, &forged_root));
    }

    #[test]
    fn appending_changes_the_root() {
        let mut w = Witness::new();
        let before = w.root();
        w.append(&receipt(1));
        let after = w.root();
        assert_ne!(before, after);
    }

    // Property: RFC 6962 consistency — an appended-only log proves the earlier
    // root is a prefix of the current one, for every prefix pair.
    #[test]
    fn consistency_proofs_verify_for_all_prefix_pairs() {
        for n in 1..=10usize {
            // Roots at each size 0..=n, from genuine appends.
            let mut w = Witness::new();
            let mut roots = vec![w.root()];
            for i in 0..n {
                w.append(&receipt(i as u8));
                roots.push(w.root());
            }
            for m in 0..=n {
                let proof = w.consistency_proof(m, n).expect("in range");
                assert!(
                    verify_consistency(&roots[m], &roots[n], &proof, m, n),
                    "size {m} → {n} should be consistent"
                );
            }
        }
    }

    // Property: append-only / NO FORKED HISTORY. A log that rewrote an early
    // leaf cannot produce a proof that regenerates the honest old root — this is
    // exactly the equivocation-detection guarantee.
    #[test]
    fn rewritten_history_fails_consistency() {
        let mut honest = Witness::new();
        for i in 0..3 {
            honest.append(&receipt(i));
        }
        let old_root = honest.root(); // size 3
        honest.append(&receipt(9));
        let new_root = honest.root(); // size 4
        let proof = honest.consistency_proof(3, 4).unwrap();
        assert!(verify_consistency(&old_root, &new_root, &proof, 3, 4));

        // Now a forked log that rewrote leaf 0 then appended the same 4th leaf.
        let mut forked = Witness::new();
        forked.append(&receipt(200)); // tampered leaf 0
        for i in 1..3 {
            forked.append(&receipt(i));
        }
        forked.append(&receipt(9));
        let forked_new_root = forked.root();
        let forked_proof = forked.consistency_proof(3, 4).unwrap();
        // The forked log cannot prove consistency against the *honest* old root.
        assert!(!verify_consistency(
            &old_root,
            &forked_new_root,
            &forked_proof,
            3,
            4
        ));
    }

    #[test]
    fn consistency_edge_cases_fail_closed() {
        let mut w = Witness::new();
        for i in 0..4 {
            w.append(&receipt(i));
        }
        let root = w.root();
        // m == n: empty proof, equal roots ok; unequal roots rejected.
        let p = w.consistency_proof(4, 4).unwrap();
        assert!(verify_consistency(&root, &root, &p, 4, 4));
        assert!(!verify_consistency(&root, &[7u8; 32], &p, 4, 4));
        // m == 0: vacuous prefix; a non-empty proof is rejected.
        let p0 = w.consistency_proof(0, 4).unwrap();
        assert!(verify_consistency(&[0u8; 32], &root, &p0, 0, 4));
        assert!(!verify_consistency(
            &[0u8; 32],
            &root,
            &ConsistencyProof {
                nodes: vec![[1u8; 32]]
            },
            0,
            4
        ));
        // Out of range: new_size must equal current length.
        assert!(w.consistency_proof(2, 5).is_none());
    }
}
