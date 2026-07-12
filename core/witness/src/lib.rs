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
//! Implemented here: append, root, inclusion proof + verification.
//! TODO(witness, @udaya): consistency proofs + gossip for non-equivocation
//! (forked-view detection) — the other half of §6 deliverable #1.

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
    /// Canonical bytes committed as the Merkle leaf. TODO(witness): RFC 8785
    /// JCS before this is a wire format; deterministic serde_json is enough for
    /// now.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializable")
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
    match leaves.len() {
        0 => empty_root(),
        1 => hash_leaf(&leaves[0]),
        n => {
            let k = split_point(n);
            hash_node(&subtree_root(&leaves[..k]), &subtree_root(&leaves[k..]))
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
}
