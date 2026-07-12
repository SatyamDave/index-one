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
//! Implemented here: append, root, inclusion proof + verification, RFC 6962
//! §2.1.2 consistency proofs, and the gossip primitives — signed tree heads
//! ([`SignedTreeHead`]) plus [`reconcile_heads`], which turns two irreconcilable
//! heads from the same log into cryptographic proof it equivocated.
//! TODO(witness, @udaya): the peer-to-peer distribution that actually fans
//! signed heads out to observers (a networking concern) — the detection crypto
//! is here; the transport that gossips it is not.

use indexone_crypto::{verify_signature, PublicKey, Signature, Signer};
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
    /// Per-invocation nonce making this receipt unique even when the same chain
    /// performs the same-shaped action twice. Without it, two byte-identical
    /// actions (e.g. two identical $40 charges) would share a leaf, and an
    /// attestation for one would be replayable for the other (audit Finding 6).
    pub nonce: Digest,
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

/// Domain separation for the purpose-bound action digest (kept distinct from the
/// leaf/node tags above so an action digest can never be reinterpreted as a tree
/// hash).
const ACTION_DIGEST_DOMAIN: &[u8] = b"indexone-witness/action-digest/v1";

/// Bind an action digest to the delegated **purpose** and the action's params:
/// `blake3(DOMAIN ‖ len(purpose) ‖ purpose ‖ params_digest)`.
///
/// Computing a receipt's `action_digest` this way makes it no longer an opaque,
/// caller-chosen value: a verifier can recompute the digest from the purpose the
/// final hop was actually delegated for and the declared params, so an action
/// witnessed under a *different* purpose (or with different params) yields a
/// different digest and is caught ([`crate`] users: see `indexone-verifier`'s
/// `verify_action_purpose_binding`). Closes VERIFIER_AUDIT finding #2.
///
/// Honest scope (CLAUDE.md §4): this binds the digest to the *declared* purpose
/// and params — not to ground truth about what physically happened. The witness
/// anchors what was reported.
pub fn bind_action(purpose: &str, params_digest: &Digest) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ACTION_DIGEST_DOMAIN);
    hasher.update(&(purpose.len() as u64).to_be_bytes());
    hasher.update(purpose.as_bytes());
    hasher.update(params_digest);
    *hasher.finalize().as_bytes()
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
    /// Leaf hash of each appended entry, in order. Append-only ⇒ each is
    /// immutable once set. The raw receipt bytes are not retained — the leaf
    /// hash is all the tree needs; callers that need the receipts keep them
    /// (e.g. the witness service's durable log does).
    leaf_hashes: Vec<Digest>,
    /// Memoized roots of *perfect, aligned* subtrees, keyed by `(start, len)`.
    /// In an append-only log a subtree over a fixed leaf range never changes, so
    /// this is correct with **no invalidation** and turns root/proof generation
    /// from O(n) into O(log n). Interior-mutable so `&self` read paths can fill
    /// it; the `RefCell` keeps `Witness` !Sync, so sharing needs the usual
    /// `Mutex` (which the service already uses).
    subtree_cache: std::cell::RefCell<std::collections::HashMap<(usize, usize), Digest>>,
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

impl Witness {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current Merkle root — the value receipts and attestations commit to.
    pub fn root(&self) -> Digest {
        self.subtree(0, self.leaf_hashes.len())
    }

    pub fn len(&self) -> usize {
        self.leaf_hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_hashes.is_empty()
    }

    /// Append a receipt, returning its leaf index. Callers should build the
    /// receipt with `prev_root = witness.root()` *before* appending so receipts
    /// chain.
    pub fn append(&mut self, receipt: &ActionReceipt) -> usize {
        let index = self.leaf_hashes.len();
        self.leaf_hashes.push(hash_leaf(&receipt.canonical_bytes()));
        index
    }

    /// Inclusion proof for the leaf at `index`, or `None` if out of range.
    pub fn inclusion_proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaf_hashes.len() {
            return None;
        }
        Some(InclusionProof {
            leaf_index: index,
            tree_size: self.leaf_hashes.len(),
            path: self.subtree_path(0, self.leaf_hashes.len(), index),
        })
    }

    /// RFC 6962 §2.1.2 consistency proof that the size-`old_size` tree is a
    /// prefix of the current tree. `new_size` must equal the current length —
    /// you prove consistency *up to* the log's current head. Returns `None`
    /// (fail closed) unless `old_size <= new_size == len`.
    pub fn consistency_proof(&self, old_size: usize, new_size: usize) -> Option<ConsistencyProof> {
        if new_size != self.leaf_hashes.len() || old_size > new_size {
            return None;
        }
        let mut nodes = Vec::new();
        if old_size != 0 && old_size != new_size {
            self.subproof(old_size, 0, new_size, true, &mut nodes);
        }
        Some(ConsistencyProof { nodes })
    }

    // ── memoized tree core ──────────────────────────────────────────────────
    //
    // These compute exactly what a naive RFC 6962 recomputation over
    // `leaf_hashes[start..start+len]` would (proven byte-for-byte in the tests'
    // differential oracle), but memoize *perfect, aligned* subtrees. Such a
    // subtree over a fixed leaf range is immutable in an append-only log, so the
    // cache is never invalidated; only the O(log n) right "spine" is recomputed.

    /// Root over the leaf-hash range `[start, start + len)` (RFC 6962 MTH).
    fn subtree(&self, start: usize, len: usize) -> Digest {
        match len {
            0 => empty_root(),
            1 => self.leaf_hashes[start],
            _ => {
                let perfect = len.is_power_of_two() && start.is_multiple_of(len);
                if perfect {
                    if let Some(h) = self.subtree_cache.borrow().get(&(start, len)) {
                        return *h;
                    }
                }
                let k = split_point(len);
                let h = hash_node(&self.subtree(start, k), &self.subtree(start + k, len - k));
                if perfect {
                    self.subtree_cache.borrow_mut().insert((start, len), h);
                }
                h
            }
        }
    }

    /// Audit path (leaf-up) for `index` within the range `[start, start + len)`.
    fn subtree_path(&self, start: usize, len: usize, index: usize) -> Vec<PathStep> {
        if len <= 1 {
            return Vec::new();
        }
        let k = split_point(len);
        if index < k {
            let mut path = self.subtree_path(start, k, index);
            path.push(PathStep {
                sibling: self.subtree(start + k, len - k),
                sibling_is_left: false,
            });
            path
        } else {
            let mut path = self.subtree_path(start + k, len - k, index - k);
            path.push(PathStep {
                sibling: self.subtree(start, k),
                sibling_is_left: true,
            });
            path
        }
    }

    /// RFC 6962 `SUBPROOF(m, D[start..start+len], b)`, over the leaf-hash range.
    fn subproof(&self, m: usize, start: usize, len: usize, b: bool, out: &mut Vec<Digest>) {
        if m == len {
            // MTH(D[0:m]) is a known root iff `b`; otherwise it must be supplied.
            if !b {
                out.push(self.subtree(start, len));
            }
            return;
        }
        let k = split_point(len);
        if m <= k {
            self.subproof(m, start, k, b, out);
            out.push(self.subtree(start + k, len - k));
        } else {
            self.subproof(m - k, start + k, len - k, false, out);
            out.push(self.subtree(start, k));
        }
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

/// Largest audit-path length any honest proof can have: a tree of `usize::MAX`
/// leaves has depth `⌈log2⌉ ≤ 64`. Anything longer is attacker padding — reject
/// it before folding (audit Finding 4: unbounded proof length → CPU/mem DoS).
pub const MAX_PROOF_PATH: usize = 64;

/// Verify that `receipt` is included in a tree whose root is `root`, using
/// `proof`. Pure and stateless — the verifier checks this without touching the
/// witness's storage. Returns `false` for any mismatch (fail closed), including
/// a malformed or oversized proof.
pub fn verify_inclusion(receipt: &ActionReceipt, proof: &InclusionProof, root: &Digest) -> bool {
    if proof.leaf_index >= proof.tree_size || proof.path.len() > MAX_PROOF_PATH {
        return false;
    }
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

// ── Gossip / non-equivocation transport ─────────────────────────────────────
//
// Consistency proofs prove a log didn't rewrite its own history. But a
// malicious log can still *equivocate* — show one history to observer A and a
// different one to observer B — and neither can tell alone. The fix (CT gossip
// discipline): the log signs its head, observers exchange those signed heads,
// and any two heads from the same log must be mutually consistent. Two heads
// that aren't (same size, different roots; or no valid consistency proof
// between sizes) are cryptographic proof the log forked.

/// A tree head (size + root) signed by the log operator. Observers gossip these;
/// two that can't be reconciled are proof of equivocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub tree_size: usize,
    pub root: Digest,
    pub signature: Signature,
}

/// Canonical bytes the log signs for a tree head (RFC 8785 JCS).
fn sth_signing_bytes(tree_size: usize, root: &Digest) -> Vec<u8> {
    serde_jcs::to_vec(&(tree_size, root)).expect("serializable")
}

impl Witness {
    /// Sign the current tree head with the log operator's key, for gossip.
    pub fn signed_head(&self, signer: &dyn Signer) -> SignedTreeHead {
        let tree_size = self.leaf_hashes.len();
        let root = self.root();
        let signature = signer
            .sign(&sth_signing_bytes(tree_size, &root))
            .expect("sign tree head");
        SignedTreeHead {
            tree_size,
            root,
            signature,
        }
    }
}

/// Verify a signed tree head against the log operator's public key.
pub fn verify_signed_head(sth: &SignedTreeHead, log_key: &PublicKey) -> bool {
    verify_signature(
        &sth_signing_bytes(sth.tree_size, &sth.root),
        &sth.signature,
        log_key,
    )
    .unwrap_or(false)
}

/// Why two signed tree heads could not be reconciled.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EquivocationError {
    #[error("signed tree head signature invalid")]
    InvalidSignedHead,
    #[error("equivocation: tree size {size} was shown two different roots")]
    ForkedRoot { size: usize },
    #[error("equivocation: the log is not consistent between sizes {old} and {new}")]
    Inconsistent { old: usize, new: usize },
}

/// Reconcile two signed tree heads from the *same* log (both must verify under
/// `log_key`). Returns `Ok(())` if they are mutually consistent, and an
/// [`EquivocationError`] — proof the log forked — if not. Heads of equal size
/// need no proof (their roots must simply match); heads of different sizes need
/// a [`ConsistencyProof`] that the smaller is a prefix of the larger.
pub fn reconcile_heads(
    a: &SignedTreeHead,
    b: &SignedTreeHead,
    log_key: &PublicKey,
    proof: Option<&ConsistencyProof>,
) -> Result<(), EquivocationError> {
    if !verify_signed_head(a, log_key) || !verify_signed_head(b, log_key) {
        return Err(EquivocationError::InvalidSignedHead);
    }
    if a.tree_size == b.tree_size {
        return if a.root == b.root {
            Ok(())
        } else {
            Err(EquivocationError::ForkedRoot { size: a.tree_size })
        };
    }
    let (small, large) = if a.tree_size < b.tree_size {
        (a, b)
    } else {
        (b, a)
    };
    let inconsistent = || EquivocationError::Inconsistent {
        old: small.tree_size,
        new: large.tree_size,
    };
    let proof = proof.ok_or_else(inconsistent)?;
    if verify_consistency(
        &small.root,
        &large.root,
        proof,
        small.tree_size,
        large.tree_size,
    ) {
        Ok(())
    } else {
        Err(inconsistent())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(action: u8) -> ActionReceipt {
        ActionReceipt {
            chain_digest: [1u8; 32],
            action_digest: [action; 32],
            nonce: [action; 32],
            prev_root: [0u8; 32],
        }
    }

    /// A distinct receipt for each `i` (so large trees have unique leaves).
    fn receipt_n(i: usize) -> ActionReceipt {
        let mut d = [0u8; 32];
        d[..8].copy_from_slice(&(i as u64).to_le_bytes());
        ActionReceipt {
            chain_digest: [1u8; 32],
            action_digest: d,
            nonce: d,
            prev_root: [0u8; 32],
        }
    }

    // ── Naive RFC 6962 oracle: a from-scratch, cache-free recomputation. The
    //    memoized `Witness` methods MUST produce byte-identical output; the
    //    differential tests below assert that for every small size/index/pair,
    //    so the optimization can never silently change a root or a proof.

    fn naive_root(hashes: &[Digest]) -> Digest {
        match hashes.len() {
            0 => empty_root(),
            1 => hashes[0],
            n => {
                let k = split_point(n);
                hash_node(&naive_root(&hashes[..k]), &naive_root(&hashes[k..]))
            }
        }
    }

    fn naive_path(hashes: &[Digest], index: usize) -> Vec<PathStep> {
        let n = hashes.len();
        if n <= 1 {
            return Vec::new();
        }
        let k = split_point(n);
        if index < k {
            let mut p = naive_path(&hashes[..k], index);
            p.push(PathStep {
                sibling: naive_root(&hashes[k..]),
                sibling_is_left: false,
            });
            p
        } else {
            let mut p = naive_path(&hashes[k..], index - k);
            p.push(PathStep {
                sibling: naive_root(&hashes[..k]),
                sibling_is_left: true,
            });
            p
        }
    }

    fn naive_subproof(m: usize, hashes: &[Digest], b: bool, out: &mut Vec<Digest>) {
        let n = hashes.len();
        if m == n {
            if !b {
                out.push(naive_root(hashes));
            }
            return;
        }
        let k = split_point(n);
        if m <= k {
            naive_subproof(m, &hashes[..k], b, out);
            out.push(naive_root(&hashes[k..]));
        } else {
            naive_subproof(m - k, &hashes[k..], false, out);
            out.push(naive_root(&hashes[..k]));
        }
    }

    #[test]
    fn cached_root_matches_naive_oracle_for_all_sizes() {
        let mut w = Witness::new();
        let mut hashes: Vec<Digest> = Vec::new();
        for n in 0..=300usize {
            assert_eq!(w.root(), naive_root(&hashes), "root mismatch at size {n}");
            let r = receipt_n(n);
            hashes.push(hash_leaf(&r.canonical_bytes()));
            w.append(&r);
        }
    }

    #[test]
    fn cached_inclusion_paths_match_naive_oracle() {
        let mut w = Witness::new();
        let mut hashes: Vec<Digest> = Vec::new();
        for n in 1..=200usize {
            let r = receipt_n(n - 1);
            hashes.push(hash_leaf(&r.canonical_bytes()));
            w.append(&r);
            for i in 0..n {
                let got = w.inclusion_proof(i).expect("in range").path;
                let want = naive_path(&hashes, i);
                assert_eq!(got, want, "inclusion path mismatch: size {n}, index {i}");
            }
        }
    }

    #[test]
    fn cached_consistency_proofs_match_naive_oracle() {
        let mut w = Witness::new();
        let mut hashes: Vec<Digest> = Vec::new();
        for new in 0..=150usize {
            // w and `hashes` both hold `new` leaves at this point.
            for old in 0..=new {
                let got = w.consistency_proof(old, new).expect("valid range").nodes;
                let mut want = Vec::new();
                if old != 0 && old != new {
                    naive_subproof(old, &hashes[..new], true, &mut want);
                }
                assert_eq!(
                    got, want,
                    "consistency nodes mismatch: old {old}, new {new}"
                );
            }
            let r = receipt_n(new);
            hashes.push(hash_leaf(&r.canonical_bytes()));
            w.append(&r);
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

    // Audit Finding 4: an oversized (attacker-padded) or out-of-range proof is
    // rejected *before* folding, so it can't burn CPU/memory.
    #[test]
    fn oversized_or_malformed_proof_is_rejected() {
        let mut w = Witness::new();
        w.append(&receipt(1));
        let root = w.root();
        let good = w.inclusion_proof(0).unwrap();
        assert!(verify_inclusion(&receipt(1), &good, &root));

        let mut huge = good.clone();
        huge.path = vec![
            PathStep {
                sibling: [0u8; 32],
                sibling_is_left: false
            };
            MAX_PROOF_PATH + 1
        ];
        assert!(!verify_inclusion(&receipt(1), &huge, &root));

        let mut oob = good;
        oob.leaf_index = 99;
        oob.tree_size = 1;
        assert!(!verify_inclusion(&receipt(1), &oob, &root));
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

    // Gossip: an honest log's two signed heads (different sizes) reconcile with
    // a consistency proof — no equivocation.
    #[test]
    fn honest_signed_heads_reconcile() {
        use indexone_crypto::Ed25519Signer;
        let log = Ed25519Signer::from_seed([77u8; 32]);
        let mut w = Witness::new();
        w.append(&receipt(1));
        w.append(&receipt(2));
        let head_2 = w.signed_head(&log);
        w.append(&receipt(3));
        w.append(&receipt(4));
        let head_4 = w.signed_head(&log);
        assert!(verify_signed_head(&head_2, &log.public_key()));
        let proof = w.consistency_proof(2, 4).unwrap();
        assert!(reconcile_heads(&head_2, &head_4, &log.public_key(), Some(&proof)).is_ok());
    }

    // Gossip: two signed heads at the SAME size with DIFFERENT roots are proof
    // the log equivocated (showed different histories to different observers).
    #[test]
    fn forked_root_at_same_size_is_equivocation() {
        use indexone_crypto::Ed25519Signer;
        let log = Ed25519Signer::from_seed([77u8; 32]);
        let mut a = Witness::new();
        a.append(&receipt(1));
        a.append(&receipt(2));
        let head_a = a.signed_head(&log);
        // A forked view of size 2 that swapped a leaf.
        let mut b = Witness::new();
        b.append(&receipt(1));
        b.append(&receipt(99));
        let head_b = b.signed_head(&log);
        assert_eq!(
            reconcile_heads(&head_a, &head_b, &log.public_key(), None).unwrap_err(),
            EquivocationError::ForkedRoot { size: 2 }
        );
    }

    // A signed head that doesn't verify under the log's key is rejected before
    // any consistency reasoning.
    #[test]
    fn signed_head_from_wrong_key_is_rejected() {
        use indexone_crypto::Ed25519Signer;
        let log = Ed25519Signer::from_seed([77u8; 32]);
        let impostor = Ed25519Signer::from_seed([13u8; 32]);
        let mut w = Witness::new();
        w.append(&receipt(1));
        let head = w.signed_head(&log);
        assert!(!verify_signed_head(&head, &impostor.public_key()));
        let head2 = {
            w.append(&receipt(2));
            w.signed_head(&log)
        };
        assert_eq!(
            reconcile_heads(&head, &head2, &impostor.public_key(), None).unwrap_err(),
            EquivocationError::InvalidSignedHead
        );
    }
}
