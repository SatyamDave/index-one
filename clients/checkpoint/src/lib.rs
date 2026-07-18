//! `indexone-checkpoint` — the IndexOne STH as a C2SP signed-note checkpoint.
//!
//! A witness that only signs its *own* tree head can still equivocate (present
//! different roots to different observers). The fix the modern transparency
//! ecosystem uses is **witness cosigning**: the log emits its head as a standard
//! [C2SP `tlog-checkpoint`], and independent witnesses each append a signature
//! over the *same* body. A relying party that requires an N-of-M quorum of known
//! witnesses then can't be shown a forked root — a contradictory root would need
//! a second, detectable cosigned checkpoint. This crate is that interop layer.
//!
//! [C2SP `tlog-checkpoint`]: a signed note whose body is three newline-terminated
//! lines — **origin** (a schema-less log identity, e.g. `indexone.dev/witness`),
//! the decimal **tree size**, and the base64 **root hash** — optionally followed
//! by extension lines. A [C2SP signed note] carries one or more signature lines
//! `— <name> base64(keyhash‖sig)`, where `keyhash = SHA-256(name ‖ 0x0A ‖ 0x01 ‖
//! pubkey)[:4]` and `0x01` is the Ed25519 note-algorithm byte. "Clients MUST
//! ignore unknown signatures", which is exactly what lets witnesses cosign and
//! keys rotate.
//!
//! Scope/honesty: the SHA-256 key-id and standard base64 here are the *note
//! format's* primitives — deliberately distinct from IndexOne's blake3 tree
//! hashing. Byte-level interop with the Go `sumdb/note` reference should be
//! validated against a vector before relying on cross-implementation cosigning;
//! this implements the documented format and round-trips + cosigns internally.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest as _, Sha256};

use indexone_crypto::{verify_signature, Algorithm, Ed25519Signer, PublicKey, Signature, Signer};
use indexone_witness::{verify_consistency, ConsistencyProof, Digest, SignedTreeHead};

/// The note signature-algorithm byte for Ed25519 (C2SP signed-note).
const ED25519_NOTE_ALG: u8 = 0x01;

/// A transparency-log checkpoint: the committed (origin, size, root) triple that
/// a note is signed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Schema-less log identity, e.g. `indexone.dev/witness`.
    pub origin: String,
    /// Tree size (number of leaves).
    pub size: usize,
    /// RFC 6962 root hash.
    pub root: Digest,
}

impl Checkpoint {
    /// Derive a checkpoint from a signed tree head under `origin`.
    pub fn from_sth(origin: impl Into<String>, sth: &SignedTreeHead) -> Checkpoint {
        Checkpoint {
            origin: origin.into(),
            size: sth.tree_size,
            root: sth.root,
        }
    }

    /// The exact signed text (C2SP `tlog-checkpoint` body): origin, decimal size,
    /// base64(root), each newline-terminated.
    fn body(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            STANDARD.encode(self.root)
        )
    }
}

/// `keyhash = SHA-256(name ‖ '\n' ‖ 0x01 ‖ pubkey)[:4]`.
fn key_hash(name: &str, pubkey: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\n");
    h.update([ED25519_NOTE_ALG]);
    h.update(pubkey);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

/// One signature line `— <name> base64(keyhash‖sig)\n` over `body`.
fn signature_line(body: &str, signer: &Ed25519Signer, key_name: &str) -> String {
    let pubkey = signer.public_key();
    let sig = signer.sign(body.as_bytes()).expect("ed25519 sign");
    let mut blob = Vec::with_capacity(4 + sig.bytes.len());
    blob.extend_from_slice(&key_hash(key_name, &pubkey.bytes));
    blob.extend_from_slice(&sig.bytes);
    format!("\u{2014} {} {}\n", key_name, STANDARD.encode(blob))
}

/// Sign a checkpoint as a C2SP signed note (one signature). The returned text is
/// the body followed by the operator's signature line.
pub fn sign_checkpoint(signer: &Ed25519Signer, key_name: &str, checkpoint: &Checkpoint) -> String {
    let body = checkpoint.body();
    let line = signature_line(&body, signer, key_name);
    format!("{body}{line}")
}

/// Append a **cosignature** over the same body — the witness-cosigning operation.
/// Returns the extended note, or `None` if `note` is malformed.
pub fn cosign(note: &str, signer: &Ed25519Signer, key_name: &str) -> Option<String> {
    let body = note_body(note)?;
    let line = signature_line(&body, signer, key_name);
    Some(format!("{note}{line}"))
}

/// The body text of a signed note: everything up to the first signature line,
/// reconstructed with its trailing newlines.
fn note_body(note: &str) -> Option<String> {
    let sig_marker = "\u{2014} "; // "— "
    let mut lines: Vec<&str> = note.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop(); // trailing newline
    }
    let sig_start = lines.iter().position(|l| l.starts_with(sig_marker))?;
    if sig_start < 3 {
        return None; // a checkpoint body is at least origin/size/root
    }
    Some(format!("{}\n", lines[..sig_start].join("\n")))
}

/// Verify a checkpoint note against `pubkey` under `key_name`, returning the
/// parsed [`Checkpoint`] iff a valid signature line for that key is present.
/// Unknown/extra signatures are ignored (C2SP: "clients MUST ignore unknown
/// signatures"), which is what makes cosigning and key rotation work.
pub fn verify_checkpoint(note: &str, key_name: &str, pubkey: &PublicKey) -> Option<Checkpoint> {
    let expected = key_hash(key_name, &pubkey.bytes);
    let sig_marker = "\u{2014} ";
    let mut lines: Vec<&str> = note.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let sig_start = lines.iter().position(|l| l.starts_with(sig_marker))?;
    if sig_start < 3 {
        return None;
    }
    let body = format!("{}\n", lines[..sig_start].join("\n"));

    // Find a valid signature line whose key-id and Ed25519 signature match.
    let mut verified = false;
    for line in &lines[sig_start..] {
        let Some(rest) = line.strip_prefix(sig_marker) else {
            continue;
        };
        let Some((name, b64)) = rest.split_once(' ') else {
            continue;
        };
        if name != key_name {
            continue;
        }
        let Ok(blob) = STANDARD.decode(b64) else {
            continue;
        };
        if blob.len() != 4 + 64 || blob[..4] != expected {
            continue;
        }
        let sig = Signature {
            algorithm: Algorithm::Ed25519,
            bytes: blob[4..].to_vec(),
        };
        if verify_signature(body.as_bytes(), &sig, pubkey).unwrap_or(false) {
            verified = true;
            break;
        }
    }
    if !verified {
        return None;
    }

    // Parse the committed fields from the (now signature-verified) body.
    let body_lines: Vec<&str> = body.lines().collect();
    let origin = body_lines.first()?.to_string();
    let size: usize = body_lines.get(1)?.parse().ok()?;
    let root: Digest = STANDARD.decode(body_lines.get(2)?).ok()?.try_into().ok()?;
    Some(Checkpoint { origin, size, root })
}

// ── Witness cosigning (C2SP tlog-witness) + N-of-M quorum ───────────────────

/// Why a witness refused to cosign a checkpoint.
#[derive(Debug, PartialEq, Eq)]
pub enum CosignError {
    /// The checkpoint is not validly signed by the log key this witness watches.
    BadLogSignature,
    /// The presented `old` size is not the size this witness last cosigned — the
    /// client must re-fetch and retry (C2SP tlog-witness returns 409 + this size).
    SizeMismatch { our_size: usize },
    /// The new checkpoint is smaller than what this witness already cosigned — a
    /// rollback, refused.
    Rollback { our_size: usize, new_size: usize },
    /// The consistency proof does not show the new tree is an append-only
    /// extension of the last one this witness cosigned.
    InconsistentProof,
}

/// A witness that cosigns one log's checkpoints (the C2SP `tlog-witness`
/// `add-checkpoint` role). It remembers the last (size, root) it cosigned so it
/// can enforce append-only extension and refuse rollbacks — the property that,
/// across an N-of-M quorum, makes a forked/equivocating log detectable.
pub struct CosigningWitness {
    signer: Ed25519Signer,
    key_name: String,
    log_origin: String,
    log_key: PublicKey,
    /// The last checkpoint this witness cosigned for the watched log.
    seen: Option<(usize, Digest)>,
}

impl CosigningWitness {
    /// A fresh witness watching the log identified by `log_origin` + `log_key`,
    /// cosigning under its own `key_name`.
    pub fn new(
        signer: Ed25519Signer,
        key_name: impl Into<String>,
        log_origin: impl Into<String>,
        log_key: PublicKey,
    ) -> CosigningWitness {
        CosigningWitness {
            signer,
            key_name: key_name.into(),
            log_origin: log_origin.into(),
            log_key,
            seen: None,
        }
    }

    /// The size this witness last cosigned (0 if none yet).
    pub fn last_size(&self) -> usize {
        self.seen.map(|(s, _)| s).unwrap_or(0)
    }

    /// `add-checkpoint`: verify the log-signed `note` is a consistent append-only
    /// extension of what this witness last cosigned, then return **its cosignature
    /// line** over the same body (to be merged into the published note). Updates
    /// the witness's last-seen state on success.
    pub fn add_checkpoint(
        &mut self,
        note: &str,
        old_size: usize,
        consistency: &ConsistencyProof,
    ) -> Result<String, CosignError> {
        let cp = verify_checkpoint(note, &self.log_origin, &self.log_key)
            .ok_or(CosignError::BadLogSignature)?;

        let (our_size, our_root) = self.seen.unwrap_or((0, [0u8; 32]));
        if old_size != our_size {
            return Err(CosignError::SizeMismatch { our_size });
        }
        if cp.size < our_size {
            return Err(CosignError::Rollback {
                our_size,
                new_size: cp.size,
            });
        }

        // Append-only extension from our_size → cp.size. Extending from an empty
        // (size-0) view is consistent for any tree with an empty proof (RFC 6962:
        // the empty tree is a prefix of every tree).
        let consistent = if our_size == 0 {
            consistency.nodes.is_empty()
        } else {
            verify_consistency(&our_root, &cp.root, consistency, our_size, cp.size)
        };
        if !consistent {
            return Err(CosignError::InconsistentProof);
        }

        self.seen = Some((cp.size, cp.root));
        // Cosign the exact body the log signed.
        let body = note_body(note).ok_or(CosignError::BadLogSignature)?;
        Ok(signature_line(&body, &self.signer, &self.key_name))
    }
}

/// Verify a checkpoint note carries at least `threshold` valid cosignatures from
/// the named `witnesses`, all committing the **same** checkpoint. This is the
/// N-of-M non-equivocation check — the upgrade of the verifier's step 6 from a
/// single trusted root to a witness quorum. Returns the agreed [`Checkpoint`], or
/// `None` if the quorum isn't met or two witnesses disagree on the root.
pub fn verify_quorum(
    note: &str,
    witnesses: &[(&str, &PublicKey)],
    threshold: usize,
) -> Option<Checkpoint> {
    let mut agreed: Option<Checkpoint> = None;
    let mut count = 0usize;
    for (name, key) in witnesses {
        if let Some(cp) = verify_checkpoint(note, name, key) {
            match &agreed {
                None => agreed = Some(cp),
                Some(existing) if *existing != cp => return None, // forked view
                Some(_) => {}
            }
            count += 1;
        }
    }
    if count >= threshold {
        agreed
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint() -> Checkpoint {
        Checkpoint {
            origin: "indexone.dev/witness".to_string(),
            size: 42,
            root: [7u8; 32],
        }
    }

    /// Round-trip: a signed checkpoint verifies and reconstructs the exact triple.
    #[test]
    fn sign_then_verify_roundtrips() {
        let op = Ed25519Signer::from_seed([1u8; 32]);
        let cp = checkpoint();
        let note = sign_checkpoint(&op, "indexone", &cp);
        let got = verify_checkpoint(&note, "indexone", &op.public_key()).expect("verifies");
        assert_eq!(got, cp);
    }

    /// The note body is exactly the C2SP three-line form, and the signature line
    /// begins with the em-dash marker.
    #[test]
    fn note_has_c2sp_shape() {
        let op = Ed25519Signer::from_seed([2u8; 32]);
        let note = sign_checkpoint(&op, "indexone", &checkpoint());
        let mut lines = note.lines();
        assert_eq!(lines.next().unwrap(), "indexone.dev/witness");
        assert_eq!(lines.next().unwrap(), "42");
        assert_eq!(lines.next().unwrap(), STANDARD.encode([7u8; 32]));
        assert!(lines.next().unwrap().starts_with("\u{2014} indexone "));
    }

    /// Tamper with the signed body (flip the size) → verification fails closed.
    #[test]
    fn tampered_body_is_rejected() {
        let op = Ed25519Signer::from_seed([3u8; 32]);
        let note = sign_checkpoint(&op, "indexone", &checkpoint());
        let tampered = note.replacen("42", "43", 1);
        assert!(verify_checkpoint(&tampered, "indexone", &op.public_key()).is_none());
    }

    /// A different operator key does not verify the note.
    #[test]
    fn wrong_key_is_rejected() {
        let op = Ed25519Signer::from_seed([4u8; 32]);
        let impostor = Ed25519Signer::from_seed([5u8; 32]);
        let note = sign_checkpoint(&op, "indexone", &checkpoint());
        assert!(verify_checkpoint(&note, "indexone", &impostor.public_key()).is_none());
    }

    /// The cosigning foundation: two independent witnesses sign the same body;
    /// the note verifies under EITHER key, and unknown signatures are ignored.
    #[test]
    fn cosigned_note_verifies_under_each_witness() {
        let log = Ed25519Signer::from_seed([6u8; 32]);
        let witness_a = Ed25519Signer::from_seed([7u8; 32]);
        let witness_b = Ed25519Signer::from_seed([8u8; 32]);
        let cp = checkpoint();

        let note = sign_checkpoint(&log, "indexone", &cp);
        let note = cosign(&note, &witness_a, "witness-a").expect("cosign a");
        let note = cosign(&note, &witness_b, "witness-b").expect("cosign b");

        // Each party verifies against its own key; the checkpoint is the same.
        assert_eq!(
            verify_checkpoint(&note, "indexone", &log.public_key()),
            Some(cp.clone())
        );
        assert_eq!(
            verify_checkpoint(&note, "witness-a", &witness_a.public_key()),
            Some(cp.clone())
        );
        assert_eq!(
            verify_checkpoint(&note, "witness-b", &witness_b.public_key()),
            Some(cp)
        );
        // An unknown key simply isn't found (ignored, not an error for others).
        let stranger = Ed25519Signer::from_seed([9u8; 32]);
        assert!(verify_checkpoint(&note, "stranger", &stranger.public_key()).is_none());
    }

    /// Interops with a real STH: derive the checkpoint from a signed tree head.
    #[test]
    fn from_signed_tree_head() {
        use indexone_witness::Witness;
        let op = Ed25519Signer::from_seed([10u8; 32]);
        let w = Witness::new();
        let sth = w.signed_head(&op);
        let cp = Checkpoint::from_sth("indexone.dev/witness", &sth);
        let note = sign_checkpoint(&op, "indexone", &cp);
        let got = verify_checkpoint(&note, "indexone", &op.public_key()).unwrap();
        assert_eq!(got.size, sth.tree_size);
        assert_eq!(got.root, sth.root);
    }

    // ── cosigning flow (tlog-witness) + quorum ──────────────────────────────

    use indexone_witness::{ActionReceipt, Witness};

    const ORIGIN: &str = "indexone.dev/witness";

    fn receipt(tag: u8, prev: Digest) -> ActionReceipt {
        ActionReceipt {
            chain_digest: [tag; 32],
            action_digest: [tag; 32],
            nonce: [tag; 32],
            prev_root: prev,
        }
    }

    /// The log's current head as a checkpoint note (key name = origin).
    fn log_note(log: &Ed25519Signer, w: &Witness) -> String {
        let cp = Checkpoint::from_sth(ORIGIN, &w.signed_head(log));
        sign_checkpoint(log, ORIGIN, &cp)
    }

    fn empty_proof() -> ConsistencyProof {
        ConsistencyProof { nodes: vec![] }
    }

    /// A witness cosigns successive consistent extensions, and the cosigned note
    /// meets a 2-of-2 quorum.
    #[test]
    fn witness_cosigns_extensions_and_quorum_holds() {
        let log = Ed25519Signer::from_seed([1u8; 32]);
        let wa = Ed25519Signer::from_seed([2u8; 32]);
        let (log_key, wa_key) = (log.public_key(), wa.public_key());
        let quorum = [(ORIGIN, &log_key), ("witness-a", &wa_key)];

        let mut w = Witness::new();
        let r1 = receipt(1, w.root());
        w.append(&r1);
        let note1 = log_note(&log, &w);

        let mut witness = CosigningWitness::new(wa, "witness-a", ORIGIN, log_key.clone());
        let line1 = witness
            .add_checkpoint(&note1, 0, &empty_proof())
            .expect("cosign size 1");
        assert_eq!(witness.last_size(), 1);
        let cosigned1 = format!("{note1}{line1}");
        assert_eq!(verify_quorum(&cosigned1, &quorum, 2).unwrap().size, 1);

        // Grow to size 2 and cosign with a real consistency proof.
        let r2 = receipt(2, w.root());
        w.append(&r2);
        let note2 = log_note(&log, &w);
        let proof = w.consistency_proof(1, 2).expect("consistency 1->2");
        let line2 = witness
            .add_checkpoint(&note2, 1, &proof)
            .expect("cosign size 2");
        assert_eq!(witness.last_size(), 2);
        assert!(verify_quorum(&format!("{note2}{line2}"), &quorum, 2).is_some());
    }

    /// A witness refuses a wrong `old` size (needs a re-fetch) and a rollback.
    #[test]
    fn witness_refuses_size_mismatch_and_rollback() {
        let log = Ed25519Signer::from_seed([3u8; 32]);
        let log_key = log.public_key();
        let mut w = Witness::new();
        w.append(&receipt(1, w.root()));
        let note1 = log_note(&log, &w);
        let mut witness =
            CosigningWitness::new(Ed25519Signer::from_seed([4u8; 32]), "wa", ORIGIN, log_key);
        witness.add_checkpoint(&note1, 0, &empty_proof()).unwrap(); // our_size = 1

        // Wrong `old` (0, but we last cosigned 1).
        assert_eq!(
            witness
                .add_checkpoint(&note1, 0, &empty_proof())
                .unwrap_err(),
            CosignError::SizeMismatch { our_size: 1 }
        );

        // Advance to 2, then present the size-1 checkpoint as a rollback.
        w.append(&receipt(2, w.root()));
        let note2 = log_note(&log, &w);
        let proof = w.consistency_proof(1, 2).unwrap();
        witness.add_checkpoint(&note2, 1, &proof).unwrap(); // our_size = 2
        assert_eq!(
            witness
                .add_checkpoint(&note1, 2, &empty_proof())
                .unwrap_err(),
            CosignError::Rollback {
                our_size: 2,
                new_size: 1,
            }
        );
    }

    /// A bogus consistency proof is refused (no append-only evidence).
    #[test]
    fn witness_rejects_inconsistent_proof() {
        let log = Ed25519Signer::from_seed([5u8; 32]);
        let log_key = log.public_key();
        let mut w = Witness::new();
        w.append(&receipt(1, w.root()));
        let note1 = log_note(&log, &w);
        let mut witness =
            CosigningWitness::new(Ed25519Signer::from_seed([6u8; 32]), "wa", ORIGIN, log_key);
        witness.add_checkpoint(&note1, 0, &empty_proof()).unwrap();
        w.append(&receipt(2, w.root()));
        let note2 = log_note(&log, &w);
        let bogus = ConsistencyProof {
            nodes: vec![[9u8; 32]],
        };
        assert_eq!(
            witness.add_checkpoint(&note2, 1, &bogus).unwrap_err(),
            CosignError::InconsistentProof
        );
    }

    /// A checkpoint signed by a different log key is refused.
    #[test]
    fn witness_rejects_foreign_log() {
        let log = Ed25519Signer::from_seed([7u8; 32]);
        let impostor = Ed25519Signer::from_seed([8u8; 32]);
        let mut w = Witness::new();
        w.append(&receipt(1, w.root()));
        let foreign_note = log_note(&impostor, &w);
        let mut witness = CosigningWitness::new(
            Ed25519Signer::from_seed([9u8; 32]),
            "wa",
            ORIGIN,
            log.public_key(),
        );
        assert_eq!(
            witness
                .add_checkpoint(&foreign_note, 0, &empty_proof())
                .unwrap_err(),
            CosignError::BadLogSignature
        );
    }

    /// The quorum only holds at or above the threshold count of known witnesses.
    #[test]
    fn quorum_requires_threshold() {
        let log = Ed25519Signer::from_seed([10u8; 32]);
        let wa = Ed25519Signer::from_seed([11u8; 32]);
        let (log_key, wa_key) = (log.public_key(), wa.public_key());
        let quorum = [(ORIGIN, &log_key), ("witness-a", &wa_key)];

        let mut w = Witness::new();
        w.append(&receipt(1, w.root()));
        let note1 = log_note(&log, &w);

        // Only the log has signed → 1 of 2. Threshold 2 not met; threshold 1 is.
        assert!(verify_quorum(&note1, &quorum, 2).is_none());
        assert!(verify_quorum(&note1, &quorum, 1).is_some());

        // Witness-a cosigns → 2 of 2.
        let mut witness = CosigningWitness::new(wa, "witness-a", ORIGIN, log_key.clone());
        let line = witness.add_checkpoint(&note1, 0, &empty_proof()).unwrap();
        assert!(verify_quorum(&format!("{note1}{line}"), &quorum, 2).is_some());
    }
}
