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
use indexone_witness::{Digest, SignedTreeHead};

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
}
