//! `indexone-verifier-wasm` — the composed `verify()`, in the browser or at the edge.
//!
//! This compiles the *real* `indexone-verifier` to `wasm32` and exposes it to
//! JavaScript. It is the concrete form of a marketable wedge (CLAUDE.md §8): the
//! proof lives in the token and is checked **locally, offline, in microseconds —
//! no chain, no registry lookup, no callback**. A relying party (a browser, a
//! Cloudflare Worker, an edge function) can reject an omitted or self-reported
//! cross-org action without talking to us at all.
//!
//! The JSON in/out shapes match the `indexone-cli` `composed_verify` command, so
//! the same request an SDK builds for the sidecar works here unchanged. Fail
//! closed: any unresolved step returns `{"ok":false,"error":".."}`.

use indexone_attestation::CompletionAttestation;
use indexone_chain::{Chain, Scope};
use indexone_crypto::PublicKey;
use indexone_verifier::{verify, VerifiableAction, VerifyPolicy};
use indexone_witness::ActionReceipt;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

/// A composed-verify request. `trusted_root` is 32-byte hex; the chain, keys,
/// receipt, and completion are the same serde objects the core produces.
#[derive(Deserialize)]
struct VerifyRequest {
    chain: Chain,
    root_key: PublicKey,
    trusted_root: String,
    action_receipt: ActionReceipt,
    completion: CompletionAttestation,
    #[serde(default)]
    trusted_attesters: Vec<PublicKey>,
    #[serde(default)]
    allow_counter_signed: bool,
}

/// Verify a composed cross-org action locally. Input and output are JSON strings
/// (same shapes as `indexone-cli`'s `composed_verify`). Returns
/// `{"ok":true,"effective_scope":..}` on success, or `{"ok":false,"error":".."}`
/// naming the unresolved step (omission, not independently attested, ...).
#[wasm_bindgen]
pub fn verify_action(input_json: &str) -> String {
    match run(input_json) {
        Ok(scope) => serde_json::json!({ "ok": true, "effective_scope": scope }).to_string(),
        Err(error) => serde_json::json!({ "ok": false, "error": error }).to_string(),
    }
}

fn run(input: &str) -> Result<Scope, String> {
    let req: VerifyRequest =
        serde_json::from_str(input).map_err(|e| format!("invalid request JSON: {e}"))?;
    let trusted_root: [u8; 32] = hex::decode(req.trusted_root.trim())
        .map_err(|e| format!("invalid trusted_root hex: {e}"))?
        .try_into()
        .map_err(|_| "trusted_root must be 32 bytes (64 hex chars)".to_string())?;
    let action = VerifiableAction {
        chain: req.chain,
        action_receipt: req.action_receipt,
        completion: req.completion,
    };
    let policy = VerifyPolicy {
        trusted_attesters: req.trusted_attesters,
        allow_counter_signed: req.allow_counter_signed,
    };
    verify(&action, &req.root_key, &trusted_root, &policy).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wasm entry point rejects a malformed request as fail-closed JSON rather
    /// than panicking (the rest of the verify path is covered natively in
    /// `indexone-verifier`; this checks the JSON boundary and the fail-closed
    /// contract that a browser relies on).
    #[test]
    fn malformed_request_fails_closed() {
        let out = verify_action("not json");
        assert!(out.contains("\"ok\":false"));
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["ok"], false);
        assert!(parsed["error"].as_str().unwrap().contains("invalid request JSON"));
    }
}
