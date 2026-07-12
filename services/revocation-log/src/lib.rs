//! `indexone-revocation-log-service` — the hosted IndexOne revocation log.
//!
//! The **publisher** side of remote revocation: it holds the revoked set,
//! signs a [`SignedRevocationSnapshot`] over it, and serves that snapshot over
//! HTTP. The **client** side is `indexone-revocation-http`
//! (`HttpSnapshotSource` → `SnapshotChecker`); together they close the loop the
//! transport crate opened. Every cryptographic operation already lives in
//! `indexone-revocation` — this layer only parses requests, holds the log
//! behind a mutex, and re-signs on read so a served snapshot is always fresh.
//!
//! API:
//!   GET  /revocations/v1/snapshot      — the current SignedRevocationSnapshot
//!                                        (native serde form → wire-compatible
//!                                        with HttpSnapshotSource by construction)
//!   POST /revocations/v1/revoke        — {revocation_id: hex, reason} → revoke,
//!                                        bump the epoch, return the new snapshot
//!   GET  /revocations/v1/entries       — audit list of {id, reason}
//!   GET  /.well-known/revocation-keys  — the operator's public key (pin it as
//!                                        `operator_key` in a SnapshotChecker)
//!
//! Fail-closed by construction: the *checker* rejects a bad-signature, stale, or
//! rolled-back snapshot (that logic is the client's, in `indexone-revocation`).
//! This service's job is to never lie about the epoch — it is **monotonic**: a
//! revocation only ever raises it, so an operator can't quietly un-revoke by
//! serving an older set (the checker enforces the rollback rejection). TLS is
//! intentionally not handled here (terminate at a proxy).

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use indexone_crypto::{Ed25519Signer, PublicKey, Signer};
use indexone_revocation::{RevocationId, SignedRevocationSnapshot};
use serde::{Deserialize, Serialize};

// ── Log state ───────────────────────────────────────────────────────────────

/// The in-memory revocation set plus its monotonic epoch. Append-only: there is
/// deliberately no un-revoke API — dropping an entry is exactly the suppression
/// the design forbids (see `indexone-revocation` invariant #4).
struct RevocationLog {
    /// The signed set. `BTreeSet` so the snapshot digest is order-independent.
    revoked: BTreeSet<RevocationId>,
    /// Audit-only: why each id was pulled. Not part of the signed snapshot.
    reasons: HashMap<RevocationId, String>,
    /// Version of the set; a revocation that changes the set raises it by one.
    epoch: u64,
}

/// A clock returning Unix seconds. Injected so tests are deterministic; the
/// service edge is the only place a real system-clock read is allowed (the core
/// stays clock-injected).
type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

#[derive(Clone)]
pub struct AppState {
    log: Arc<Mutex<RevocationLog>>,
    signer: Arc<Ed25519Signer>,
    operator_key: PublicKey,
    now: Clock,
}

impl AppState {
    /// A fresh, empty log operated by `signer`, reading wall-clock time.
    pub fn new(signer: Ed25519Signer) -> Self {
        Self::with_clock(
            signer,
            Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock before 1970")
                    .as_secs()
            }),
        )
    }

    /// A fresh, empty log with an injected clock (tests pin time for determinism).
    pub fn with_clock(signer: Ed25519Signer, now: Clock) -> Self {
        let operator_key = signer.public_key();
        AppState {
            log: Arc::new(Mutex::new(RevocationLog {
                revoked: BTreeSet::new(),
                reasons: HashMap::new(),
                epoch: 0,
            })),
            signer: Arc::new(signer),
            operator_key,
            now,
        }
    }

    /// Sign the current set at the current epoch and time. Re-signed on every
    /// read, so a served snapshot's `published_at` is always fresh.
    fn current_snapshot(&self) -> SignedRevocationSnapshot {
        let log = self.log.lock().expect("revocation log mutex poisoned");
        SignedRevocationSnapshot::sign(&*self.signer, log.epoch, (self.now)(), log.revoked.clone())
    }
}

/// Build the router. Kept separate from `main` so tests can drive it in-process
/// with `tower::ServiceExt::oneshot` — no socket bound.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/revocations/v1/snapshot", get(get_snapshot))
        .route("/revocations/v1/revoke", post(revoke))
        .route("/revocations/v1/entries", get(get_entries))
        .route("/.well-known/revocation-keys", get(get_keys))
        .with_state(state)
}

// ── Wire DTOs ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RevokeRequest {
    /// The 32-byte `RevocationId` as lowercase hex (matches `RevocationId`'s
    /// `Display`). Keyless: derivable by any token holder from the block
    /// signature, so a revoker never needs the signing key.
    revocation_id: String,
    reason: String,
}

#[derive(Serialize)]
struct EntryDto {
    revocation_id: String,
    reason: String,
}

#[derive(Serialize)]
struct EntriesDto {
    epoch: u64,
    entries: Vec<EntryDto>,
}

#[derive(Serialize)]
struct KeysDto {
    keys: Vec<KeyEntry>,
}

#[derive(Serialize)]
struct KeyEntry {
    kid: String,
    public_key: String,
    alg: &'static str,
}

// ── Errors (fail closed) ────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            ApiError::BadRequest(detail) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "title": "bad request", "detail": detail }),
            ),
        };
        (status, Json(body)).into_response()
    }
}

/// Parse a hex `RevocationId`, rejecting anything that isn't exactly 32 bytes
/// (the blake3 output width) — a malformed id must never silently become a
/// different, valid one.
fn revocation_id_from_hex(s: &str) -> Result<RevocationId, ApiError> {
    let bytes = hex::decode(s.trim())
        .map_err(|_| ApiError::BadRequest("revocation_id must be hex".into()))?;
    if bytes.len() != 32 {
        return Err(ApiError::BadRequest(
            "revocation_id must be 32 bytes (64 hex chars)".into(),
        ));
    }
    Ok(RevocationId(bytes))
}

// ── Handlers ────────────────────────────────────────────────────────────────

async fn get_snapshot(State(st): State<AppState>) -> Json<SignedRevocationSnapshot> {
    Json(st.current_snapshot())
}

async fn revoke(
    State(st): State<AppState>,
    Json(req): Json<RevokeRequest>,
) -> Result<(StatusCode, Json<SignedRevocationSnapshot>), ApiError> {
    let id = revocation_id_from_hex(&req.revocation_id)?;
    {
        let mut log = st.log.lock().expect("revocation log mutex poisoned");
        // Epoch is the version of the *set*: only a genuine change raises it, so
        // repeated revokes of the same id stay idempotent and monotonic.
        if log.revoked.insert(id.clone()) {
            log.epoch += 1;
        }
        log.reasons.insert(id, req.reason);
    }
    Ok((StatusCode::CREATED, Json(st.current_snapshot())))
}

async fn get_entries(State(st): State<AppState>) -> Json<EntriesDto> {
    let log = st.log.lock().expect("revocation log mutex poisoned");
    // Iterate the sorted set so the audit listing is deterministic.
    let entries = log
        .revoked
        .iter()
        .map(|id| EntryDto {
            revocation_id: id.to_string(),
            reason: log.reasons.get(id).cloned().unwrap_or_default(),
        })
        .collect();
    Json(EntriesDto {
        epoch: log.epoch,
        entries,
    })
}

async fn get_keys(State(st): State<AppState>) -> Json<KeysDto> {
    let hex_key = hex::encode(&st.operator_key.bytes);
    Json(KeysDto {
        keys: vec![KeyEntry {
            kid: hex_key.clone(),
            public_key: hex_key,
            alg: "ed25519",
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use indexone_crypto::{Algorithm, Signature};
    use indexone_revocation::{FixedClock, RevocationChecker, RevocationStatus, SnapshotChecker};
    use indexone_revocation_http::HttpSnapshotSource;
    use tower::ServiceExt;

    fn state_at(now: u64) -> AppState {
        AppState::with_clock(Ed25519Signer::from_seed([21u8; 32]), Arc::new(move || now))
    }

    /// A revocation id built the same way the core does — keyless, from
    /// signature bytes — so tests name real ids without holding any key.
    fn rev_id(tag: u8) -> RevocationId {
        RevocationId::from_signature(&Signature {
            algorithm: Algorithm::Ed25519,
            bytes: vec![tag; 64],
        })
    }

    async fn json_request(
        app: Router,
        method: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let resp = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    /// An empty log serves a valid, operator-signed snapshot at epoch 0, so a
    /// client can bootstrap `last_seen_epoch = 0` without rejecting it.
    #[tokio::test]
    async fn empty_log_serves_a_signed_epoch_zero_snapshot() {
        let st = state_at(1_000);
        let (status, body) = json_request(
            app(st.clone()),
            "GET",
            "/revocations/v1/snapshot",
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let snap: SignedRevocationSnapshot = serde_json::from_value(body).unwrap();
        assert_eq!(snap.epoch, 0);
        assert!(snap.revoked.is_empty());
        assert!(snap.verify_signature(&st.operator_key));
    }

    /// Revoking raises the epoch and adds the id to the signed set; re-revoking
    /// the same id is idempotent (epoch does not move).
    #[tokio::test]
    async fn revoke_raises_epoch_and_is_idempotent() {
        let st = state_at(2_000);
        let id = rev_id(7);
        let (status, body) = json_request(
            app(st.clone()),
            "POST",
            "/revocations/v1/revoke",
            serde_json::json!({ "revocation_id": id.to_string(), "reason": "key leaked" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let snap: SignedRevocationSnapshot = serde_json::from_value(body).unwrap();
        assert_eq!(snap.epoch, 1);
        assert!(snap.revoked.contains(&id));
        assert!(snap.verify_signature(&st.operator_key));

        // Same id again → still epoch 1 (idempotent, monotonic).
        let (_s, body2) = json_request(
            app(st.clone()),
            "POST",
            "/revocations/v1/revoke",
            serde_json::json!({ "revocation_id": id.to_string(), "reason": "still leaked" }),
        )
        .await;
        let snap2: SignedRevocationSnapshot = serde_json::from_value(body2).unwrap();
        assert_eq!(snap2.epoch, 1);
    }

    /// A non-hex or wrong-length id is rejected (fail closed), never coerced.
    #[tokio::test]
    async fn malformed_revocation_id_is_rejected() {
        let st = state_at(1_000);
        let (status, _body) = json_request(
            app(st),
            "POST",
            "/revocations/v1/revoke",
            serde_json::json!({ "revocation_id": "not-hex", "reason": "x" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// The whole loop, in one test: this service signs a snapshot, the real HTTP
    /// transport (`HttpSnapshotSource`) fetches it over a bound socket, and a
    /// `SnapshotChecker` answers a revocation query from it — publisher →
    /// transport → checker, end to end.
    #[tokio::test(flavor = "multi_thread")]
    async fn end_to_end_publisher_to_transport_to_checker() {
        let st = state_at(5_000);
        let revoked = rev_id(3);
        let live = rev_id(4);

        // Revoke `revoked` through the service.
        json_request(
            app(st.clone()),
            "POST",
            "/revocations/v1/revoke",
            serde_json::json!({ "revocation_id": revoked.to_string(), "reason": "compromised" }),
        )
        .await;

        // Serve the app on a real socket so the blocking HTTP client can reach it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let operator_key = st.operator_key.clone();
        tokio::spawn(async move {
            axum::serve(listener, app(st)).await.unwrap();
        });

        // The blocking transport must run off the async runtime.
        let checker_result = tokio::task::spawn_blocking(move || {
            let url = format!("http://{addr}/revocations/v1/snapshot");
            let checker = SnapshotChecker::new(
                Box::new(HttpSnapshotSource::new(url)),
                operator_key,
                FixedClock(5_050),
                3_600,
            );
            let revoked_status = checker.is_revoked(&revoked).unwrap();
            let live_status = checker.is_revoked(&live).unwrap();
            (revoked_status, live_status)
        })
        .await
        .unwrap();

        assert!(matches!(checker_result.0, RevocationStatus::Revoked { .. }));
        assert_eq!(checker_result.1, RevocationStatus::Live);
    }
}
