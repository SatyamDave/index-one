//! `indexone-witness-service` — the hosted IndexOne witness.
//!
//! A cross-org transparency-log HTTP service: the "run the anchor" product. It
//! is a thin, standards-aligned shell over `indexone-witness` — every
//! cryptographic operation already lives in that crate; this layer only parses
//! requests, (de)serializes digests/signatures as base64url, and holds the log
//! state behind a mutex.
//!
//! API (RFC 6962 §4 / SCITT SCRAPI aligned; see `README.md`):
//!   POST /witness/v1/entries       — submit a receipt → leaf index + inclusion proof + STH
//!   GET  /witness/v1/sth           — current signed tree head            (RFC 6962 get-sth)
//!   GET  /witness/v1/proof         — inclusion proof by leaf_index       (get-proof-by-hash/index)
//!   GET  /witness/v1/consistency   — consistency proof first→second      (get-sth-consistency)
//!   POST /witness/v1/gossip        — reconcile a peer STH → consistent | equivocation proof
//!   GET  /.well-known/witness-keys — the operator's public key (verify offline)
//!
//! Fail-closed: a bad request, a stale `prev_root`, or a detected equivocation
//! all return a typed error, never a silent success. TLS is intentionally not
//! handled here (terminate at a proxy).

use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use indexone_crypto::{Ed25519Signer, PublicKey, Signature, Signer};
use indexone_witness::{
    reconcile_heads, ActionReceipt, ConsistencyProof, Digest, EquivocationError, InclusionProof,
    PathStep, SignedTreeHead, Witness,
};
use serde::{Deserialize, Serialize};

// ── Shared state ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    witness: Arc<Mutex<Witness>>,
    log_signer: Arc<Ed25519Signer>,
    log_key: PublicKey,
    /// Durable append-only backing store. `Some` ⇒ every appended receipt is
    /// persisted (and flushed) before it is acked, and the whole log is rebuilt
    /// from disk on restart; `None` ⇒ in-memory only (tests, ephemeral runs).
    store: Option<Arc<Mutex<Store>>>,
}

impl AppState {
    /// A fresh, empty **in-memory** log operated by `log_signer` (no persistence
    /// — a restart starts from an empty tree).
    pub fn new(log_signer: Ed25519Signer) -> Self {
        let log_key = log_signer.public_key();
        AppState {
            witness: Arc::new(Mutex::new(Witness::new())),
            log_signer: Arc::new(log_signer),
            log_key,
            store: None,
        }
    }

    /// A **durable** log backed by the append-only file at `path`. Existing
    /// entries are replayed into the tree on open — so the root and every
    /// inclusion proof survive a restart — and each new receipt is persisted
    /// before it is acked. A missing file starts an empty log.
    pub fn with_persistence(log_signer: Ed25519Signer, path: impl AsRef<Path>) -> io::Result<Self> {
        let log_key = log_signer.public_key();
        let mut witness = Witness::new();
        let store = Store::open(path.as_ref(), &mut witness)?;
        Ok(AppState {
            witness: Arc::new(Mutex::new(witness)),
            log_signer: Arc::new(log_signer),
            log_key,
            store: Some(Arc::new(Mutex::new(store))),
        })
    }
}

/// Durable append-only storage for the witness log: a sequence of
/// length-prefixed (`u32` little-endian) canonical `ActionReceipt` frames. The
/// Merkle tree is a pure function of these receipts in order, so replaying the
/// file reconstructs the exact same root — disk is the source of truth.
struct Store {
    file: std::fs::File,
}

impl Store {
    /// Open (creating if absent) the log at `path`, replaying every persisted
    /// receipt into `witness` in order, then leave the file open for appends.
    fn open(path: &Path, witness: &mut Witness) -> io::Result<Store> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        // Replay every COMPLETE frame. A torn *trailing* frame — a partial length
        // prefix, or a length prefix whose body was not fully written — is an
        // append that crashed before it was fsync'd/acked; recover by truncating
        // back to the last complete frame rather than refusing to start. Interior
        // corruption (a bad frame with more data after it) is genuine damage and
        // still fails closed.
        let mut committed = 0usize;
        let mut cursor = 0usize;
        while cursor + 4 <= bytes.len() {
            let len =
                u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().expect("4 bytes")) as usize;
            let body = cursor + 4;
            if body + len > bytes.len() {
                break; // torn trailing frame: the body was not fully written
            }
            match serde_json::from_slice::<ActionReceipt>(&bytes[body..body + len]) {
                Ok(receipt) => {
                    witness.append(&receipt);
                }
                Err(e) => {
                    // Interior (non-trailing) unparseable frame is real corruption;
                    // a length-complete-but-bad frame at the very end is treated as
                    // an uncommitted torn append and truncated.
                    if body + len < bytes.len() {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                    }
                    break;
                }
            }
            cursor = body + len;
            committed = cursor;
        }
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?;
        // Physically drop any torn trailing bytes so the next append lands on a
        // frame boundary, and fsync the truncation.
        if committed < bytes.len() {
            file.set_len(committed as u64)?;
            file.sync_all()?;
        }
        // Best-effort: fsync the directory so the log file's creation is itself
        // durable (a crash right after create() can otherwise lose the entry).
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            if let Ok(dir_file) = std::fs::File::open(dir) {
                let _ = dir_file.sync_all();
            }
        }
        Ok(Store { file })
    }

    /// Durably append one receipt as a length-prefixed frame, **fsync'd to the
    /// physical device** before returning, so an acked entry survives power loss
    /// / kernel panic — not just a clean process exit.
    fn append(&mut self, receipt: &ActionReceipt) -> io::Result<()> {
        let bytes = receipt.canonical_bytes();
        let len = u32::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "receipt frame too large"))?;
        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(&bytes)?;
        // fsync, not flush(): flush() only pushes to the OS page cache, which a
        // power loss can still lose. sync_all() forces bytes + metadata to disk.
        self.file.sync_all()
    }
}

/// Build the router. Kept separate from `main` so tests can drive it in-process
/// with `tower::ServiceExt::oneshot` — no socket bound.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/witness/v1/entries", post(submit))
        .route("/witness/v1/sth", get(get_sth))
        .route("/witness/v1/proof", get(get_proof))
        .route("/witness/v1/consistency", get(get_consistency))
        .route("/witness/v1/gossip", post(gossip))
        .route("/.well-known/witness-keys", get(get_keys))
        .with_state(state)
}

// ── base64url helpers ───────────────────────────────────────────────────────

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>, ApiError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| ApiError::BadRequest("invalid base64url".into()))
}

fn digest_from_b64(s: &str) -> Result<Digest, ApiError> {
    unb64(s)?
        .try_into()
        .map_err(|_| ApiError::BadRequest("digest must be 32 bytes".into()))
}

// ── Wire DTOs (base64url, RFC 6962 conventions) ─────────────────────────────

#[derive(Deserialize)]
pub struct SubmitRequest {
    chain_digest: String,
    action_digest: String,
    nonce: String,
    prev_root: String,
}

impl SubmitRequest {
    fn to_receipt(&self) -> Result<ActionReceipt, ApiError> {
        Ok(ActionReceipt {
            chain_digest: digest_from_b64(&self.chain_digest)?,
            action_digest: digest_from_b64(&self.action_digest)?,
            nonce: digest_from_b64(&self.nonce)?,
            prev_root: digest_from_b64(&self.prev_root)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct SthDto {
    tree_size: usize,
    root: String,
    signature: String,
}

fn sth_to_dto(sth: &SignedTreeHead) -> SthDto {
    SthDto {
        tree_size: sth.tree_size,
        root: b64(&sth.root),
        signature: b64(&sth.signature.bytes),
    }
}

fn dto_to_sth(dto: &SthDto) -> Result<SignedTreeHead, ApiError> {
    Ok(SignedTreeHead {
        tree_size: dto.tree_size,
        root: digest_from_b64(&dto.root)?,
        // The operator signs with Ed25519 (the key advertised at
        // /.well-known/witness-keys); reconstruct the tagged signature.
        signature: Signature {
            algorithm: indexone_crypto::Algorithm::Ed25519,
            bytes: unb64(&dto.signature)?,
        },
    })
}

#[derive(Serialize)]
struct PathStepDto {
    sibling: String,
    sibling_is_left: bool,
}

#[derive(Serialize)]
struct InclusionProofDto {
    leaf_index: usize,
    tree_size: usize,
    path: Vec<PathStepDto>,
}

fn inclusion_to_dto(p: &InclusionProof) -> InclusionProofDto {
    InclusionProofDto {
        leaf_index: p.leaf_index,
        tree_size: p.tree_size,
        path: p
            .path
            .iter()
            .map(|s: &PathStep| PathStepDto {
                sibling: b64(&s.sibling),
                sibling_is_left: s.sibling_is_left,
            })
            .collect(),
    }
}

#[derive(Serialize)]
struct SubmitResponse {
    leaf_index: usize,
    inclusion_proof: InclusionProofDto,
    sth: SthDto,
}

#[derive(Serialize, Deserialize)]
pub struct ConsistencyDto {
    /// RFC 6962 field name (`get-sth-consistency` → `consistency`).
    consistency: Vec<String>,
}

fn consistency_to_dto(p: &ConsistencyProof) -> ConsistencyDto {
    ConsistencyDto {
        consistency: p.nodes.iter().map(|n| b64(n)).collect(),
    }
}

fn dto_to_consistency(dto: &ConsistencyDto) -> Result<ConsistencyProof, ApiError> {
    let nodes = dto
        .consistency
        .iter()
        .map(|s| digest_from_b64(s))
        .collect::<Result<Vec<Digest>, _>>()?;
    Ok(ConsistencyProof { nodes })
}

#[derive(Deserialize)]
pub struct GossipRequest {
    peer_sth: SthDto,
    consistency_proof: Option<ConsistencyDto>,
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

#[derive(Deserialize)]
pub struct ProofQuery {
    leaf_index: usize,
}

#[derive(Deserialize)]
pub struct ConsistencyQuery {
    first: usize,
    second: usize,
}

// ── Errors (fail closed) ────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    StalePrevRoot,
    /// The response body *is* the equivocation evidence (two operator-signed
    /// heads that can't be reconciled).
    Equivocation(serde_json::Value),
    /// The log could not be persisted; the append is rejected rather than acked
    /// without durability (fail closed).
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            ApiError::BadRequest(detail) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "title": "bad request", "detail": detail }),
            ),
            ApiError::NotFound(detail) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({ "title": "not found", "detail": detail }),
            ),
            ApiError::StalePrevRoot => (
                StatusCode::CONFLICT,
                serde_json::json!({
                    "title": "stale prev_root",
                    "detail": "prev_root must equal the log's current root at submission"
                }),
            ),
            ApiError::Equivocation(evidence) => (StatusCode::CONFLICT, evidence),
            ApiError::Internal(detail) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "title": "internal error", "detail": detail }),
            ),
        };
        (status, Json(body)).into_response()
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

async fn submit(
    State(st): State<AppState>,
    Json(req): Json<SubmitRequest>,
) -> Result<(StatusCode, Json<SubmitResponse>), ApiError> {
    let receipt = req.to_receipt()?;
    // Lock → mutate → read → drop guard; no `.await` held across the lock.
    let (leaf_index, proof, sth) = {
        let mut w = st.witness.lock().expect("witness mutex poisoned");
        if receipt.prev_root != w.root() {
            return Err(ApiError::StalePrevRoot);
        }
        // Durability: persist the receipt (and flush) BEFORE the in-memory
        // append and before we ack, so a crash between the two is recovered by
        // replay — disk is authoritative, an acked entry is never lost. Only
        // `submit` touches the store, always under the witness lock, so the
        // witness→store lock order is globally consistent.
        if let Some(store) = &st.store {
            store
                .lock()
                .expect("store mutex poisoned")
                .append(&receipt)
                .map_err(|e| ApiError::Internal(format!("persist: {e}")))?;
        }
        let idx = w.append(&receipt);
        let proof = w
            .inclusion_proof(idx)
            .expect("just-appended leaf is in range");
        let sth = w.signed_head(&*st.log_signer);
        (idx, proof, sth)
    };
    Ok((
        StatusCode::CREATED,
        Json(SubmitResponse {
            leaf_index,
            inclusion_proof: inclusion_to_dto(&proof),
            sth: sth_to_dto(&sth),
        }),
    ))
}

async fn get_sth(State(st): State<AppState>) -> Json<SthDto> {
    let sth = {
        let w = st.witness.lock().expect("witness mutex poisoned");
        w.signed_head(&*st.log_signer)
    };
    Json(sth_to_dto(&sth))
}

async fn get_proof(
    State(st): State<AppState>,
    Query(q): Query<ProofQuery>,
) -> Result<Json<InclusionProofDto>, ApiError> {
    let proof = {
        let w = st.witness.lock().expect("witness mutex poisoned");
        w.inclusion_proof(q.leaf_index)
    };
    match proof {
        Some(p) => Ok(Json(inclusion_to_dto(&p))),
        None => Err(ApiError::NotFound(format!(
            "no leaf at index {}",
            q.leaf_index
        ))),
    }
}

async fn get_consistency(
    State(st): State<AppState>,
    Query(q): Query<ConsistencyQuery>,
) -> Result<Json<ConsistencyDto>, ApiError> {
    let proof = {
        let w = st.witness.lock().expect("witness mutex poisoned");
        w.consistency_proof(q.first, q.second)
    };
    match proof {
        Some(p) => Ok(Json(consistency_to_dto(&p))),
        None => Err(ApiError::BadRequest(
            "second must equal the current tree size and first <= second".into(),
        )),
    }
}

async fn gossip(
    State(st): State<AppState>,
    Json(req): Json<GossipRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let peer = dto_to_sth(&req.peer_sth)?;
    let proof = req
        .consistency_proof
        .as_ref()
        .map(dto_to_consistency)
        .transpose()?;
    let ours = {
        let w = st.witness.lock().expect("witness mutex poisoned");
        w.signed_head(&*st.log_signer)
    };
    match reconcile_heads(&ours, &peer, &st.log_key, proof.as_ref()) {
        Ok(()) => Ok(Json(serde_json::json!({ "status": "consistent" }))),
        Err(e) => {
            let reason = match e {
                EquivocationError::InvalidSignedHead => "invalid_signed_head",
                EquivocationError::ForkedRoot { .. } => "forked_root",
                EquivocationError::Inconsistent { .. } => "inconsistent",
            };
            // 409 with the two operator-signed heads: non-repudiable evidence.
            Err(ApiError::Equivocation(serde_json::json!({
                "status": "equivocation",
                "reason": reason,
                "our_sth": sth_to_dto(&ours),
                "peer_sth": req.peer_sth,
            })))
        }
    }
}

async fn get_keys(State(st): State<AppState>) -> Json<KeysDto> {
    Json(KeysDto {
        keys: vec![KeyEntry {
            kid: b64(&st.log_key.bytes),
            public_key: b64(&st.log_key.bytes),
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
    use indexone_witness::{verify_inclusion, verify_signed_head};
    use tower::ServiceExt;

    fn state() -> AppState {
        AppState::new(Ed25519Signer::from_seed([7u8; 32]))
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

    fn receipt_json(action: u8, prev_root: &Digest) -> serde_json::Value {
        serde_json::json!({
            "chain_digest": b64(&[1u8; 32]),
            "action_digest": b64(&[action; 32]),
            "nonce": b64(&[action; 32]),
            "prev_root": b64(prev_root),
        })
    }

    // The log's current root (an empty log's root is hash_leaf([]), not zeros),
    // which a submitter must use as `prev_root` — the crate's chaining contract.
    async fn current_root(st: &AppState) -> Digest {
        let (_s, body) = json_request(
            app(st.clone()),
            "GET",
            "/witness/v1/sth",
            serde_json::Value::Null,
        )
        .await;
        digest_from_b64(body["root"].as_str().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn submit_then_the_returned_proof_verifies_against_the_sth() {
        let st = state();
        let root0 = current_root(&st).await;
        let (status, body) = json_request(
            app(st.clone()),
            "POST",
            "/witness/v1/entries",
            receipt_json(42, &root0),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["leaf_index"], 0);

        // Reconstruct the receipt, the proof, and the STH from the response and
        // verify inclusion offline — exactly what a relying party does.
        let receipt = ActionReceipt {
            chain_digest: [1u8; 32],
            action_digest: [42u8; 32],
            nonce: [42u8; 32],
            prev_root: root0,
        };
        let sth_dto: SthDto = serde_json::from_value(body["sth"].clone()).unwrap();
        let sth = dto_to_sth(&sth_dto).unwrap();
        assert!(verify_signed_head(&sth, &st.log_key));

        let proof = InclusionProof {
            leaf_index: body["inclusion_proof"]["leaf_index"].as_u64().unwrap() as usize,
            tree_size: body["inclusion_proof"]["tree_size"].as_u64().unwrap() as usize,
            path: body["inclusion_proof"]["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| PathStep {
                    sibling: digest_from_b64(s["sibling"].as_str().unwrap()).unwrap(),
                    sibling_is_left: s["sibling_is_left"].as_bool().unwrap(),
                })
                .collect(),
        };
        assert!(verify_inclusion(&receipt, &proof, &sth.root));
    }

    #[tokio::test]
    async fn stale_prev_root_is_rejected() {
        let st = state();
        let r0 = current_root(&st).await;
        // First append (with the real current root) succeeds and moves the root;
        // a second submit still claiming `r0` as prev_root is now stale.
        let (first, _) = json_request(
            app(st.clone()),
            "POST",
            "/witness/v1/entries",
            receipt_json(1, &r0),
        )
        .await;
        assert_eq!(first, StatusCode::CREATED);
        let (status, body) =
            json_request(app(st), "POST", "/witness/v1/entries", receipt_json(2, &r0)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["title"], "stale prev_root");
    }

    #[tokio::test]
    async fn sth_and_consistency_track_appends() {
        let st = state();
        let mut prev = current_root(&st).await;
        for i in 0..3u8 {
            let (_s, body) = json_request(
                app(st.clone()),
                "POST",
                "/witness/v1/entries",
                receipt_json(i, &prev),
            )
            .await;
            let sth: SthDto = serde_json::from_value(body["sth"].clone()).unwrap();
            prev = digest_from_b64(&sth.root).unwrap();
        }
        let (status, body) = json_request(
            app(st),
            "GET",
            "/witness/v1/consistency?first=1&second=3",
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body["consistency"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn gossip_detects_a_forked_root() {
        let st = state();
        // Our log has one entry.
        let r0 = current_root(&st).await;
        json_request(
            app(st.clone()),
            "POST",
            "/witness/v1/entries",
            receipt_json(1, &r0),
        )
        .await;

        // A forked peer: a different size-1 log, its head signed by the SAME
        // operator key — a genuine equivocation.
        let mut forked = Witness::new();
        forked.append(&ActionReceipt {
            chain_digest: [9u8; 32],
            action_digest: [9u8; 32],
            nonce: [9u8; 32],
            prev_root: [0u8; 32],
        });
        let forked_head = forked.signed_head(&Ed25519Signer::from_seed([7u8; 32]));

        let (status, body) = json_request(
            app(st),
            "POST",
            "/witness/v1/gossip",
            serde_json::json!({ "peer_sth": sth_to_dto(&forked_head) }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["status"], "equivocation");
        assert_eq!(body["reason"], "forked_root");
    }

    #[tokio::test]
    async fn well_known_keys_are_served() {
        let st = state();
        let (status, body) = json_request(
            app(st.clone()),
            "GET",
            "/.well-known/witness-keys",
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["keys"][0]["alg"], "ed25519");
        assert_eq!(body["keys"][0]["public_key"], b64(&st.log_key.bytes));
    }

    fn temp_log_path() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        std::env::temp_dir().join(format!(
            "indexone-witness-persist-{}-{}.log",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn persisted_log_survives_restart() {
        let path = temp_log_path();
        let seed = [7u8; 32];

        // Instance 1: append three chained receipts (disk + memory, exactly as
        // `submit` does) and record the resulting root and length.
        let (expected_root, expected_len) = {
            let st = AppState::with_persistence(Ed25519Signer::from_seed(seed), &path).unwrap();
            let mut w = st.witness.lock().unwrap();
            let mut prev = w.root();
            for i in 0..3u8 {
                let r = ActionReceipt {
                    chain_digest: [i; 32],
                    action_digest: [i; 32],
                    nonce: [i; 32],
                    prev_root: prev,
                };
                st.store
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .append(&r)
                    .unwrap();
                w.append(&r);
                prev = w.root();
            }
            (w.root(), w.len())
        };

        // Instance 2: reopen the same path — the tree is rebuilt from disk, so
        // root and length match exactly and every past inclusion proof still
        // verifies against the recovered root.
        let st2 = AppState::with_persistence(Ed25519Signer::from_seed(seed), &path).unwrap();
        {
            let w2 = st2.witness.lock().unwrap();
            assert_eq!(w2.len(), expected_len);
            assert_eq!(w2.root(), expected_root);
        }
        std::fs::remove_file(&path).ok();

        // A fresh (absent) path opens as a size-0 log — no stale state leaks in.
        let fresh = temp_log_path();
        let empty = AppState::with_persistence(Ed25519Signer::from_seed(seed), &fresh).unwrap();
        assert_eq!(empty.witness.lock().unwrap().len(), 0);
        std::fs::remove_file(&fresh).ok();
    }

    /// Write `count` chained receipts to a fresh persisted log and return the
    /// resulting (root, len). Shared setup for the crash-recovery tests.
    fn seed_log(path: &Path, seed: [u8; 32], count: u8) -> (Digest, usize) {
        let st = AppState::with_persistence(Ed25519Signer::from_seed(seed), path).unwrap();
        let mut w = st.witness.lock().unwrap();
        let mut prev = w.root();
        for i in 0..count {
            let r = ActionReceipt {
                chain_digest: [i; 32],
                action_digest: [i; 32],
                nonce: [i; 32],
                prev_root: prev,
            };
            st.store
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .append(&r)
                .unwrap();
            w.append(&r);
            prev = w.root();
        }
        (w.root(), w.len())
    }

    /// Crash mid-append: a length prefix whose body was only partially written to
    /// disk before power loss. On restart the torn frame is dropped (it was never
    /// acked), the committed frames replay, and the log keeps working — durably.
    #[test]
    fn torn_trailing_frame_is_recovered_on_restart() {
        use std::io::Write;
        let path = temp_log_path();
        let seed = [8u8; 32];
        let (root2, len2) = seed_log(&path, seed, 2);

        // Simulate the crash: a frame claiming 100 bytes, of which only 3 landed.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(&100u32.to_le_bytes()).unwrap();
            f.write_all(&[1u8, 2, 3]).unwrap();
            f.sync_all().unwrap();
        }

        // Reopen: torn frame dropped, committed frames intact, and a fresh append
        // lands on the recovered boundary.
        let expected = {
            let st = AppState::with_persistence(Ed25519Signer::from_seed(seed), &path).unwrap();
            let mut w = st.witness.lock().unwrap();
            assert_eq!(w.len(), len2, "torn frame must not be counted");
            assert_eq!(
                w.root(),
                root2,
                "recovered root must match the committed log"
            );
            let r = ActionReceipt {
                chain_digest: [9; 32],
                action_digest: [9; 32],
                nonce: [9; 32],
                prev_root: w.root(),
            };
            st.store
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .append(&r)
                .unwrap();
            w.append(&r);
            (w.root(), w.len())
        };

        // The truncation + the new append both survive another restart.
        let st3 = AppState::with_persistence(Ed25519Signer::from_seed(seed), &path).unwrap();
        let w3 = st3.witness.lock().unwrap();
        assert_eq!((w3.root(), w3.len()), expected);
        std::fs::remove_file(&path).ok();
    }

    /// A crash that left only a *partial length prefix* (< 4 bytes) at the tail is
    /// likewise recovered — the committed frames still replay.
    #[test]
    fn partial_length_prefix_is_recovered_on_restart() {
        use std::io::Write;
        let path = temp_log_path();
        let seed = [8u8; 32];
        let (root1, len1) = seed_log(&path, seed, 1);
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(&[0xAB, 0xCD]).unwrap(); // 2 stray bytes of a length prefix
            f.sync_all().unwrap();
        }
        let st2 = AppState::with_persistence(Ed25519Signer::from_seed(seed), &path).unwrap();
        let w2 = st2.witness.lock().unwrap();
        assert_eq!(w2.len(), len1);
        assert_eq!(w2.root(), root1);
        std::fs::remove_file(&path).ok();
    }
}
