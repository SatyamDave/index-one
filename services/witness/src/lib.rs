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
}

impl AppState {
    /// A fresh, empty log operated by `log_signer`.
    pub fn new(log_signer: Ed25519Signer) -> Self {
        let log_key = log_signer.public_key();
        AppState {
            witness: Arc::new(Mutex::new(Witness::new())),
            log_signer: Arc::new(log_signer),
            log_key,
        }
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
}
