use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use mandatepay::{
    error::AppError,
    gateway,
    mandates::{self, Authority, Mandate},
    policy::{self, Decision},
    store::Db,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

type SharedState = Arc<AppState>;

struct AppState {
    authority: Authority,
    db: Db,
}

#[derive(Deserialize)]
struct IssueRequest {
    agent_id: String,
    merchant_id: String,
    currency: String,
    max_amount_minor: u64,
    ttl_secs: u64,
}

#[derive(Serialize)]
struct Issued {
    mandate: Mandate,
    signature: String,
}

#[derive(Deserialize)]
struct CheckoutRequest {
    mandate: Mandate,
    signature: String,
}

#[derive(Serialize)]
struct DecisionResponse {
    decision: String,
    reason: String,
    order_id: Option<String>,
}

async fn issue(
    State(state): State<SharedState>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<Issued>, AppError> {
    if req.agent_id.trim().is_empty() || req.merchant_id.trim().is_empty() {
        return Err(AppError::BadRequest(
            "agent_id and merchant_id are required".into(),
        ));
    }
    if !(60..=86_400).contains(&req.ttl_secs) {
        return Err(AppError::BadRequest(
            "ttl_secs must be between 60 and 86400".into(),
        ));
    }
    if req.currency != "INR" {
        return Err(AppError::BadRequest(
            "only INR mandates are supported".into(),
        ));
    }
    if req.max_amount_minor == 0 {
        return Err(AppError::BadRequest(
            "max_amount_minor must be positive".into(),
        ));
    }

    let now = mandates::unix_now();
    let mandate = Mandate {
        version: 1,
        mandate_id: mandates::new_token("mnd_", 9),
        agent_id: req.agent_id.trim().to_string(),
        merchant_id: req.merchant_id.trim().to_string(),
        action: "create_order".into(),
        currency: "INR".into(),
        max_amount_minor: req.max_amount_minor,
        issued_at: now,
        expires_at: now
            .checked_add(req.ttl_secs)
            .ok_or_else(|| AppError::BadRequest("ttl_secs overflow".into()))?,
        nonce: mandates::new_token("n_", 16),
    };
    let signature = state
        .authority
        .sign(&mandate)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    state
        .db
        .record_decision(
            "/v1/mandates",
            "ISSUED",
            &format!(
                "cap {} {} for agent {}",
                mandate.max_amount_minor, mandate.currency, mandate.agent_id
            ),
            &serde_json::to_string(&mandate).unwrap_or_default(),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(Issued { mandate, signature }))
}

async fn checkout(
    State(state): State<SharedState>,
    Json(req): Json<CheckoutRequest>,
) -> Result<Json<DecisionResponse>, AppError> {
    let decision = policy::evaluate(&state.authority, &req.mandate, &req.signature, &state.db);

    let (label, mut reason) = match &decision {
        Decision::Allow { reason } => ("ALLOW", reason.clone()),
        Decision::Reject { reason } => ("REJECT", reason.clone()),
    };

    let mut order_id = None;
    if matches!(decision, Decision::Allow { .. }) {
        match gateway::create_test_order(&req.mandate).await {
            Ok(id) => order_id = Some(id),
            Err(e) => reason = format!("{reason}; gateway: {e}"),
        }
    }

    state
        .db
        .record_decision(
            "/v1/checkout",
            label,
            &reason,
            &serde_json::to_string(&req.mandate).unwrap_or_default(),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(DecisionResponse {
        decision: label.into(),
        reason,
        order_id,
    }))
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let authority = Authority::from_seed(mandates::load_seed());
    eprintln!("authority public key: {}", authority.public_key_b64());

    let db = Db::open("mandatepay.db").expect("failed to open sqlite ledger");
    let state = Arc::new(AppState { authority, db });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/mandates", post(issue))
        .route("/v1/checkout", post(checkout))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("port 8080 already in use");
    eprintln!("listening on http://{addr}");
    axum::serve(listener, app).await.expect("server crashed");
}
