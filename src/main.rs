use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Query, State},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use mandatepay::{
    auth::{extract_api_key, resolve_api_key, verify_api_key},
    error::AppError,
    gateway::Gateway,
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
    gateway: Gateway,
    allowed_merchants: Vec<String>,
    api_key: String,
    max_mandate_cap: u64,
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
    amount_minor: u64,
}

#[derive(Serialize)]
struct DecisionResponse {
    decision: String,
    reason: String,
    order_id: Option<String>,
    gateway: String,
}

fn parse_allowlist() -> Vec<String> {
    std::env::var("ALLOWED_MERCHANTS")
        .unwrap_or_else(|_| "merchant-001".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_max_cap() -> u64 {
    std::env::var("MANDATEPAY_MAX_CAP")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(100_000)
}

async fn require_api_key(
    State(state): State<SharedState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AppError> {
    let provided = extract_api_key(req.headers());
    match provided {
        Some(k) if verify_api_key(&k, &state.api_key) => Ok(next.run(req).await),
        _ => Err(AppError::Unauthorized("invalid or missing API key".into())),
    }
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
    if req.max_amount_minor > state.max_mandate_cap {
        return Err(AppError::BadRequest(format!(
            "max_amount_minor {} exceeds server cap {}",
            req.max_amount_minor, state.max_mandate_cap
        )));
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
    let agent_id = req.mandate.agent_id.trim();
    if agent_id.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }

    if !state.db.check_velocity(agent_id)? {
        let reason = format!("velocity limit exceeded for agent {}", agent_id);
        state.db.record_decision(
            "/v1/checkout",
            "REJECT",
            &reason,
            &serde_json::to_string(&req.mandate).unwrap_or_default(),
        )?;
        return Ok(Json(DecisionResponse {
            decision: "REJECT".into(),
            reason,
            order_id: None,
            gateway: state.gateway.label().into(),
        }));
    }

    let agent_policy = state.db.get_agent_policy(agent_id)?.unwrap_or_else(|| {
        let allow = parse_allowlist();
        mandatepay::store::AgentPolicy {
            agent_id: agent_id.to_string(),
            max_cap: state.max_mandate_cap,
            velocity_limit: 50,
            velocity_window_secs: 60,
            allowed_merchants: allow,
        }
    });

    let allowed_merchants = agent_policy.allowed_merchants.clone();

    let decision = policy::evaluate(
        &state.authority,
        &req.mandate,
        &req.signature,
        req.amount_minor,
        &allowed_merchants,
        &state.db,
    );

    let (label, mut reason) = match &decision {
        Decision::Allow { reason } => ("ALLOW", reason.clone()),
        Decision::Reject { reason } => ("REJECT", reason.clone()),
    };

    let mut order_id = None;
    if matches!(decision, Decision::Allow { .. }) {
        if let Ok(Some(cached)) = state.db.get_cached_order(&req.mandate.mandate_id) {
            order_id = Some(cached);
            reason = format!("{reason} (idempotent replay: cached order returned)");
        } else {
            match state
                .gateway
                .create_order(&req.mandate, req.amount_minor)
                .await
            {
                Ok(order) => {
                    let _ =
                        state
                            .db
                            .cache_order(&req.mandate.mandate_id, &order.id, req.amount_minor);
                    order_id = Some(order.id);
                }
                Err(e) => reason = format!("{reason}; gateway: {e}"),
            }
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
        gateway: state.gateway.label().into(),
    }))
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

#[derive(Deserialize)]
struct ListParams {
    limit: Option<i64>,
}

async fn list_decisions(
    State(state): State<SharedState>,
    Query(params): Query<ListParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let rows = state
        .db
        .list_recent(limit)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!({ "decisions": rows })))
}

async fn ledger_stats(
    State(state): State<SharedState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let stats = state
        .db
        .stats()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!(stats)))
}

async fn dashboard() -> impl IntoResponse {
    let html = include_str!("../dashboard/index.html");
    Html(html)
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let authority = Authority::from_seed(mandates::load_seed());
    eprintln!("authority public key: {}", authority.public_key_b64());

    let gateway = Gateway::from_env();
    let db = Db::open("mandatepay.db").expect("failed to open sqlite ledger");
    let api_key = resolve_api_key();
    let max_mandate_cap = parse_max_cap();
    eprintln!(
        "mandate cap: {} paise (₹{:.2})",
        max_mandate_cap,
        max_mandate_cap as f64 / 100.0
    );
    let state = Arc::new(AppState {
        authority,
        db,
        gateway,
        allowed_merchants: parse_allowlist(),
        api_key: api_key.clone(),
        max_mandate_cap,
    });

    let protected = Router::new()
        .route("/v1/mandates", post(issue))
        .route("/v1/checkout", post(checkout))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/v1/decisions", get(list_decisions))
        .route("/v1/stats", get(ledger_stats))
        .merge(protected)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("port 8080 already in use");
    eprintln!("listening on http://{addr}");
    axum::serve(listener, app).await.expect("server crashed");
}
