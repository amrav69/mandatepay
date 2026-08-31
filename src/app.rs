use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use validator::Validate;

use crate::{
    auth::{extract_api_key, verify_api_key},
    error::AppError,
    gateway::Gateway,
    mandates::{self, Authority, Mandate},
    policy::{self, Decision},
    store::Db,
};

pub struct AppState {
    pub authority: Authority,
    pub db: Db,
    pub gateway: Gateway,
    pub api_key: String,
    pub max_mandate_cap: u64,
}

#[derive(Deserialize, Validate)]
pub struct IssueRequest {
    #[validate(length(min = 1, message = "agent_id required"))]
    pub agent_id: String,
    #[validate(length(min = 1, message = "merchant_id required"))]
    pub merchant_id: String,
    #[validate(length(equal = 3, message = "currency must be 3 chars"))]
    pub currency: String,
    #[validate(range(min = 1, message = "max_amount_minor must be positive"))]
    pub max_amount_minor: u64,
    #[validate(range(
        min = 60,
        max = 86400,
        message = "ttl_secs must be between 60 and 86400"
    ))]
    pub ttl_secs: u64,
}

#[derive(Serialize)]
pub struct Issued {
    pub mandate: Mandate,
    pub signature: String,
}

#[derive(Deserialize, Validate)]
pub struct CheckoutRequest {
    pub mandate: Mandate,
    pub signature: String,
    #[validate(range(min = 1, message = "amount_minor must be positive"))]
    pub amount_minor: u64,
}

#[derive(Serialize)]
pub struct DecisionResponse {
    pub decision: String,
    pub reason: String,
    pub order_id: Option<String>,
    pub gateway: String,
}

pub fn parse_allowlist() -> Vec<String> {
    std::env::var("ALLOWED_MERCHANTS")
        .unwrap_or_else(|_| "merchant-001".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn parse_max_cap() -> u64 {
    std::env::var("MANDATEPAY_MAX_CAP")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(100_000)
}

pub async fn require_api_key(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AppError> {
    let provided = extract_api_key(req.headers());
    match provided {
        Some(k) if verify_api_key(&k, &state.api_key) => Ok(next.run(req).await),
        _ => Err(AppError::Unauthorized("invalid or missing API key".into())),
    }
}

pub async fn issue(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<Issued>, AppError> {
    req.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    if req.currency != "INR" {
        return Err(AppError::BadRequest(
            "only INR mandates are supported".into(),
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

pub async fn checkout(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckoutRequest>,
) -> Result<Json<DecisionResponse>, AppError> {
    req.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    let agent_id = req.mandate.agent_id.trim();
    if agent_id.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }

    let agent_policy = state.db.get_agent_policy(agent_id)?.unwrap_or_else(|| {
        let allow = parse_allowlist();
        crate::store::AgentPolicy {
            agent_id: agent_id.to_string(),
            max_cap: state.max_mandate_cap,
            velocity_limit: 50,
            velocity_window_secs: 60,
            allowed_merchants: allow,
        }
    });

    let allowed_merchants = agent_policy.allowed_merchants.clone();

    let mut decision = policy::evaluate(
        &state.authority,
        &req.mandate,
        &req.signature,
        req.amount_minor,
        &allowed_merchants,
        &state.db,
    );

    if matches!(decision, Decision::Allow { .. }) {
        if !state.db.check_velocity(agent_id)? {
            decision = Decision::Reject {
                reason: format!("velocity limit exceeded for agent {}", agent_id),
            };
        }
    }

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

pub async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

#[derive(Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
}

pub async fn list_decisions(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let rows = state
        .db
        .list_recent(limit)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!({ "decisions": rows })))
}

pub async fn ledger_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let stats = state
        .db
        .stats()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!(stats)))
}

pub async fn get_decision(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = state
        .db
        .get_decision(id)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    match row {
        Some(r) => Ok(Json(json!(r))),
        None => Err(AppError::NotFound(format!("decision {id} not found"))),
    }
}

pub async fn verify_decision(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = state
        .db
        .get_decision(id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("decision {id} not found")))?;
    let chain_ok = state
        .db
        .verify_chain()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!({
        "id": row.id,
        "audit_hash": row.audit_hash,
        "prev_hash": row.prev_hash,
        "chain_valid": chain_ok,
        "decision": row.decision,
    })))
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub mandate: Mandate,
    pub signature: String,
}

pub async fn verify_mandate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    match state.authority.verify(&req.mandate, &req.signature) {
        Ok(()) => Ok(Json(
            json!({"valid": true, "reason": "signature verifies against mandate authority"}),
        )),
        Err(e) => Ok(Json(json!({"valid": false, "reason": e.to_string()}))),
    }
}

pub async fn chain_verify(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let ok = state
        .db
        .verify_chain()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!({"chain_valid": ok})))
}

pub async fn get_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let policy = state
        .db
        .get_or_create_agent(&id)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!(policy)))
}

#[derive(Deserialize)]
pub struct AgentListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub q: Option<String>,
}

pub async fn list_agents(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AgentListParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = params.limit.unwrap_or(100).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);
    let mut agents = state
        .db
        .list_agents_paginated(limit, offset)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if let Some(q) = params
        .q
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        let needle = q.to_lowercase();
        agents.retain(|a| a.agent_id.to_lowercase().contains(&needle));
    }
    Ok(Json(json!({ "agents": agents })))
}

#[derive(Deserialize)]
pub struct UpdateAgentRequest {
    pub max_cap: Option<u64>,
    pub velocity_limit: Option<u32>,
    pub velocity_window_secs: Option<u64>,
    pub allowed_merchants: Option<Vec<String>>,
}

pub async fn update_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAgentRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(v) = req.max_cap
        && v == 0
    {
        return Err(AppError::BadRequest("max_cap must be positive".into()));
    }
    if let Some(v) = req.velocity_limit
        && v == 0
    {
        return Err(AppError::BadRequest(
            "velocity_limit must be positive".into(),
        ));
    }
    let policy = state
        .db
        .update_agent(
            &id,
            req.max_cap,
            req.velocity_limit,
            req.velocity_window_secs,
            req.allowed_merchants,
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!(policy)))
}

pub async fn delete_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let deleted = state
        .db
        .delete_agent(&id)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if !deleted {
        return Err(AppError::NotFound(format!("agent {id} not found")));
    }
    Ok(Json(json!({"deleted": id})))
}

#[derive(Deserialize)]
pub struct CreateAgentRequest {
    pub agent_id: String,
    pub max_cap: Option<u64>,
    pub velocity_limit: Option<u32>,
    pub velocity_window_secs: Option<u64>,
    pub allowed_merchants: Option<Vec<String>>,
}

pub async fn create_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateAgentRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = req.agent_id.trim();
    if id.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
    if state.db.get_agent_policy(id)?.is_some() {
        return Err(AppError::BadRequest(format!("agent {id} already exists")));
    }
    if let Some(v) = req.max_cap
        && v == 0
    {
        return Err(AppError::BadRequest("max_cap must be positive".into()));
    }
    if let Some(v) = req.velocity_limit
        && v == 0
    {
        return Err(AppError::BadRequest(
            "velocity_limit must be positive".into(),
        ));
    }
    let policy = state
        .db
        .update_agent(
            id,
            req.max_cap,
            req.velocity_limit,
            req.velocity_window_secs,
            req.allowed_merchants,
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(json!(policy)))
}

pub async fn dashboard() -> impl IntoResponse {
    let html = include_str!("../dashboard/index.html");
    Html(html)
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/v1/mandates", post(issue))
        .route("/v1/checkout", post(checkout))
        .route("/v1/agents", post(create_agent))
        .route(
            "/v1/agents/{id}",
            get(get_agent).patch(update_agent).delete(delete_agent),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));

    Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/v1/decisions", get(list_decisions))
        .route("/v1/decisions/{id}", get(get_decision))
        .route("/v1/decisions/{id}/verify", get(verify_decision))
        .route("/v1/verify", post(verify_mandate))
        .route("/v1/chain/verify", get(chain_verify))
        .route("/v1/stats", get(ledger_stats))
        .route("/v1/metrics", get(ledger_stats))
        .route("/v1/agents", get(list_agents))
        .merge(protected)
        .with_state(state)
}
