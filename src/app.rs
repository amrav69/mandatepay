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

/// Master key (admin): gates `/v1/agents*` management endpoints only.
/// Per-agent keys gate `POST /v1/mandates` and `POST /v1/checkout` via
/// `require_agent_key` inside those handlers (needs the body `agent_id`).
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

/// C1: verify the caller presents the per-agent key for `agent_id`.
/// 401 when missing/unknown, 403 on mismatch for a known agent.
fn require_agent_key(
    db: &Db,
    headers: &axum::http::HeaderMap,
    agent_id: &str,
) -> Result<(), AppError> {
    let agent = agent_id.trim();
    if agent.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
    let Some(provided) = extract_api_key(headers) else {
        return Err(AppError::Unauthorized("missing agent API key".into()));
    };
    let ok = db
        .verify_agent_key(agent, &provided)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if ok {
        return Ok(());
    }
    let known = db
        .get_agent_policy(agent)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .is_some();
    if known {
        Err(AppError::Forbidden("invalid API key for this agent".into()))
    } else {
        Err(AppError::Unauthorized(
            "unknown agent or missing key; create via POST /v1/agents with master key".into(),
        ))
    }
}

pub async fn issue(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<IssueRequest>,
) -> Result<Json<Issued>, AppError> {
    // C1: per-agent key must belong to the body agent_id. Master key does NOT work here.
    require_agent_key(&state.db, &headers, &req.agent_id)?;
    req.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    if req.currency != "INR" {
        return Err(AppError::BadRequest(
            "only INR mandates are supported".into(),
        ));
    }
    if req.max_amount_minor > i64::MAX as u64 {
        return Err(AppError::BadRequest(
            "max_amount_minor exceeds i64::MAX".into(),
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
    headers: axum::http::HeaderMap,
    Json(req): Json<CheckoutRequest>,
) -> Result<Json<DecisionResponse>, AppError> {
    req.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    // C1: per-agent key must belong to the mandate's agent_id. Master key does NOT work here.
    // Ed25519 signature (what) verified inside `policy::evaluate` next.
    require_agent_key(&state.db, &headers, &req.mandate.agent_id)?;
    if req.amount_minor > i64::MAX as u64 {
        return Err(AppError::BadRequest("amount_minor exceeds i64::MAX".into()));
    }
    if req.mandate.max_amount_minor > i64::MAX as u64 {
        return Err(AppError::BadRequest(
            "mandate max_amount_minor exceeds i64::MAX".into(),
        ));
    }
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

    if req.mandate.max_amount_minor > agent_policy.max_cap {
        let reason = format!(
            "mandate cap {} exceeds agent cap {}",
            req.mandate.max_amount_minor, agent_policy.max_cap
        );
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
    if req.amount_minor > agent_policy.max_cap {
        let reason = format!(
            "amount {} exceeds agent cap {}",
            req.amount_minor, agent_policy.max_cap
        );
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

    let allowed_merchants = agent_policy.allowed_merchants.clone();

    // Idempotency: same mandate_id already succeeded once — return cached order without
    // re-consuming nonce or velocity budget, but only after the current request has passed
    // the cheap authz gates that would be checked anyway:
    //   1) authority.verify (signature)  2) expires_at  3) agent cap (already checked above)
    // This ensures a forged/unverified request can't hit a stale ALLOW cache.
    if let Ok(Some((cached_id, cached_amount))) = state
        .db
        .get_cached_order_with_amount(&req.mandate.mandate_id)
    {
        let verify_ok = state.authority.verify(&req.mandate, &req.signature).is_ok();
        let not_expired = mandates::unix_now() < req.mandate.expires_at;
        let allowlist_ok = allowed_merchants
            .iter()
            .any(|m| m == &req.mandate.merchant_id);
        let amount_ok = req.amount_minor != 0
            && req.amount_minor <= req.mandate.max_amount_minor
            && req.amount_minor <= agent_policy.max_cap
            && req.mandate.max_amount_minor <= agent_policy.max_cap;
        // Fix #1: also verify the cached amount matches the current request — otherwise
        // the same mandate_id with a different (still valid) amount would silently return
        // the wrong order for the amount the caller specified.
        if verify_ok
            && not_expired
            && allowlist_ok
            && amount_ok
            && req.amount_minor == cached_amount
        {
            return Ok(Json(DecisionResponse {
                decision: "ALLOW".into(),
                reason: "idempotent replay: cached order returned".into(),
                order_id: Some(cached_id),
                gateway: state.gateway.label().into(),
            }));
        }
    }

    let mut decision = policy::evaluate(
        &state.authority,
        &req.mandate,
        &req.signature,
        req.amount_minor,
        &allowed_merchants,
        &state.db,
    );

    // Velocity: if policy Allow but velocity exceeded, override to Reject.
    // Nonce was already claimed inside evaluate() -> rollback so the mandate remains retryable
    // after the velocity window. This is intentional: velocity is a rate limit, not a mandate
    // validity verdict. Without rollback, a velocity-rejected mandate could never be retried
    // even after the window cleared, which would be surprising. Documented behavior: velocity
    // rejections are retryable; gateway failures also rollback for same reason.
    if matches!(decision, Decision::Allow { .. }) && !state.db.check_velocity(agent_id)? {
        if let Err(e) = state.db.rollback_nonce(&req.mandate.nonce) {
            tracing::error!(error = %e, nonce = %req.mandate.nonce, "failed to roll back nonce after velocity rejection");
        }
        decision = Decision::Reject {
            reason: format!("velocity limit exceeded for agent {}", agent_id),
        };
    }

    let (mut label, mut reason) = match &decision {
        Decision::Allow { reason } => ("ALLOW", reason.clone()),
        Decision::Reject { reason } => ("REJECT", reason.clone()),
    };

    let mut order_id = None;
    if matches!(decision, Decision::Allow { .. }) {
        // Second cache check: another concurrent Allow may have just completed and cached.
        // Also verify cached amount matches current request (fix #1).
        if let Ok(Some((cached_id, cached_amount))) = state
            .db
            .get_cached_order_with_amount(&req.mandate.mandate_id)
            && req.amount_minor == cached_amount
        {
            order_id = Some(cached_id);
            reason = format!("{reason} (idempotent replay: cached order returned)");
        }
        if order_id.is_none() {
            // C4: atomic PENDING reservation *before* gateway call.
            // INSERT OR IGNORE with PRIMARY KEY on mandate_id guarantees only one concurrent
            // writer wins the reservation; losers see `false` and must not call gateway.
            let reserved = state
                .db
                .try_reserve_order(&req.mandate.mandate_id, req.amount_minor)?;
            if !reserved {
                // Lost reservation: someone else owns this mandate_id. If they already completed,
                // return their cached order as idempotent replay (only if amount matches);
                // otherwise we're racing a pending order still being created -> reject as duplicate.
                if let Ok(Some((cached_id, cached_amount))) = state
                    .db
                    .get_cached_order_with_amount(&req.mandate.mandate_id)
                {
                    if req.amount_minor == cached_amount {
                        order_id = Some(cached_id);
                        reason = format!("{reason} (idempotent replay: cached order returned)");
                    } else {
                        if let Err(e) = state.db.rollback_nonce(&req.mandate.nonce) {
                            tracing::error!(error = %e, nonce = %req.mandate.nonce, "failed to roll back nonce after duplicate in-flight amount mismatch");
                        }
                        label = "REJECT";
                        reason = "duplicate mandate_id: order already in flight (amount mismatch)"
                            .into();
                    }
                } else if let Ok(Some(cached)) = state.db.get_cached_order(&req.mandate.mandate_id)
                {
                    // Fallback for legacy rows without amount
                    order_id = Some(cached);
                    reason = format!("{reason} (idempotent replay: cached order returned)");
                } else {
                    // Pending but not yet completed: treat as duplicate. Nonce was already
                    // claimed for the winner, this loser already consumed a nonce claim in
                    // evaluate (Allow) but lost the pending race -> rollback so it remains clear
                    // that the duplicate was not processed. The winner's order will become
                    // visible for subsequent retries via the early cache above.
                    if let Err(e) = state.db.rollback_nonce(&req.mandate.nonce) {
                        tracing::error!(error = %e, nonce = %req.mandate.nonce, "failed to roll back nonce after duplicate in-flight rejection");
                    }
                    // Note: we do not clear the winner's pending; winner will finalize.
                    label = "REJECT";
                    reason = "duplicate mandate_id: order already in flight".into();
                }
            } else {
                match state
                    .gateway
                    .create_order(&req.mandate, req.amount_minor)
                    .await
                {
                    Ok(order) => {
                        if let Err(e) = state
                            .db
                            .finalize_reserved_order(&req.mandate.mandate_id, &order.id)
                        {
                            tracing::error!(error = %e, mandate_id = %req.mandate.mandate_id, "failed to finalize reserved order after gateway success");
                        }
                        order_id = Some(order.id);
                    }
                    Err(e) => {
                        if let Err(rollback_err) =
                            state.db.clear_pending_order(&req.mandate.mandate_id)
                        {
                            tracing::error!(error = %rollback_err, mandate_id = %req.mandate.mandate_id, "failed to clear pending order after gateway failure");
                        }
                        if let Err(rollback_err) = state.db.rollback_nonce(&req.mandate.nonce) {
                            tracing::error!(error = %rollback_err, nonce = %req.mandate.nonce, "failed to roll back nonce after gateway failure");
                        }
                        reason = format!("{reason}; gateway: {e}");
                        label = "REJECT";
                    }
                }
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

pub async fn health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "gateway": state.gateway.label() }))
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

/// C1: returns flat policy; includes `api_key` plaintext only when newly minted
/// (first touch or legacy migration). Existing keyed agents omit it (unrecoverable).
pub async fn get_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
    let (policy, new_key) = state
        .db
        .get_or_create_agent(trimmed)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let mut v = serde_json::to_value(&policy).map_err(|e| AppError::Internal(e.to_string()))?;
    if let Some(k) = new_key {
        v["api_key"] = serde_json::Value::String(k);
        v["api_key_warning"] = serde_json::Value::String("store this key; it is shown once".into());
    }
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct AgentListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub q: Option<String>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

pub async fn list_agents(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AgentListParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = params.limit.unwrap_or(100).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);
    // H1: filter AND sort in SQL before LIMIT/OFFSET so pages reflect the
    // globally-sorted filtered set (sort-after-paginate returned wrong pages).
    let sort = params.sort.as_deref().unwrap_or("agent_id");
    let desc = params
        .order
        .as_deref()
        .unwrap_or("asc")
        .eq_ignore_ascii_case("desc");
    let agents = state
        .db
        .list_agents_paginated_filtered(limit, offset, params.q.as_deref(), sort, desc)
        .map_err(|e| AppError::Internal(e.to_string()))?;
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
    if let Some(v) = req.max_cap {
        if v == 0 {
            return Err(AppError::BadRequest("max_cap must be positive".into()));
        }
        if v > i64::MAX as u64 {
            return Err(AppError::BadRequest("max_cap exceeds i64::MAX".into()));
        }
    }
    if let Some(v) = req.velocity_limit
        && v == 0
    {
        return Err(AppError::BadRequest(
            "velocity_limit must be positive".into(),
        ));
    }
    if let Some(v) = req.velocity_window_secs
        && v == 0
    {
        return Err(AppError::BadRequest(
            "velocity_window_secs must be positive".into(),
        ));
    }
    // C3: reject wrap-around values at the HTTP layer too (store re-checks).
    if let Some(v) = req.velocity_window_secs
        && v > i64::MAX as u64
    {
        return Err(AppError::BadRequest(
            "velocity_window_secs exceeds i64::MAX".into(),
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
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("must be") || s.contains("exceeds") {
                AppError::BadRequest(s)
            } else {
                AppError::Internal(s)
            }
        })?;
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
    if let Some(v) = req.max_cap {
        if v == 0 {
            return Err(AppError::BadRequest("max_cap must be positive".into()));
        }
        if v > i64::MAX as u64 {
            return Err(AppError::BadRequest("max_cap exceeds i64::MAX".into()));
        }
    }
    if let Some(v) = req.velocity_limit
        && v == 0
    {
        return Err(AppError::BadRequest(
            "velocity_limit must be positive".into(),
        ));
    }
    if let Some(v) = req.velocity_window_secs
        && v == 0
    {
        return Err(AppError::BadRequest(
            "velocity_window_secs must be positive".into(),
        ));
    }
    // C3: reject wrap-around values at the HTTP layer too (store re-checks).
    if let Some(v) = req.velocity_window_secs
        && v > i64::MAX as u64
    {
        return Err(AppError::BadRequest(
            "velocity_window_secs exceeds i64::MAX".into(),
        ));
    }
    // Atomic: INSERT OR IGNORE returns 0 if already exists — no separate existence check (avoids TOCTOU).
    let (inserted, new_key) = state
        .db
        .try_create_agent(
            id,
            req.max_cap,
            req.velocity_limit,
            req.velocity_window_secs,
            req.allowed_merchants,
        )
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("must be") || s.contains("exceeds") {
                AppError::BadRequest(s)
            } else {
                AppError::Internal(s)
            }
        })?;
    if !inserted {
        return Err(AppError::BadRequest(format!("agent {id} already exists")));
    }
    let policy = state
        .db
        .get_agent_policy(id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::Internal("just inserted agent not found".into()))?;
    let mut v = serde_json::to_value(&policy).map_err(|e| AppError::Internal(e.to_string()))?;
    // C1: return per-agent key once. Admin must distribute it to the agent.
    if let Some(k) = new_key {
        v["api_key"] = serde_json::Value::String(k);
        v["api_key_warning"] = serde_json::Value::String("store this key; it is shown once".into());
    }
    Ok(Json(v))
}

/// C1: rotate an agent's key (master-gated). Returns new plaintext once.
pub async fn rotate_agent_key(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
    let key = state
        .db
        .rotate_agent_key(trimmed)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    match key {
        Some(k) => Ok(Json(json!({
            "agent_id": trimmed,
            "api_key": k,
            "warning": "store this key; it is shown once",
        }))),
        None => Err(AppError::NotFound(format!("agent {trimmed} not found"))),
    }
}

pub async fn dashboard() -> impl IntoResponse {
    let html = include_str!("../dashboard/index.html");
    Html(html)
}

pub fn build_router(state: Arc<AppState>) -> Router {
    // C1: agent-key routes do their own per-agent verification inside handlers
    // (they need the body agent_id), so they are NOT behind the master middleware.
    // C2: agent list requires the master key, matching single-agent reads.
    let master_protected = Router::new()
        .route("/v1/agents", post(create_agent).get(list_agents))
        .route(
            "/v1/agents/{id}",
            get(get_agent).patch(update_agent).delete(delete_agent),
        )
        .route("/v1/agents/{id}/rotate", post(rotate_agent_key))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));

    // Public reads: health + dashboard + ledger/stats for demo. In production, gate /v1/decisions/* and /v1/agents behind read-auth or a redacted view.
    Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/v1/mandates", post(issue))
        .route("/v1/checkout", post(checkout))
        .route("/v1/decisions", get(list_decisions))
        .route("/v1/decisions/{id}", get(get_decision))
        .route("/v1/decisions/{id}/verify", get(verify_decision))
        .route("/v1/verify", post(verify_mandate))
        .route("/v1/chain/verify", get(chain_verify))
        .route("/v1/stats", get(ledger_stats))
        .route("/v1/metrics", get(ledger_stats))
        .merge(master_protected)
        .with_state(state)
}
