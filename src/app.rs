use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderValue, Method},
    middleware::Next,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use validator::Validate;

use crate::{
    auth::{extract_api_key, verify_api_key},
    error::AppError,
    gateway::{Gateway, GatewayError},
    mandates::{self, Authority, Mandate},
    policy::{self, Decision},
    store::Db,
};

/// True for a duplicate-receipt failure from `create_order`: either the
/// distinct `DuplicateReceipt` variant or a Razorpay 400 whose body names a
/// duplicate receipt. Used to fall back to `find_order_by_receipt` + adopt
/// after a reclaim race instead of rolling back and double-creating.
fn is_duplicate_receipt_err(e: &GatewayError) -> bool {
    match e {
        GatewayError::DuplicateReceipt(_) => true,
        GatewayError::Api(msg) if msg.to_lowercase().contains("duplicate") => true,
        _ => false,
    }
}

/// Four different caps — similar names, different owners:
/// - `Mandate.max_amount_minor`: per-mandate spend ceiling, signed by the authority.
/// - `AgentPolicy.max_cap`: per-agent ceiling, set by the admin; checkout enforces
///   `amount <= mandate cap <= agent cap`.
/// - `AppState.max_mandate_cap` (`MANDATEPAY_MAX_CAP`): server-wide ceiling on issuance.
/// - `AGENT_BUDGET_MINOR`: the buyer agent's own wallet env var (client-side only).
pub struct AppState {
    pub authority: Authority,
    pub db: Db,
    pub gateway: Gateway,
    /// Master/admin key for `/v1/agents*` management only; never valid for mandates/checkout.
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
    // M5: warn on garbage instead of silently falling back to 100000.
    match std::env::var("MANDATEPAY_MAX_CAP") {
        Ok(v) if !v.trim().is_empty() => match v.trim().parse::<u64>() {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(value = %v, "MANDATEPAY_MAX_CAP invalid, falling back to 100000");
                100_000
            }
        },
        _ => 100_000,
    }
}

/// Background prune cadence (`MANDATEPAY_PRUNE_INTERVAL_SECS`, default hourly).
/// Garbage or zero falls back to `DEFAULT_PRUNE_INTERVAL_SECS` with a warning.
pub fn parse_prune_interval_secs() -> u64 {
    match std::env::var("MANDATEPAY_PRUNE_INTERVAL_SECS") {
        Ok(v) if !v.trim().is_empty() => match v.trim().parse::<u64>() {
            Ok(n) if n > 0 => n,
            _ => {
                tracing::warn!(value = %v, "MANDATEPAY_PRUNE_INTERVAL_SECS invalid, falling back to 3600");
                crate::store::DEFAULT_PRUNE_INTERVAL_SECS
            }
        },
        _ => crate::store::DEFAULT_PRUNE_INTERVAL_SECS,
    }
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
fn mandate_payload_json(mandate: &Mandate) -> Result<String, AppError> {
    // Audit payloads must never silently become "" on serialization failure.
    serde_json::to_string(mandate)
        .map_err(|e| AppError::Internal(format!("mandate serialization failed: {e}")))
}

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

/// The authority is intentionally a dumb signer: it authenticates the AGENT
/// (per-agent key) but does NOT consult that agent's allowlist/caps — those are
/// checkout-time policy. So a signed mandate may still REJECT at checkout; sign
/// only what you intend the agent to be able to spend within its current policy.
pub async fn issue(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<IssueRequest>,
) -> Result<Json<Issued>, AppError> {
    // C1: per-agent key must belong to the body agent_id. Master key does NOT work here.
    require_agent_key(&state.db, &headers, &req.agent_id)?;
    req.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    // H4: length validator runs on the raw string, so whitespace-only ids pass
    // it and trim to empty. Reject after trimming to avoid issuing mandates
    // that can never be spent.
    if req.agent_id.trim().is_empty() || req.merchant_id.trim().is_empty() {
        return Err(AppError::BadRequest(
            "agent_id and merchant_id are required".into(),
        ));
    }
    if req.currency != "INR" {
        return Err(AppError::BadRequest("currency not supported".into()));
    }
    if req.max_amount_minor > i64::MAX as u64 {
        return Err(AppError::BadRequest("amount exceeds maximum".into()));
    }
    if req.max_amount_minor > state.max_mandate_cap {
        return Err(AppError::BadRequest("amount exceeds server policy".into()));
    }

    let now = mandates::unix_now();
    let mandate = Mandate {
        version: 1,
        mandate_id: mandates::try_new_token("mnd_", 9)
            .map_err(|e| AppError::Internal(e.to_string()))?,
        agent_id: req.agent_id.trim().to_string(),
        merchant_id: req.merchant_id.trim().to_string(),
        action: "create_order".into(),
        currency: "INR".into(),
        max_amount_minor: req.max_amount_minor,
        issued_at: now,
        expires_at: now
            .checked_add(req.ttl_secs)
            .ok_or_else(|| AppError::BadRequest("ttl_secs overflow".into()))?,
        nonce: mandates::try_new_token("n_", 16).map_err(|e| AppError::Internal(e.to_string()))?,
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
            &mandate_payload_json(&mandate)?,
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
        return Err(AppError::BadRequest("amount exceeds maximum".into()));
    }
    if req.mandate.max_amount_minor > i64::MAX as u64 {
        return Err(AppError::BadRequest("amount exceeds maximum".into()));
    }
    let agent_id = req.mandate.agent_id.trim();
    if agent_id.is_empty() {
        return Err(AppError::BadRequest(
            "agent_id and merchant_id are required".into(),
        ));
    }

    // H2: unknown agents fall back to the same defaults as get_or_create_agent
    // (previously the looser server cap). Unreachable in practice — checkout
    // auth already requires a keyed row — but must not disagree when it fires.
    let agent_policy = state.db.get_agent_policy(agent_id)?.unwrap_or_else(|| {
        let allow = parse_allowlist();
        crate::store::AgentPolicy {
            agent_id: agent_id.to_string(),
            max_cap: crate::store::DEFAULT_AGENT_MAX_CAP,
            velocity_limit: crate::store::DEFAULT_VELOCITY_LIMIT,
            velocity_window_secs: crate::store::DEFAULT_VELOCITY_WINDOW_SECS,
            allowed_merchants: allow,
        }
    });

    if req.mandate.max_amount_minor > agent_policy.max_cap {
        // Generic: exact per-agent caps stay server-side (no policy oracle).
        let reason = "amount exceeds agent policy".to_string();
        state.db.record_decision(
            "/v1/checkout",
            "REJECT",
            &reason,
            &mandate_payload_json(&req.mandate)?,
        )?;
        return Ok(Json(DecisionResponse {
            decision: "REJECT".into(),
            reason,
            order_id: None,
            gateway: state.gateway.label().into(),
        }));
    }
    if req.amount_minor > agent_policy.max_cap {
        // Generic: exact per-agent caps stay server-side (no policy oracle).
        let reason = "amount exceeds agent policy".to_string();
        state.db.record_decision(
            "/v1/checkout",
            "REJECT",
            &reason,
            &mandate_payload_json(&req.mandate)?,
        )?;
        return Ok(Json(DecisionResponse {
            decision: "REJECT".into(),
            reason,
            order_id: None,
            gateway: state.gateway.label().into(),
        }));
    }

    let allowed_merchants = agent_policy.allowed_merchants.clone();

    // H11: idempotency early-cache reuses the shared stateless validator (no nonce
    // side effect) plus agent-cap and amount==cached checks. A forged request
    // cannot hit a stale ALLOW cache because validate_stateless covers
    // signature/expiry/scope/allowlist/amount.
    if let Ok(Some((cached_id, cached_amount))) = state
        .db
        .get_cached_order_with_amount(&req.mandate.mandate_id)
    {
        let stateless_ok = matches!(
            policy::validate_stateless(
                &state.authority,
                &req.mandate,
                &req.signature,
                req.amount_minor,
                &allowed_merchants,
            ),
            Decision::Allow { .. }
        );
        let cap_ok = req.amount_minor <= agent_policy.max_cap
            && req.mandate.max_amount_minor <= agent_policy.max_cap;
        // Amount must match the cached order, otherwise fall through to nonce replay.
        if stateless_ok && cap_ok && req.amount_minor == cached_amount {
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

    // Stale-pending reclaim for an identical retry (same mandate_id + nonce +
    // amount) whose original attempt crashed after reserving. evaluate() failed
    // at the nonce claim, so we never reached reservation. Only the identical
    // owner may proceed; a DIFFERENT mandate reusing a consumed nonce
    // (different mandate_id, or nonce/amount mismatch) stays REJECT and its
    // nonce row is never freed. A stale row is NEVER reclaimed blindly: we
    // always call find_order_by_receipt first (no DB lock held across await).
    let mut reclaimed_fresh = false;
    if matches!(&decision, Decision::Replay { .. }) {
        let now = mandates::unix_now();
        if let Ok(Some(info)) = state.db.get_pending_info(&req.mandate.mandate_id) {
            let identical = info.nonce == req.mandate.nonce && info.amount == req.amount_minor;
            if identical && Db::is_pending_stale(&info, now) {
                match state
                    .gateway
                    .find_order_by_receipt(&req.mandate.mandate_id)
                    .await
                {
                    Ok(Some(order)) => {
                        if order.amount == req.amount_minor {
                            let adopt_reason = "reclaimed stale pending: adopted gateway order";
                            match state
                                .db
                                .finalize_reserved_order(&req.mandate.mandate_id, &order.id)
                            {
                                Ok(true) => {
                                    // We won the pending -> completed CAS: only
                                    // this caller records the audit row.
                                    let payload = mandate_payload_json(&req.mandate)?;
                                    state
                                        .db
                                        .record_decision(
                                            "/v1/checkout",
                                            "ALLOW",
                                            adopt_reason,
                                            &payload,
                                        )
                                        .map_err(|e| AppError::Internal(e.to_string()))?;
                                }
                                Ok(false) => {
                                    // A concurrent identical retry already
                                    // adopted and recorded this same order;
                                    // return the same ALLOW without a second row.
                                }
                                Err(e) => {
                                    return Err(AppError::Internal(format!(
                                        "failed to finalize adopted order: {e}"
                                    )));
                                }
                            }
                            return Ok(Json(DecisionResponse {
                                decision: "ALLOW".into(),
                                reason: adopt_reason.into(),
                                order_id: Some(order.id),
                                gateway: state.gateway.label().into(),
                            }));
                        }
                        // Amount mismatch on adopt: stay with the nonce REJECT below.
                    }
                    Ok(None) => {
                        match state.db.cas_reclaim_pending(
                            &req.mandate.mandate_id,
                            info.reserved_at,
                            req.amount_minor,
                            &req.mandate.nonce,
                            now,
                        ) {
                            Ok(true) => {
                                // Won the CAS: we now own a fresh pending row
                                // for the identical retry. The original nonce
                                // row (same value) stays claimed by us and the
                                // original velocity charge stays; do not
                                // recharge either.
                                reclaimed_fresh = true;
                                decision = Decision::Allow {
                                    reason: "signature, scope, merchant, amount, expiry and replay checks passed (stale pending reclaimed)".into(),
                                };
                            }
                            Ok(false) => {
                                // Lost to a concurrent identical retry; its
                                // row is now fresh. Stay REJECT (no nonce free,
                                // no velocity touch — the shared nonce row
                                // belongs to the winner too).
                            }
                            Err(e) => return Err(AppError::Internal(e.to_string())),
                        }
                    }
                    Err(_) => {
                        // Lookup error or DuplicateReceipt: leave pending,
                        // retryable 503, create NO order, free nothing.
                        return Err(AppError::ServiceUnavailable(
                            "gateway lookup unavailable, retry later".into(),
                        ));
                    }
                }
            }
        }
    }

    // Velocity: if policy Allow but velocity exceeded, override to Reject.
    // Nonce was already claimed inside evaluate() -> rollback so the mandate remains retryable
    // after the velocity window. This is intentional: velocity is a rate limit, not a mandate
    // validity verdict. Without rollback, a velocity-rejected mandate could never be retried
    // even after the window cleared, which would be surprising. Documented behavior: velocity
    // rejections are retryable; gateway failures also rollback for same reason.
    // Keep the exact window charged so later refunds (gateway/duplicate) hit
    // that row even if the clock rolled to a new window in between.
    // A reclaimed identical retry keeps its original velocity charge and must
    // not be charged a second time.
    let mut velocity_window: Option<u64> = None;
    if matches!(decision, Decision::Allow { .. }) && !reclaimed_fresh {
        let outcome = state.db.check_velocity(agent_id)?;
        velocity_window = Some(outcome.window_start);
        if !outcome.allowed {
            if let Err(e) = state.db.rollback_nonce(&req.mandate.nonce) {
                tracing::error!(error = %e, nonce = %req.mandate.nonce, "failed to roll back nonce after velocity rejection");
            }
            decision = Decision::Reject {
                reason: format!("velocity limit exceeded for agent {}", agent_id),
            };
        }
    }

    let (mut label, mut reason) = match &decision {
        Decision::Allow { reason } => ("ALLOW", reason.clone()),
        Decision::Reject { reason } => ("REJECT", reason.clone()),
        Decision::Replay { reason } => ("REJECT", reason.clone()),
    };

    let mut order_id = None;
    // Winner-path decision is recorded inside the spawned gateway task (not
    // here) so a client disconnect mid-await still leaves exactly one audit
    // row. When true, the final `record_decision` below must be skipped.
    let mut winner_decision_recorded = false;
    if matches!(decision, Decision::Allow { .. }) {
        // Second cache check: another concurrent Allow may have just completed and cached.
        // Re-validate stateless gates + caps (policy may have changed between evaluate
        // and here) and require amount match.
        let second_cached = state
            .db
            .get_cached_order_with_amount(&req.mandate.mandate_id)
            .ok()
            .flatten();
        if let Some((cached_id, cached_amount)) = second_cached
            && req.amount_minor == cached_amount
            && matches!(
                policy::validate_stateless(
                    &state.authority,
                    &req.mandate,
                    &req.signature,
                    req.amount_minor,
                    &allowed_merchants,
                ),
                Decision::Allow { .. }
            )
            && req.amount_minor <= agent_policy.max_cap
            && req.mandate.max_amount_minor <= agent_policy.max_cap
        {
            order_id = Some(cached_id);
            reason = format!("{reason} (idempotent replay: cached order returned)");
        }
        if order_id.is_none() {
            // C4: atomic PENDING reservation *before* gateway call.
            // INSERT OR IGNORE with PRIMARY KEY on mandate_id guarantees only one concurrent
            // writer wins the reservation; losers see `false` and must not call gateway.
            // The owner nonce is stored so a later identical retry can prove
            // ownership during stale reclaim (see above). A reclaimed retry
            // already owns a fresh pending row via CAS and skips this step.
            let (reserved, _) = if reclaimed_fresh {
                (true, None)
            } else {
                state.db.try_reserve_with_nonce(
                    &req.mandate.mandate_id,
                    req.amount_minor,
                    &req.mandate.nonce,
                )?
            };
            if !reserved {
                // Lost reservation: someone else owns this mandate_id. If they already completed,
                // return their cached order as idempotent replay (only if amount matches);
                // otherwise we're racing a pending order still being created -> reject as duplicate.
                if let Ok(Some((cached_id, cached_amount))) = state
                    .db
                    .get_cached_order_with_amount(&req.mandate.mandate_id)
                {
                    let still_valid = matches!(
                        policy::validate_stateless(
                            &state.authority,
                            &req.mandate,
                            &req.signature,
                            req.amount_minor,
                            &allowed_merchants,
                        ),
                        Decision::Allow { .. }
                    ) && req.amount_minor <= agent_policy.max_cap
                        && req.mandate.max_amount_minor <= agent_policy.max_cap;
                    if req.amount_minor == cached_amount && still_valid {
                        order_id = Some(cached_id);
                        reason = format!("{reason} (idempotent replay: cached order returned)");
                    } else {
                        if let Err(e) = state.db.rollback_nonce(&req.mandate.nonce) {
                            tracing::error!(error = %e, nonce = %req.mandate.nonce, "failed to roll back nonce after duplicate in-flight amount mismatch");
                        }
                        // Velocity was charged before the reservation race;
                        // no order was placed, so refund the exact window charged.
                        if let Some(window_start) = velocity_window
                            && let Err(e) = state.db.refund_velocity(agent_id, window_start)
                        {
                            tracing::error!(error = %e, "failed to refund velocity after duplicate in-flight amount mismatch");
                        }
                        label = "REJECT";
                        reason = "duplicate mandate_id: order already in flight (amount or policy mismatch)"
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
                    // Velocity was charged before the reservation race;
                    // no order was placed, so refund the exact window charged.
                    if let Some(window_start) = velocity_window
                        && let Err(e) = state.db.refund_velocity(agent_id, window_start)
                    {
                        tracing::error!(error = %e, "failed to refund velocity after duplicate in-flight rejection");
                    }
                    // Note: we do not clear the winner's pending; winner will finalize.
                    label = "REJECT";
                    reason = "duplicate mandate_id: order already in flight".into();
                }
            } else {
                // Phase3 cancel-safety: run gateway + finalize/rollback +
                // record_decision in a spawned task so a decision row is
                // written for every outcome (success and gateway failure)
                // even when the client disconnects and axum drops this
                // handler future mid-await. The task owns a drop-guard that
                // rolls back pending/nonce/velocity on panic; normal paths
                // disarm it after explicit cleanup. No DB mutex is held
                // across the gateway `.await`: the mutex is only locked
                // inside each short synchronous `Db` call before/after it.
                // The JoinHandle carries (label, reason, order_id) back so
                // the handler can respond without a second DB write.
                struct PendingGuard {
                    state: Arc<AppState>,
                    mandate_id: String,
                    nonce: String,
                    agent_id: String,
                    window_start: Option<u64>,
                    armed: bool,
                }
                impl Drop for PendingGuard {
                    fn drop(&mut self) {
                        if self.armed {
                            let _ = self.state.db.clear_pending_order(&self.mandate_id);
                            let _ = self.state.db.rollback_nonce(&self.nonce);
                            if let Some(window_start) = self.window_start {
                                let _ = self.state.db.refund_velocity(&self.agent_id, window_start);
                            }
                        }
                    }
                }
                let task_state = Arc::clone(&state);
                let task_mandate = req.mandate.clone();
                let task_amount = req.amount_minor;
                let task_mandate_id = req.mandate.mandate_id.clone();
                let task_nonce = req.mandate.nonce.clone();
                let task_agent = agent_id.to_string();
                let task_window = velocity_window;
                let task_payload = mandate_payload_json(&req.mandate)?;
                let task_reason_base = reason.clone();
                let task_reclaimed = reclaimed_fresh;
                let join = tokio::spawn(async move {
                    let mut guard = PendingGuard {
                        state: Arc::clone(&task_state),
                        mandate_id: task_mandate_id.clone(),
                        nonce: task_nonce.clone(),
                        agent_id: task_agent.clone(),
                        window_start: task_window,
                        armed: true,
                    };
                    let result = task_state
                        .gateway
                        .create_order(&task_mandate, task_amount)
                        .await;
                    match result {
                        Ok(order) => {
                            if let Err(e) = task_state
                                .db
                                .finalize_reserved_order(&task_mandate_id, &order.id)
                            {
                                tracing::error!(error = %e, mandate_id = %task_mandate_id, "failed to finalize reserved order after gateway success");
                            }
                            guard.armed = false;
                            let task_label = "ALLOW";
                            let decision_reason = task_reason_base;
                            if let Err(e) = task_state.db.record_decision(
                                "/v1/checkout",
                                task_label,
                                &decision_reason,
                                &task_payload,
                            ) {
                                tracing::error!(error = %e, mandate_id = %task_mandate_id, "failed to record decision after gateway success");
                            }
                            (task_label.to_string(), decision_reason, Some(order.id))
                        }
                        Err(e) => {
                            // Reclaim race: our create hit a duplicate receipt
                            // because the gateway already holds an order for
                            // this receipt (concurrent winner). Fall back to
                            // find + adopt instead of rolling back.
                            if task_reclaimed
                                && is_duplicate_receipt_err(&e)
                                && let Ok(Some(found)) = task_state
                                    .gateway
                                    .find_order_by_receipt(&task_mandate_id)
                                    .await
                            {
                                if let Err(fin_err) = task_state
                                    .db
                                    .finalize_reserved_order(&task_mandate_id, &found.id)
                                {
                                    tracing::error!(error = %fin_err, mandate_id = %task_mandate_id, "failed to finalize adopted order after duplicate create");
                                }
                                guard.armed = false;
                                let task_label = "ALLOW";
                                let decision_reason = format!(
                                    "{task_reason_base} (reclaimed stale pending: adopted gateway order)"
                                );
                                if let Err(record_err) = task_state.db.record_decision(
                                    "/v1/checkout",
                                    task_label,
                                    &decision_reason,
                                    &task_payload,
                                ) {
                                    tracing::error!(error = %record_err, mandate_id = %task_mandate_id, "failed to record decision after duplicate adopt");
                                }
                                return (task_label.to_string(), decision_reason, Some(found.id));
                            }
                            if let Err(rollback_err) =
                                task_state.db.clear_pending_order(&task_mandate_id)
                            {
                                tracing::error!(error = %rollback_err, mandate_id = %task_mandate_id, "failed to clear pending order after gateway failure");
                            }
                            if let Err(rollback_err) = task_state.db.rollback_nonce(&task_nonce) {
                                tracing::error!(error = %rollback_err, nonce = %task_nonce, "failed to roll back nonce after gateway failure");
                            }
                            // Velocity was charged before the gateway call; the
                            // order never happened, so refund the exact window charged.
                            // Reclaimed retries never charged (original charge
                            // stays), so `task_window` is None and this is a no-op.
                            if let Some(window_start) = task_window
                                && let Err(rollback_err) =
                                    task_state.db.refund_velocity(&task_agent, window_start)
                            {
                                tracing::error!(error = %rollback_err, "failed to refund velocity after gateway failure");
                            }
                            guard.armed = false;
                            let task_label = "REJECT";
                            let decision_reason = format!("{task_reason_base}; gateway: {e}");
                            if let Err(record_err) = task_state.db.record_decision(
                                "/v1/checkout",
                                task_label,
                                &decision_reason,
                                &task_payload,
                            ) {
                                tracing::error!(error = %record_err, mandate_id = %task_mandate_id, "failed to record decision after gateway failure");
                            }
                            (task_label.to_string(), decision_reason, None)
                        }
                    }
                });
                match join.await {
                    Ok((task_label, task_reason, task_order)) => {
                        if task_label == "ALLOW" {
                            label = "ALLOW";
                        } else {
                            label = "REJECT";
                        }
                        reason = task_reason;
                        order_id = task_order;
                        winner_decision_recorded = true;
                    }
                    Err(_) => {
                        // Spawned task panicked; its drop-guard already rolled
                        // back pending/nonce/velocity. Map to a generic 500
                        // without leaking internals (no oracle).
                        return Err(AppError::Internal("internal error".into()));
                    }
                }
            }
        }
    }

    // Winner path already recorded its decision inside the spawned task
    // (cancel-safe); all other paths record here exactly once.
    if !winner_decision_recorded {
        state
            .db
            .record_decision(
                "/v1/checkout",
                label,
                &reason,
                &mandate_payload_json(&req.mandate)?,
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    Ok(Json(DecisionResponse {
        decision: label.into(),
        reason,
        order_id,
        gateway: state.gateway.label().into(),
    }))
}

/// Public liveness probe for orchestrators/CI. The `gateway` label (`mock` vs
/// `razorpay-test`) is operational, not secret: it reveals only whether live
/// keys are configured, never key material. Intentionally unauthenticated.
pub async fn health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "gateway": state.gateway.label() }))
}

/// H5: redact mandate nonces in public decision reads. Callers presenting a valid
/// master key see full payloads; unauthenticated callers (dashboard) see payloads
/// with `nonce` replaced by a prefix, preventing bulk nonce harvesting while
/// keeping the demo readable.
fn redact_payload(payload: &str, authed: bool) -> String {
    if authed {
        return payload.to_string();
    }
    match serde_json::from_str::<serde_json::Value>(payload) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut()
                && let Some(nonce) = obj
                    .get("nonce")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string())
            {
                let prefix: String = nonce.chars().take(4).collect();
                obj.insert(
                    "nonce".to_string(),
                    serde_json::Value::String(format!("{prefix}…(redacted)")),
                );
                return serde_json::to_string(&v).unwrap_or_else(|_| payload.to_string());
            }
            payload.to_string()
        }
        Err(_) => payload.to_string(),
    }
}

fn is_master(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    extract_api_key(headers)
        .map(|k| verify_api_key(&k, &state.api_key))
        .unwrap_or(false)
}

#[derive(Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
}

pub async fn list_decisions(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<ListParams>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let authed = is_master(&state, &headers);
    let rows = state
        .db
        .list_recent(limit)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let redacted: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|mut r| {
            r.payload = redact_payload(&r.payload, authed);
            serde_json::to_value(&r).unwrap_or(serde_json::Value::Null)
        })
        .collect();
    Ok(Json(json!({ "decisions": redacted })))
}

/// Backwards-compat alias `/v1/metrics` serves this same handler; both are public.
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
    headers: axum::http::HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let authed = is_master(&state, &headers);
    let row = state
        .db
        .get_decision(id)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    match row {
        Some(mut r) => {
            r.payload = redact_payload(&r.payload, authed);
            Ok(Json(json!(r)))
        }
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

/// Intentionally public and keyless: pure signature check over caller-supplied
/// bytes, no state access, no key oracle beyond what checkout already reveals
/// (a forged mandate fails checkout identically with or without this endpoint).
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
    // Defaults differ deliberately: decisions default 50 (high-volume ledger),
    // agents default 100 (low-cardinality registry). Both clamp to 1..=200.
    let limit = params.limit.unwrap_or(100).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);
    // H1: filter AND sort in SQL before LIMIT/OFFSET so pages reflect the
    // globally-sorted filtered set (sort-after-paginate returned wrong pages).
    // Unknown sort/order are 400, not silent defaults (typos must not look fine).
    let sort = params.sort.as_deref().unwrap_or("agent_id");
    if !matches!(sort, "agent_id" | "max_cap" | "velocity_limit") {
        return Err(AppError::BadRequest(format!("unknown sort field '{sort}'")));
    }
    let order_raw = params.order.as_deref().unwrap_or("asc");
    let desc = if order_raw.eq_ignore_ascii_case("desc") {
        true
    } else if order_raw.eq_ignore_ascii_case("asc") {
        false
    } else {
        return Err(AppError::BadRequest(format!("unknown order '{order_raw}'")));
    };
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
    // Normalize like create/get so " foo " and "foo" address one agent.
    let id = id.trim().to_string();
    if id.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
    if let Some(v) = req.max_cap {
        if v == 0 {
            return Err(AppError::BadRequest("max_cap must be positive".into()));
        }
        if v > i64::MAX as u64 {
            return Err(AppError::BadRequest("agent cap exceeds maximum".into()));
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
            "velocity window exceeds maximum".into(),
        ));
    }
    // Absurd windows would never reset; store re-checks (InvalidParameterName -> 400).
    if let Some(v) = req.velocity_window_secs
        && v > crate::store::MAX_VELOCITY_WINDOW_SECS
    {
        return Err(AppError::BadRequest(format!(
            "velocity_window_secs must be 1..={}",
            crate::store::MAX_VELOCITY_WINDOW_SECS
        )));
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
    // Normalize like create/get so " foo " and "foo" address one agent.
    let id = id.trim().to_string();
    if id.is_empty() {
        return Err(AppError::BadRequest("agent_id required".into()));
    }
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
            return Err(AppError::BadRequest("agent cap exceeds maximum".into()));
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
            "velocity window exceeds maximum".into(),
        ));
    }
    // Absurd windows would never reset; store re-checks (InvalidParameterName -> 400).
    if let Some(v) = req.velocity_window_secs
        && v > crate::store::MAX_VELOCITY_WINDOW_SECS
    {
        return Err(AppError::BadRequest(format!(
            "velocity_window_secs must be 1..={}",
            crate::store::MAX_VELOCITY_WINDOW_SECS
        )));
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

// Allow https://*.vercel.app frontend to call this API when deployed separately.
// Permissive * is intentional for Buildathon demo; tighten to exact origin in prod.
async fn cors_middleware(req: Request, next: Next) -> impl IntoResponse {
    if req.method() == Method::OPTIONS {
        return (
            [
                ("access-control-allow-origin", "*"),
                (
                    "access-control-allow-methods",
                    "GET,POST,PATCH,DELETE,OPTIONS",
                ),
                (
                    "access-control-allow-headers",
                    "content-type,authorization,x-api-key",
                ),
                ("access-control-max-age", "86400"),
            ],
            "",
        )
            .into_response();
    }
    let mut res = next.run(req).await.into_response();
    let h = res.headers_mut();
    h.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    h.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("GET,POST,PATCH,DELETE,OPTIONS"),
    );
    h.insert(
        "access-control-allow-headers",
        HeaderValue::from_static("content-type,authorization,x-api-key"),
    );
    res
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
        .layer(axum::middleware::from_fn(cors_middleware))
        .with_state(state)
}
