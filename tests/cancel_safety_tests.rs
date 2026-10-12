#[allow(dead_code)]
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::ensure_agent_key;
use mandatepay::{
    app::{AppState, build_router},
    gateway::{FailureMode, Gateway, TestGate},
    mandates::Authority,
    store::Db,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::util::ServiceExt;

fn failing_app(mode: FailureMode) -> (axum::Router, Arc<AppState>, String) {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("os randomness unavailable");
    let api_key = B64.encode(raw);
    let authority = Authority::from_seed([7u8; 32]);
    let db = Db::open(":memory:").expect("in-memory db");
    let state = Arc::new(AppState {
        authority,
        db,
        gateway: Gateway::failing_for_tests(mode),
        api_key: api_key.clone(),
        max_mandate_cap: 100_000,
    });
    (build_router(state.clone()), state, api_key)
}

fn gated_app(mode: FailureMode, gate: Arc<TestGate>) -> (axum::Router, Arc<AppState>, String) {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("os randomness unavailable");
    let api_key = B64.encode(raw);
    let authority = Authority::from_seed([7u8; 32]);
    let db = Db::open(":memory:").expect("in-memory db");
    let state = Arc::new(AppState {
        authority,
        db,
        gateway: Gateway::failing_gated_for_tests(mode, gate),
        api_key: api_key.clone(),
        max_mandate_cap: 100_000,
    });
    (build_router(state.clone()), state, api_key)
}

async fn issue(app: &axum::Router, agent_key: &str, agent: &str) -> (Value, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mandates")
                .header("content-type", "application/json")
                .header("x-api-key", agent_key)
                .body(Body::from(
                    json!({
                        "agent_id": agent,
                        "merchant_id": "merchant-001",
                        "currency": "INR",
                        "max_amount_minor": 50000,
                        "ttl_secs": 600
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let sig = body["signature"].as_str().unwrap().to_string();
    (body["mandate"].clone(), sig)
}

fn checkout_request(mandate: &Value, sig: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/checkout")
        .header("content-type", "application/json")
        .header("x-api-key", "placeholder")
        .body(Body::from(
            json!({
                "mandate": mandate,
                "signature": sig,
                "amount_minor": 1000
            })
            .to_string(),
        ))
        .unwrap()
}

/// Wait until `state.db.stats().total == expected`, polling the DB.
/// No fixed-duration assumption about gateway timing: the caller signals the
/// gateway via the [`TestGate`] and we wait for the resulting condition with
/// a generous timeout.
async fn wait_for_total(state: &Arc<AppState>, expected: i64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let total = state.db.stats().expect("stats").total;
            if total == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timed out waiting for checkout decision row");
}

fn checkout_decisions(state: &Arc<AppState>) -> Vec<mandatepay::store::DecisionRow> {
    state
        .db
        .list_recent(10)
        .expect("list decisions")
        .into_iter()
        .filter(|r| r.endpoint == "/v1/checkout")
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_mid_gateway_failure_records_reject_and_cleans_up() {
    let gate = Arc::new(TestGate::new());
    let (app, state, master) = gated_app(FailureMode::Timeout, gate.clone());
    let agent = "cancel-fail";
    let agent_key = ensure_agent_key(&app, &master, agent).await;
    let (mandate, sig) = issue(&app, &agent_key, agent).await;
    let mandate_id = mandate["mandate_id"].as_str().unwrap().to_string();
    let nonce = mandate["nonce"].as_str().unwrap().to_string();
    let mut req = checkout_request(&mandate, &sig);
    req.headers_mut()
        .insert("x-api-key", agent_key.parse().unwrap());
    let fut = app.clone().oneshot(req);
    let mut boxed = Box::pin(fut);
    // Drive the handler until the gateway signals entry, then drop the
    // handler to simulate a client disconnect. Deterministic: no sleep.
    tokio::select! {
        res = &mut boxed => panic!("checkout completed before cancel: {res:?}"),
        res = tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()) => {
            res.expect("gateway never started");
        }
    }
    drop(boxed);
    // Let the detached gateway task finish its failure path.
    gate.release.notify_one();
    wait_for_total(&state, 2).await;

    // Exactly one checkout decision row, REJECT with gateway cause.
    let checkouts = checkout_decisions(&state);
    assert_eq!(checkouts.len(), 1, "exactly one checkout decision row");
    assert_eq!(checkouts[0].decision, "REJECT");
    assert!(
        checkouts[0].reason.contains("gateway"),
        "failure reason must name the gateway: {}",
        checkouts[0].reason
    );
    // Outcome matches cleanup: no order, nonce retryable, velocity refunded.
    assert!(state.db.get_order_status(&mandate_id).unwrap().is_none());
    assert!(state.db.get_cached_order(&mandate_id).unwrap().is_none());
    assert!(state.db.try_claim_nonce(&nonce).unwrap());
    state.db.rollback_nonce(&nonce).unwrap();
    assert_eq!(state.db.velocity_count(agent).unwrap(), 0);
    // Hash chain stays linear.
    assert!(state.db.verify_chain().unwrap());
    let stats = state.db.stats().unwrap();
    assert_eq!(stats.total, 2);
    assert_eq!(stats.issued, 1);
    assert_eq!(stats.reject, 1);
    assert_eq!(stats.allow, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_mid_gateway_success_records_allow_and_finalizes() {
    let gate = Arc::new(TestGate::new());
    let (app, state, master) = gated_app(FailureMode::Delay, gate.clone());
    let agent = "cancel-ok";
    let agent_key = ensure_agent_key(&app, &master, agent).await;
    let (mandate, sig) = issue(&app, &agent_key, agent).await;
    let mandate_id = mandate["mandate_id"].as_str().unwrap().to_string();
    let nonce = mandate["nonce"].as_str().unwrap().to_string();
    let mut req = checkout_request(&mandate, &sig);
    req.headers_mut()
        .insert("x-api-key", agent_key.parse().unwrap());
    let fut = app.clone().oneshot(req);
    let mut boxed = Box::pin(fut);
    // Drive the handler until the gateway signals entry, then drop the
    // handler to simulate a client disconnect. Deterministic: no sleep.
    tokio::select! {
        res = &mut boxed => panic!("checkout completed before cancel: {res:?}"),
        res = tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()) => {
            res.expect("gateway never started");
        }
    }
    drop(boxed);
    // Let the detached gateway task finish its success path.
    gate.release.notify_one();
    wait_for_total(&state, 2).await;

    // Exactly one checkout decision row, ALLOW.
    let checkouts = checkout_decisions(&state);
    assert_eq!(checkouts.len(), 1, "exactly one checkout decision row");
    assert_eq!(checkouts[0].decision, "ALLOW");
    // Outcome matches finalization: order completed, nonce kept, velocity kept.
    let cached = state.db.get_cached_order(&mandate_id).unwrap();
    assert!(cached.is_some(), "order must be finalized after disconnect");
    let (order_id, status) = state.db.get_order_status(&mandate_id).unwrap().unwrap();
    assert_eq!(order_id, cached.unwrap());
    assert_eq!(status, "completed");
    assert!(
        !state.db.try_claim_nonce(&nonce).unwrap(),
        "success keeps the nonce claimed"
    );
    assert_eq!(state.db.velocity_count(agent).unwrap(), 1);
    // Hash chain stays linear.
    assert!(state.db.verify_chain().unwrap());
    let stats = state.db.stats().unwrap();
    assert_eq!(stats.total, 2);
    assert_eq!(stats.issued, 1);
    assert_eq!(stats.allow, 1);
    assert_eq!(stats.reject, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_panic_maps_to_generic_500_and_rolls_back() {
    let (app, state, master) = failing_app(FailureMode::Panic);
    let agent = "cancel-panic";
    let agent_key = ensure_agent_key(&app, &master, agent).await;
    let (mandate, sig) = issue(&app, &agent_key, agent).await;
    let mandate_id = mandate["mandate_id"].as_str().unwrap().to_string();
    let nonce = mandate["nonce"].as_str().unwrap().to_string();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", &agent_key)
                .body(Body::from(
                    json!({
                        "mandate": mandate,
                        "signature": sig,
                        "amount_minor": 1000
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        body["error"].as_str().unwrap(),
        "internal error: internal error"
    );
    assert!(state.db.get_order_status(&mandate_id).unwrap().is_none());
    assert!(state.db.try_claim_nonce(&nonce).unwrap());
    state.db.rollback_nonce(&nonce).unwrap();
    assert_eq!(state.db.velocity_count(agent).unwrap(), 0);
    assert!(state.db.verify_chain().unwrap());
}
