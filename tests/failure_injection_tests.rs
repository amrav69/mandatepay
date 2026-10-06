use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use mandatepay::{
    app::{AppState, build_router},
    gateway::{FailureMode, Gateway},
    mandates::Authority,
    store::Db,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::util::ServiceExt;

fn random_key() -> String {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("os randomness");
    B64.encode(raw)
}

fn failing_app(mode: FailureMode) -> (axum::Router, Arc<AppState>, String) {
    let api_key = random_key();
    let authority = Authority::from_seed([7u8; 32]);
    let db = Db::open(":memory:").expect("in-memory db");
    let state = Arc::new(AppState {
        authority,
        db,
        gateway: Gateway::Failing { mode },
        api_key: api_key.clone(),
        max_mandate_cap: 100_000,
    });
    let key = api_key.clone();
    (build_router(state.clone()), state, key)
}

async fn issue(app: axum::Router, key: &str, agent: &str) -> (Value, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mandates")
                .header("content-type", "application/json")
                .header("x-api-key", key)
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

async fn checkout_once(app: axum::Router, key: &str, mandate: Value, sig: &str) -> Value {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", key)
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
    assert_eq!(resp.status(), StatusCode::OK);
    serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn gateway_failure_mode_leaves_no_trace(mode: FailureMode, agent: &str) {
    let (app, state, key) = failing_app(mode);
    assert_eq!(state.db.velocity_count(agent).unwrap(), 0);
    let (mandate, sig) = issue(app.clone(), &key, agent).await;
    let mandate_id = mandate["mandate_id"].as_str().unwrap().to_string();
    let nonce = mandate["nonce"].as_str().unwrap().to_string();

    let body = checkout_once(app.clone(), &key, mandate, &sig).await;
    assert_eq!(body["decision"], "REJECT");
    assert!(
        body["reason"].as_str().unwrap().contains("gateway"),
        "failure reason must name the gateway: {}",
        body["reason"]
    );
    assert!(body["order_id"].is_null());

    // No leaked pending row...
    assert!(state.db.get_order_status(&mandate_id).unwrap().is_none());
    assert!(state.db.get_cached_order(&mandate_id).unwrap().is_none());
    // ...no leaked nonce (retry would be able to claim it)...
    assert!(state.db.try_claim_nonce(&nonce).unwrap());
    // ...no burned velocity...
    assert_eq!(state.db.velocity_count(agent).unwrap(), 0);
    // ...and exactly one complete decision row, chain still valid.
    let stats = state.db.stats().unwrap();
    assert_eq!(stats.total, 2); // ISSUED + REJECT
    assert_eq!(stats.reject, 1);
    assert!(state.db.verify_chain().unwrap());
}

#[tokio::test]
async fn injected_gateway_error_leaves_no_trace() {
    gateway_failure_mode_leaves_no_trace(FailureMode::Error, "fail-err").await;
}

#[tokio::test]
async fn injected_gateway_timeout_leaves_no_trace() {
    gateway_failure_mode_leaves_no_trace(FailureMode::Timeout, "fail-timeout").await;
}

#[tokio::test]
async fn injected_malformed_body_leaves_no_trace() {
    gateway_failure_mode_leaves_no_trace(FailureMode::MalformedBody, "fail-malformed").await;
}
