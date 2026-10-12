#[allow(dead_code)]
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::ensure_agent_key;
use mandatepay::{
    app::{AppState, build_router},
    gateway::{FailureMode, Gateway},
    mandates::Authority,
    store::Db,
};
use serde_json::{Value, json};
use std::sync::Arc;
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

async fn checkout_once(app: &axum::Router, agent_key: &str, mandate: &Value, sig: &str) -> Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", agent_key)
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
    let (app, state, master) = failing_app(mode);
    let agent_key = ensure_agent_key(&app, &master, agent).await;
    assert_eq!(state.db.velocity_count(agent).unwrap(), 0);
    let (mandate, sig) = issue(&app, &agent_key, agent).await;
    let mandate_id = mandate["mandate_id"].as_str().unwrap().to_string();
    let nonce = mandate["nonce"].as_str().unwrap().to_string();

    let body = checkout_once(&app, &agent_key, &mandate, &sig).await;
    assert_eq!(body["decision"], "REJECT");
    assert!(
        body["reason"].as_str().unwrap().contains("gateway"),
        "failure reason must name the gateway: {}",
        body["reason"]
    );
    assert!(body["order_id"].is_null());

    assert!(state.db.get_order_status(&mandate_id).unwrap().is_none());
    assert!(state.db.get_cached_order(&mandate_id).unwrap().is_none());
    assert!(state.db.try_claim_nonce(&nonce).unwrap());
    state.db.rollback_nonce(&nonce).unwrap();
    assert_eq!(state.db.velocity_count(agent).unwrap(), 0);
    let stats = state.db.stats().unwrap();
    assert_eq!(stats.total, 2);
    assert_eq!(stats.reject, 1);
    assert!(state.db.verify_chain().unwrap());

    let retry = checkout_once(&app, &agent_key, &mandate, &sig).await;
    assert_eq!(retry["decision"], "REJECT");
    assert!(
        retry["reason"].as_str().unwrap().contains("gateway"),
        "retry must re-attempt gateway, not block on nonce: {}",
        retry["reason"]
    );
    assert!(retry["order_id"].is_null());
    assert!(state.db.get_order_status(&mandate_id).unwrap().is_none());
    assert_eq!(state.db.velocity_count(agent).unwrap(), 0);
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
