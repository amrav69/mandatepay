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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_mid_gateway_failure_leaves_no_trace() {
    let (app, state, master) = failing_app(FailureMode::Timeout);
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
    tokio::select! {
        _ = &mut boxed => panic!("checkout completed before cancel"),
        _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {
            drop(boxed);
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(state.db.get_order_status(&mandate_id).unwrap().is_none());
    assert!(state.db.get_cached_order(&mandate_id).unwrap().is_none());
    assert!(state.db.try_claim_nonce(&nonce).unwrap());
    state.db.rollback_nonce(&nonce).unwrap();
    assert_eq!(state.db.velocity_count(agent).unwrap(), 0);
    assert!(state.db.verify_chain().unwrap());
    let stats = state.db.stats().unwrap();
    assert_eq!(
        stats.total, 1,
        "dropped handler records no checkout decision"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_mid_gateway_success_still_finalizes() {
    let (app, state, master) = failing_app(FailureMode::Delay);
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
    tokio::select! {
        _ = &mut boxed => panic!("checkout completed before cancel"),
        _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {
            drop(boxed);
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
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
    assert!(state.db.verify_chain().unwrap());
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
