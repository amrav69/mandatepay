use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use mandatepay::{
    app::{AppState, build_router},
    gateway::Gateway,
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

#[tokio::test]
async fn fresh_clone_no_env_still_builds_and_tests() {
    // Simulate a fresh clone with no .env — no env vars set, in-memory DB, Mock gateway
    let api_key = random_key();
    let authority = Authority::from_seed([42u8; 32]);
    let db = Db::open(":memory:").expect("in-memory db must open without any env");
    let gateway = Gateway::Mock;
    let state = Arc::new(AppState {
        authority,
        db,
        gateway,
        api_key: api_key.clone(),
        max_mandate_cap: 100_000,
    });
    let app = build_router(state);

    // health should be public, no key needed, no env needed
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // C1: create the agent with the master key, then mint with its per-agent key.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agents")
                .header("content-type", "application/json")
                .header("x-api-key", &api_key)
                .body(Body::from(json!({"agent_id": "fresh-agent"}).to_string()))
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
    let agent_key = body["api_key"].as_str().unwrap().to_string();

    // mandates should work with the in-memory, no-env app via the agent key
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mandates")
                .header("content-type", "application/json")
                .header("x-api-key", &agent_key)
                .body(Body::from(
                    json!({
                        "agent_id": "fresh-agent",
                        "merchant_id": "merchant-001",
                        "currency": "INR",
                        "max_amount_minor": 10000,
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
    assert!(body["mandate"]["mandate_id"].is_string());
}

#[tokio::test]
async fn fresh_clone_chain_verify_without_env() {
    let api_key = random_key();
    let authority = Authority::from_seed([99u8; 32]);
    let db = Db::open(":memory:").unwrap();
    let state = Arc::new(AppState {
        authority,
        db,
        gateway: Gateway::Mock,
        api_key: api_key.clone(),
        max_mandate_cap: 100_000,
    });
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/chain/verify")
                .body(Body::empty())
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
    assert_eq!(body["chain_valid"], true);
}
