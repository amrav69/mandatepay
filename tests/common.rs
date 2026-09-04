use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use mandatepay::{
    app::{AppState, build_router},
    gateway::Gateway,
    mandates::Authority,
    store::Db,
};
use std::sync::Arc;

pub fn random_test_key() -> String {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("os randomness unavailable");
    B64.encode(raw)
}

pub fn test_app() -> (axum::Router, String) {
    // Returns (router, master_key). Per-agent keys must be minted via
    // ensure_agent_key() below; master does NOT authorize mandates/checkout (C1).
    let api_key = random_test_key();
    let authority = Authority::from_seed([7u8; 32]);
    let db = Db::open(":memory:").expect("in-memory db");
    let gateway = Gateway::Mock;
    let state = Arc::new(AppState {
        authority,
        db,
        gateway,
        api_key: api_key.clone(),
        max_mandate_cap: 100_000,
    });
    (build_router(state), api_key)
}

/// C1 helper: create `agent_id` via master-key POST /v1/agents and return its
/// per-agent key (shown once). If the agent already exists, rotates to obtain
/// a fresh usable key.
pub async fn ensure_agent_key(app: &axum::Router, master: &str, agent_id: &str) -> String {
    use axum::{body::Body, http::Request};
    use tower::util::ServiceExt;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agents")
                .header("content-type", "application/json")
                .header("x-api-key", master)
                .body(Body::from(
                    serde_json::json!({"agent_id": agent_id}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    if let Some(k) = body["api_key"].as_str() {
        return k.to_string();
    }
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/agents/{agent_id}/rotate"))
                .header("x-api-key", master)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    body["api_key"].as_str().unwrap().to_string()
}
