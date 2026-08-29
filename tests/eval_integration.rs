use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use mandatepay::{
    app::{AppState, build_router},
    gateway::Gateway,
    mandates::Authority,
    store::Db,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::util::ServiceExt;

fn test_app() -> (axum::Router, String) {
    let api_key = "test-key-123".to_string();
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

#[tokio::test]
async fn issue_and_checkout_allow() {
    let (app, key) = test_app();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mandates")
                .header("content-type", "application/json")
                .header("x-api-key", &key)
                .body(Body::from(
                    json!({
                        "agent_id": "agent-1",
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
    let mandate = body["mandate"].clone();
    let sig = body["signature"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", &key)
                .body(Body::from(
                    json!({
                        "mandate": mandate,
                        "signature": sig,
                        "amount_minor": 10000
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
    assert_eq!(body["decision"], "ALLOW");
}

#[tokio::test]
async fn checkout_rejects_without_api_key() {
    let (app, _) = test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mandates")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "agent_id": "a",
                        "merchant_id": "merchant-001",
                        "currency": "INR",
                        "max_amount_minor": 1000,
                        "ttl_secs": 600
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn verify_endpoint_validates_signature() {
    let (app, key) = test_app();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mandates")
                .header("content-type", "application/json")
                .header("x-api-key", &key)
                .body(Body::from(
                    json!({
                        "agent_id": "agent-1",
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
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let mandate = body["mandate"].clone();
    let sig = body["signature"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"mandate": mandate, "signature": sig}).to_string(),
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
    assert_eq!(body["valid"], true);
}

#[tokio::test]
async fn get_agent_returns_policy() {
    let (app, key) = test_app();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents/test-agent-xyz")
                .header("x-api-key", &key)
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
    assert_eq!(body["agent_id"], "test-agent-xyz");
    assert_eq!(body["max_cap"], 50000);
    assert_eq!(body["velocity_limit"], 50);
}

#[tokio::test]
async fn get_agent_requires_auth() {
    let (app, _) = test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents/test-agent-xyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn patch_agent_updates_policy() {
    let (app, key) = test_app();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/v1/agents/patch-agent-1")
                .header("content-type", "application/json")
                .header("x-api-key", &key)
                .body(Body::from(
                    json!({
                        "max_cap": 99999,
                        "velocity_limit": 10,
                        "allowed_merchants": ["merchant-001", "merchant-002"]
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
    assert_eq!(body["max_cap"], 99999);
    assert_eq!(body["velocity_limit"], 10);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents/patch-agent-1")
                .header("x-api-key", &key)
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
    assert_eq!(body["max_cap"], 99999);
}

#[tokio::test]
async fn list_agents_returns_all() {
    let (app, key) = test_app();
    for id in ["list-a", "list-b"] {
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/agents/{id}"))
                    .header("x-api-key", &key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents")
                .header("x-api-key", &key)
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
    let agents = body["agents"].as_array().unwrap();
    assert!(agents.iter().any(|a| a["agent_id"] == "list-a"));
    assert!(agents.iter().any(|a| a["agent_id"] == "list-b"));
}

#[tokio::test]
async fn delete_agent_removes_policy() {
    let (app, key) = test_app();
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents/delete-me")
                .header("x-api-key", &key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/agents/delete-me")
                .header("x-api-key", &key)
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
    assert_eq!(body["deleted"], "delete-me");

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/agents/delete-me")
                .header("x-api-key", &key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn chain_verify_true_after_writes() {
    let (app, key) = test_app();
    for _ in 0..2 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mandates")
                    .header("content-type", "application/json")
                    .header("x-api-key", &key)
                    .body(Body::from(
                        json!({
                            "agent_id": "chain-test",
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
    }
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
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
