mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::{ensure_agent_key, test_app};
use serde_json::{Value, json};
use tower::util::ServiceExt;

#[tokio::test]
async fn issue_and_checkout_allow() {
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "agent-1").await;
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
                .header("x-api-key", &agent_key)
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
async fn issue_rejects_invalid_ttl_and_currency() {
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "a").await;
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
                        "agent_id": "a",
                        "merchant_id": "merchant-001",
                        "currency": "INR",
                        "max_amount_minor": 1000,
                        "ttl_secs": 0
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mandates")
                .header("content-type", "application/json")
                .header("x-api-key", &agent_key)
                .body(Body::from(
                    json!({
                        "agent_id": "a",
                        "merchant_id": "merchant-001",
                        "currency": "USD",
                        "max_amount_minor": 1000,
                        "ttl_secs": 600
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn master_key_cannot_issue_or_checkout() {
    // C1 regression: master/admin key authorizes /v1/agents* only.
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "agent-master-probe").await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mandates")
                .header("content-type", "application/json")
                .header("x-api-key", &master)
                .body(Body::from(
                    json!({
                        "agent_id": "agent-master-probe",
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
    assert!(
        resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN,
        "/v1/mandates with master key must be 401/403, got {}",
        resp.status()
    );
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
                        "agent_id": "agent-master-probe",
                        "merchant_id": "merchant-001",
                        "currency": "INR",
                        "max_amount_minor": 5000,
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
                .header("x-api-key", &master)
                .body(Body::from(
                    json!({"mandate": mandate, "signature": sig, "amount_minor": 100}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN,
        "/v1/checkout with master key must be 401/403, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn agent_key_for_wrong_agent_rejected() {
    // C1 regression: key for agent A cannot mint/spend as agent B.
    let (app, master) = test_app();
    let key_a = ensure_agent_key(&app, &master, "agent-wrong-a").await;
    let _ = ensure_agent_key(&app, &master, "agent-wrong-b").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mandates")
                .header("content-type", "application/json")
                .header("x-api-key", &key_a)
                .body(Body::from(
                    json!({
                        "agent_id": "agent-wrong-b",
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
    assert!(
        resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN,
        "cross-agent key use must be 401/403, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn get_agent_returns_policy() {
    let (app, master) = test_app();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents/test-agent-xyz")
                .header("x-api-key", &master)
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
async fn patch_agent_updates_policy() {
    let (app, master) = test_app();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/v1/agents/patch-agent-1")
                .header("content-type", "application/json")
                .header("x-api-key", &master)
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
}

#[tokio::test]
async fn create_agent_explicit() {
    let (app, master) = test_app();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agents")
                .header("content-type", "application/json")
                .header("x-api-key", &master)
                .body(Body::from(
                    json!({
                        "agent_id": "create-me",
                        "max_cap": 77777,
                        "velocity_limit": 7
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
    assert_eq!(body["agent_id"], "create-me");
    assert_eq!(body["max_cap"], 77777);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agents")
                .header("content-type", "application/json")
                .header("x-api-key", &master)
                .body(Body::from(json!({"agent_id": "create-me"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_agents_returns_all() {
    let (app, master) = test_app();
    for id in ["list-a", "list-b"] {
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/agents/{id}"))
                    .header("x-api-key", &master)
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
                .header("x-api-key", &master)
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
