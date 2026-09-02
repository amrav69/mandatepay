mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::test_app;
use serde_json::{Value, json};
use tower::util::ServiceExt;

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
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_agents_search() {
    let (app, key) = test_app();
    for id in ["search-foo-1", "search-foo-2", "search-bar-1"] {
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
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents?q=foo")
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
    assert_eq!(agents.len(), 2);
    assert!(
        agents
            .iter()
            .all(|a| a["agent_id"].as_str().unwrap().contains("foo"))
    );
}

#[tokio::test]
async fn list_agents_pagination() {
    let (app, key) = test_app();
    for id in ["pag-a", "pag-b", "pag-c"] {
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
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents?limit=1&offset=0")
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
    assert_eq!(body["agents"].as_array().unwrap().len(), 1);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents?limit=1&offset=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body2: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_ne!(
        body["agents"][0]["agent_id"],
        body2["agents"][0]["agent_id"]
    );
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
async fn retry_same_nonce_returns_cached_order_not_replay_error() {
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
                        "agent_id": "retry-agent",
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
    let payload = json!({
        "mandate": mandate,
        "signature": sig,
        "amount_minor": 10000
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", &key)
                .body(Body::from(payload.to_string()))
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
    let order_id = body["order_id"].as_str().unwrap().to_string();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", &key)
                .body(Body::from(payload.to_string()))
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
    assert_eq!(body["order_id"].as_str().unwrap(), order_id);
    assert!(
        body["reason"]
            .as_str()
            .unwrap()
            .contains("idempotent replay")
    );
}

#[tokio::test]
async fn agent_cap_below_mandate_cap_rejects_checkout() {
    let (app, key) = test_app();
    let agent_id = "cap-test-agent";
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/agents/{agent_id}"))
                .header("content-type", "application/json")
                .header("x-api-key", &key)
                .body(Body::from(json!({"max_cap": 1000}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
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
                        "agent_id": agent_id,
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
                .header("x-api-key", &key)
                .body(Body::from(
                    json!({
                        "mandate": mandate,
                        "signature": sig,
                        "amount_minor": 500
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
    assert_eq!(body["decision"], "REJECT");
    assert!(
        body["reason"]
            .as_str()
            .unwrap()
            .contains("exceeds agent cap")
    );
}
