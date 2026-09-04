mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::{ensure_agent_key, test_app};
use serde_json::{Value, json};
use tower::util::ServiceExt;

#[tokio::test]
async fn mandates_rejects_without_api_key() {
    // Renamed (was checkout_rejects_without_api_key): it posts to /v1/mandates.
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
async fn checkout_without_valid_key_returns_401_or_403() {
    // H8: real checkout auth coverage under the per-agent model. Three cases:
    // no key -> 401; master key (wrong scope) -> 401/403; another agent's key -> 401/403.
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "h8-agent").await;
    let other_key = ensure_agent_key(&app, &master, "h8-other").await;
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
                        "agent_id": "h8-agent",
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
    let payload = json!({"mandate": mandate, "signature": sig, "amount_minor": 100});

    // No key.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Master key and wrong-agent key must both fail with 401/403.
    for (label, key) in [("master", master.clone()), ("wrong-agent", other_key)] {
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
        assert!(
            resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN,
            "checkout with {label} key must be 401/403, got {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn verify_endpoint_validates_signature() {
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
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "chain-test").await;
    for _ in 0..2 {
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
    let (app, master) = test_app();
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents/delete-me")
                .header("x-api-key", &master)
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
    assert_eq!(body["deleted"], "delete-me");
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/agents/delete-me")
                .header("x-api-key", &master)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_agents_search() {
    let (app, master) = test_app();
    for id in ["search-foo-1", "search-foo-2", "search-bar-1"] {
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
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents?q=foo")
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
    assert_eq!(agents.len(), 2);
    assert!(
        agents
            .iter()
            .all(|a| a["agent_id"].as_str().unwrap().contains("foo"))
    );
}

#[tokio::test]
async fn list_agents_pagination() {
    let (app, master) = test_app();
    for id in ["pag-a", "pag-b", "pag-c"] {
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
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents?limit=1&offset=0")
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
    assert_eq!(body["agents"].as_array().unwrap().len(), 1);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents?limit=1&offset=1")
                .header("x-api-key", &master)
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
async fn public_decisions_redact_nonce_master_sees_full() {
    // H5 regression: unauthenticated decision reads must not expose full nonces.
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "redact-agent").await;
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
                        "agent_id": "redact-agent",
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
    let full_nonce = body["mandate"]["nonce"].as_str().unwrap().to_string();
    assert!(full_nonce.len() > 8);

    let get_list = |key: Option<String>| {
        let app = app.clone();
        async move {
            let mut req = Request::builder()
                .method("GET")
                .uri("/v1/decisions?limit=5");
            if let Some(k) = key {
                req = req.header("x-api-key", k);
            }
            let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body: Value = serde_json::from_slice(
                &axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                    .await
                    .unwrap(),
            )
            .unwrap();
            body["decisions"].as_array().unwrap().len()
        }
    };
    assert!(get_list(None).await > 0);
    // Public payload must not contain the full nonce.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/decisions?limit=5")
                .body(Body::empty())
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
    for d in body["decisions"].as_array().unwrap() {
        let payload = d["payload"].as_str().unwrap_or("");
        assert!(
            !payload.contains(&full_nonce),
            "public decisions must not leak full nonce"
        );
    }
    // Master sees the full nonce.
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/decisions?limit=50")
                .header("x-api-key", &master)
                .body(Body::empty())
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
    let found = body["decisions"].as_array().unwrap().iter().any(|d| {
        d["payload"]
            .as_str()
            .map(|p| p.contains(&full_nonce))
            .unwrap_or(false)
    });
    assert!(found, "master should see full payload nonce");
}

#[tokio::test]
async fn list_agents_requires_auth() {
    // C2 regression: list must be at least as protected as single-agent reads.
    let (app, _) = test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/agents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_agents_sort() {
    let (app, master) = test_app();
    for (id, cap) in [("sort-a", 1000), ("sort-b", 3000), ("sort-c", 2000)] {
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/agents")
                    .header("content-type", "application/json")
                    .header("x-api-key", &master)
                    .body(Body::from(
                        json!({"agent_id": id, "max_cap": cap}).to_string(),
                    ))
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
                .uri("/v1/agents?sort=max_cap&order=desc")
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
    let caps: Vec<u64> = agents
        .iter()
        .filter(|a| a["agent_id"].as_str().unwrap().starts_with("sort-"))
        .map(|a| a["max_cap"].as_u64().unwrap())
        .collect();
    assert_eq!(caps, vec![3000, 2000, 1000]);
}

#[tokio::test]
async fn forged_merchant_does_not_leak_allowlist() {
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "oracle-agent").await;
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
                        "agent_id": "oracle-agent",
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
    let mut mandate = body["mandate"].clone();
    mandate["merchant_id"] = json!("merchant-999");
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
    assert_eq!(body["decision"], "REJECT");
    assert_eq!(body["reason"], "invalid signature");
}

#[tokio::test]
async fn retry_same_nonce_returns_cached_order_not_replay_error() {
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "retry-agent").await;
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
                .header("x-api-key", &agent_key)
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
                .header("x-api-key", &agent_key)
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
    let (app, master) = test_app();
    let agent_id = "cap-test-agent";
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/agents/{agent_id}"))
                .header("content-type", "application/json")
                .header("x-api-key", &master)
                .body(Body::from(json!({"max_cap": 1000}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    // C1: PATCH is master-gated; mandates/checkout need the per-agent key.
    let agent_key = ensure_agent_key(&app, &master, agent_id).await;
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
                .header("x-api-key", &agent_key)
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

#[tokio::test]
async fn velocity_reject_rolls_back_nonce_so_retry_not_replay() {
    // Regression for src/app.rs:271 let _ = rollback_nonce silently discarding Err
    // and for the weak DB-only test at tests/mandates_tests.rs:192.
    // This is an end-to-end test through axum Router, not just Db, so it would
    // fail if the rollback call in app.rs were deleted.
    let (app, master) = test_app();
    let agent_id = "vel-e2e-rollback-test";

    // Set velocity_limit = 1 for this agent so the second checkout hits the limit
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/agents/{agent_id}"))
                .header("content-type", "application/json")
                .header("x-api-key", &master)
                .body(Body::from(
                    json!({ "velocity_limit": 1, "velocity_window_secs": 60 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let agent_key = ensure_agent_key(&app, &master, agent_id).await;

    // First mandate + checkout should be ALLOW (consumes 1 velocity token)
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
                        "agent_id": agent_id,
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
    let mandate1 = body["mandate"].clone();
    let sig1 = body["signature"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", &agent_key)
                .body(Body::from(
                    json!({ "mandate": mandate1, "signature": sig1, "amount_minor": 1000 })
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
    assert_eq!(body["decision"], "ALLOW", "first checkout should be ALLOW");

    // Second mandate (different nonce) should be REJECT for velocity, not for replay
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
                        "agent_id": agent_id,
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
    let mandate2 = body["mandate"].clone();
    let sig2 = body["signature"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", &agent_key)
                .body(Body::from(
                    json!({ "mandate": mandate2, "signature": sig2, "amount_minor": 1000 })
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
            .contains("velocity limit exceeded"),
        "second checkout should be REJECT for velocity, got: {}",
        body["reason"]
    );

    // Retry the SAME mandate2 (same nonce) again — with the fix, nonce was rolled back
    // on velocity rejection, so this should again be REJECT for velocity, NOT for nonce replay.
    // If the rollback in src/app.rs:271 were deleted, this would be REJECT "nonce already consumed".
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", &agent_key)
                .body(Body::from(
                    json!({ "mandate": mandate2, "signature": sig2, "amount_minor": 1000 })
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
    let reason = body["reason"].as_str().unwrap();
    assert!(
        reason.contains("velocity limit exceeded"),
        "retry of velocity-rejected mandate should still be velocity REJECT (nonce rolled back), not replay. Got: {reason}"
    );
    assert!(
        !reason.contains("nonce already consumed"),
        "retry should NOT be nonce replay if rollback works, got: {reason}"
    );
}

#[tokio::test]
async fn idempotency_cache_amount_mismatch_not_returned() {
    // Regression for src/app.rs:235-253 — early cache must also verify amount matches cached order.
    // Same mandate_id with two different valid amounts: second checkout must NOT silently return the first cached order.
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "idempotent-amount-test").await;

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
                        "agent_id": "idempotent-amount-test",
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

    // First checkout with amount 1000 should be ALLOW and cache order with amount 1000
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", &agent_key)
                .body(Body::from(
                    json!({ "mandate": mandate, "signature": sig, "amount_minor": 1000 })
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
    let order_id_first = body["order_id"].as_str().unwrap().to_string();
    assert!(body["reason"].as_str().unwrap().contains("passed"));

    // Second checkout with SAME mandate_id/signature/nonce but different amount 2000
    // Both amounts are individually valid (<= cap), but the second must NOT return the cached order for 1000.
    // Correct behavior: fall through to try_claim_nonce and REJECT for nonce already consumed.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", &agent_key)
                .body(Body::from(
                    json!({ "mandate": mandate, "signature": sig, "amount_minor": 2000 })
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
    assert_eq!(
        body["decision"], "REJECT",
        "amount mismatch should be REJECT, not ALLOW with wrong order"
    );
    assert!(
        body["reason"]
            .as_str()
            .unwrap()
            .contains("nonce already consumed"),
        "should be nonce replay REJECT, got: {}",
        body["reason"]
    );
    assert!(
        body["order_id"].is_null() || body["order_id"].as_str().unwrap() != order_id_first,
        "must not return cached order for different amount"
    );
}
