#[allow(dead_code)]
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::{ensure_agent_key, test_app};
use serde_json::{Value, json};
use tower::util::ServiceExt;

async fn post_raw(
    app: &axum::Router,
    key: Option<&str>,
    uri: &str,
    content_type: &str,
    body: Vec<u8>,
) -> StatusCode {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", content_type);
    if let Some(k) = key {
        builder = builder.header("x-api-key", k);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn oversized_body_rejected_with_413() {
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "adv-big").await;
    let big_agent = "a".repeat(3 * 1024 * 1024);
    let body = format!(
        r#"{{"agent_id":"{big_agent}","merchant_id":"merchant-001","currency":"INR","max_amount_minor":100,"ttl_secs":600}}"#
    );
    assert_eq!(
        post_raw(
            &app,
            Some(&agent_key),
            "/v1/mandates",
            "application/json",
            body.into_bytes()
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn wrong_content_type_rejected_with_415() {
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "adv-ctype").await;
    assert_eq!(
        post_raw(
            &app,
            Some(&agent_key),
            "/v1/mandates",
            "text/plain",
            r#"{"agent_id":"a"}"#.into()
        )
        .await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

#[tokio::test]
async fn truncated_json_rejected_as_client_error() {
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "adv-trunc").await;
    let status = post_raw(
        &app,
        Some(&agent_key),
        "/v1/checkout",
        "application/json",
        br#"{"mandate": {"#.to_vec(),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "truncated JSON must be 4xx, got {status}"
    );
}

#[tokio::test]
async fn replayed_checkout_returns_same_order() {
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "adv-replay").await;
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
                        "agent_id": "adv-replay",
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
        "amount_minor": 1000
    })
    .to_string();
    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", &agent_key)
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_body: Value = serde_json::from_slice(
        &axum::body::to_bytes(first.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first_body["decision"], "ALLOW");
    let order_id = first_body["order_id"].as_str().unwrap().to_string();
    let second = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", &agent_key)
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_body: Value = serde_json::from_slice(
        &axum::body::to_bytes(second.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(second_body["decision"], "ALLOW");
    assert_eq!(second_body["order_id"].as_str().unwrap(), order_id);
    assert!(
        second_body["reason"]
            .as_str()
            .unwrap()
            .contains("idempotent replay")
    );
}
