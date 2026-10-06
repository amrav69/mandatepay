mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::test_app;
use tower::util::ServiceExt;

async fn post_raw(
    app: axum::Router,
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
    app.oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn oversized_body_rejected_with_413() {
    let (app, key) = test_app();
    // axum's Json extractor caps bodies at 2 MiB; 3 MiB of valid JSON shape
    // must be refused before any DB write or signature work.
    let big_agent = "a".repeat(3 * 1024 * 1024);
    let body = format!(
        r#"{{"agent_id":"{big_agent}","merchant_id":"merchant-001","currency":"INR","max_amount_minor":100,"ttl_secs":600}}"#
    );
    assert_eq!(
        post_raw(
            app,
            Some(&key),
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
    let (app, key) = test_app();
    assert_eq!(
        post_raw(
            app,
            Some(&key),
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
    let (app, key) = test_app();
    let status = post_raw(
        app,
        Some(&key),
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
async fn empty_body_rejected_as_client_error() {
    let (app, key) = test_app();
    let status = post_raw(app, Some(&key), "/v1/mandates", "application/json", vec![]).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "empty body must be 4xx, got {status}"
    );
}

#[tokio::test]
async fn non_numeric_decision_id_rejected() {
    let (app, key) = test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/decisions/abc")
                .header("x-api-key", &key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn decision_limit_clamped_to_200() {
    use serde_json::Value;
    let (app, key) = test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/decisions?limit=999999")
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
    assert!(body["decisions"].as_array().unwrap().len() <= 200);
}
