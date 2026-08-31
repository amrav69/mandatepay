use mandatepay::{
    app::{AppState, build_router},
    gateway::Gateway,
    mandates::Authority,
    store::Db,
};
use std::sync::Arc;

#[tokio::test]
async fn app_boots_with_rust_log_info() {
    unsafe { std::env::set_var("RUST_LOG", "info") };
    let api_key = "test-logging-key".to_string();
    let authority = Authority::from_seed([1u8; 32]);
    let db = Db::open(":memory:").unwrap();
    let state = Arc::new(AppState {
        authority,
        db,
        gateway: Gateway::Mock,
        api_key,
        max_mandate_cap: 100_000,
    });
    let _app = build_router(state);
    drop(_app);
}

#[tokio::test]
async fn metrics_endpoint_returns_counters() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::Value;
    use tower::util::ServiceExt;

    let api_key = "metrics-test-key".to_string();
    let authority = Authority::from_seed([2u8; 32]);
    let db = Db::open(":memory:").unwrap();
    db.record_decision("/v1/mandates", "ISSUED", "test", "{}")
        .unwrap();
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
                .uri("/v1/metrics")
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
    assert!(body["total"].is_number());
}
