use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use mandatepay::{
    app::{AppState, build_router, build_router_with_options},
    gateway::Gateway,
    mandates::Authority,
    store::Db,
};
use std::sync::Arc;
use tower::util::ServiceExt;

fn random_key() -> String {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("os randomness");
    B64.encode(raw)
}

fn app_with_flag(public_reads: bool) -> (axum::Router, String) {
    let api_key = random_key();
    let authority = Authority::from_seed([77u8; 32]);
    let db = Db::open(":memory:").expect("in-memory db");
    let state = Arc::new(AppState {
        authority,
        db,
        gateway: Gateway::Mock,
        api_key: api_key.clone(),
        max_mandate_cap: 100_000,
    });
    (build_router_with_options(state, public_reads), api_key)
}

async fn get_status(app: axum::Router, uri: &str, key: Option<&str>) -> StatusCode {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(k) = key {
        builder = builder.header("x-api-key", k);
    }
    let resp = app
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn closed_by_default_rejects_unauthenticated_reads() {
    let (app, key) = app_with_flag(false);
    // All demo-public reads now require auth by default.
    for uri in [
        "/v1/decisions",
        "/v1/decisions/1",
        "/v1/decisions/1/verify",
        "/v1/chain/verify",
        "/v1/stats",
        "/v1/metrics",
        "/v1/agents",
    ] {
        assert_eq!(
            get_status(app.clone(), uri, None).await,
            StatusCode::UNAUTHORIZED,
            "{uri} must require auth when public reads are closed"
        );
    }
    // POST /v1/verify too.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mandate":{},"signature":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Health and dashboard stay public.
    assert_eq!(
        get_status(app.clone(), "/health", None).await,
        StatusCode::OK
    );
    assert_eq!(get_status(app.clone(), "/", None).await, StatusCode::OK);
    // Authenticated reads still work.
    assert_eq!(
        get_status(app.clone(), "/v1/stats", Some(&key)).await,
        StatusCode::OK
    );
    assert_eq!(
        get_status(app, "/v1/agents", Some(&key)).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn open_flag_allows_unauthenticated_reads_but_not_writes() {
    let (app, _) = app_with_flag(true);
    for uri in [
        "/v1/stats",
        "/v1/agents",
        "/v1/chain/verify",
        "/v1/decisions",
    ] {
        assert_eq!(
            get_status(app.clone(), uri, None).await,
            StatusCode::OK,
            "{uri} must be public when MANDATEPAY_PUBLIC_READS=1"
        );
    }
    // Writes stay protected even in demo mode.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mandates")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"agent_id":"a"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn env_var_controls_default_router() {
    let api_key = random_key();
    let build = || {
        let authority = Authority::from_seed([78u8; 32]);
        let db = Db::open(":memory:").expect("in-memory db");
        let state = Arc::new(AppState {
            authority,
            db,
            gateway: Gateway::Mock,
            api_key: api_key.clone(),
            max_mandate_cap: 100_000,
        });
        build_router(state)
    };
    let prev = std::env::var("MANDATEPAY_PUBLIC_READS").ok();
    // Unset -> closed.
    unsafe { std::env::remove_var("MANDATEPAY_PUBLIC_READS") };
    assert_eq!(
        get_status(build(), "/v1/stats", None).await,
        StatusCode::UNAUTHORIZED
    );
    // Set to 1 -> open.
    unsafe { std::env::set_var("MANDATEPAY_PUBLIC_READS", "1") };
    assert_eq!(get_status(build(), "/v1/stats", None).await, StatusCode::OK);
    // Any other value -> closed.
    unsafe { std::env::set_var("MANDATEPAY_PUBLIC_READS", "0") };
    assert_eq!(
        get_status(build(), "/v1/stats", None).await,
        StatusCode::UNAUTHORIZED
    );
    // Restore.
    unsafe {
        match prev {
            Some(v) => std::env::set_var("MANDATEPAY_PUBLIC_READS", v),
            None => std::env::remove_var("MANDATEPAY_PUBLIC_READS"),
        }
    };
}
