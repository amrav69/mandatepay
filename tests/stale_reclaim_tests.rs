#[allow(dead_code)]
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::ensure_agent_key;
use mandatepay::{
    app::{AppState, build_router},
    gateway::{FailureMode, Gateway},
    mandates::{Authority, Mandate},
    store::{Db, PENDING_TTL_SECS},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::util::ServiceExt;

fn mock_app() -> (axum::Router, Arc<AppState>, String) {
    mock_app_with_gateway(Gateway::mock())
}

fn mock_app_with_gateway(gateway: Gateway) -> (axum::Router, Arc<AppState>, String) {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("os randomness unavailable");
    let api_key = B64.encode(raw);
    let authority = Authority::from_seed([7u8; 32]);
    let db = Db::open(":memory:").expect("in-memory db");
    let state = Arc::new(AppState {
        authority,
        db,
        gateway,
        api_key: api_key.clone(),
        max_mandate_cap: 100_000,
    });
    (build_router(state.clone()), state, api_key)
}

fn failing_app(mode: FailureMode) -> (axum::Router, Arc<AppState>, String) {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("os randomness unavailable");
    let api_key = B64.encode(raw);
    let authority = Authority::from_seed([7u8; 32]);
    let db = Db::open(":memory:").expect("in-memory db");
    let state = Arc::new(AppState {
        authority,
        db,
        gateway: Gateway::failing_for_tests(mode),
        api_key: api_key.clone(),
        max_mandate_cap: 100_000,
    });
    (build_router(state.clone()), state, api_key)
}

async fn issue(app: &axum::Router, agent_key: &str, agent: &str) -> (Value, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mandates")
                .header("content-type", "application/json")
                .header("x-api-key", agent_key)
                .body(Body::from(
                    json!({
                        "agent_id": agent,
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
    let sig = body["signature"].as_str().unwrap().to_string();
    (body["mandate"].clone(), sig)
}

async fn checkout(
    app: &axum::Router,
    agent_key: &str,
    mandate: &Value,
    sig: &str,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/checkout")
                .header("content-type", "application/json")
                .header("x-api-key", agent_key)
                .body(Body::from(
                    json!({
                        "mandate": mandate,
                        "signature": sig,
                        "amount_minor": 1000
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap_or(json!({}));
    (status, body)
}

fn stale_now() -> u64 {
    mandatepay::mandates::unix_now().saturating_sub(PENDING_TTL_SECS + 10)
}

/// Simulate a crash between reserve and finalize: nonce claimed + stale
/// pending row, no gateway side effects yet.
fn crash_with_stale_pending(state: &Arc<AppState>, mandate_id: &str, nonce: &str, amount: u64) {
    let old = stale_now();
    state.db.try_claim_nonce_at(nonce, old).unwrap();
    let (reserved, _) = state
        .db
        .try_reserve_order_with_nonce_at(mandate_id, amount, nonce, old)
        .unwrap();
    assert!(reserved);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_pending_blocks_duplicate() {
    let (app, state, master) = mock_app();
    let agent = "reclaim-fresh";
    let agent_key = ensure_agent_key(&app, &master, agent).await;
    let (mandate, sig) = issue(&app, &agent_key, agent).await;
    let mid = mandate["mandate_id"].as_str().unwrap().to_string();
    let nonce = mandate["nonce"].as_str().unwrap().to_string();
    // Live attempt in flight right now (fresh pending, nonce claimed).
    let now = mandatepay::mandates::unix_now();
    state.db.try_claim_nonce(&nonce).unwrap();
    let (reserved, _) = state
        .db
        .try_reserve_order_with_nonce_at(&mid, 1000, &nonce, now)
        .unwrap();
    assert!(reserved);
    // Identical retry while fresh must NOT steal: REJECT, zero gateway creates.
    let (status, body) = checkout(&app, &agent_key, &mandate, &sig).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "REJECT");
    assert_eq!(state.gateway.mock_create_count(), 0);
    // Still pending (not stolen, not completed).
    let (oid, st) = state.db.get_order_status(&mid).unwrap().unwrap();
    assert_eq!(oid, "__PENDING__");
    assert_eq!(st, "pending");
    assert!(state.db.verify_chain().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_pending_with_gateway_order_is_adopted_once() {
    let (app, state, master) = mock_app();
    let agent = "reclaim-adopt";
    let agent_key = ensure_agent_key(&app, &master, agent).await;
    let (mandate, sig) = issue(&app, &agent_key, agent).await;
    let mid = mandate["mandate_id"].as_str().unwrap().to_string();
    let nonce = mandate["nonce"].as_str().unwrap().to_string();
    crash_with_stale_pending(&state, &mid, &nonce, 1000);
    // Gateway already holds the order (e.g. crash after create, before finalize).
    let m: Mandate = serde_json::from_value(mandate.clone()).unwrap();
    let created = state.gateway.create_order(&m, 1000).await.unwrap();
    assert_eq!(state.gateway.mock_create_count(), 1);
    // Retry must adopt, creating NO new order (still exactly one create).
    let (status, body) = checkout(&app, &agent_key, &mandate, &sig).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "ALLOW");
    assert_eq!(body["order_id"].as_str().unwrap(), created.id.as_str());
    assert_eq!(state.gateway.mock_create_count(), 1);
    let (oid, st) = state.db.get_order_status(&mid).unwrap().unwrap();
    assert_eq!(oid, created.id);
    assert_eq!(st, "completed");
    assert!(state.db.verify_chain().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_pending_without_gateway_order_is_reclaimed_once() {
    let (app, state, master) = mock_app();
    let agent = "reclaim-create";
    let agent_key = ensure_agent_key(&app, &master, agent).await;
    let (mandate, sig) = issue(&app, &agent_key, agent).await;
    let mid = mandate["mandate_id"].as_str().unwrap().to_string();
    let nonce = mandate["nonce"].as_str().unwrap().to_string();
    crash_with_stale_pending(&state, &mid, &nonce, 1000);
    assert_eq!(state.gateway.mock_create_count(), 0);
    let (status, body) = checkout(&app, &agent_key, &mandate, &sig).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], "ALLOW");
    assert!(body["order_id"].as_str().is_some());
    // Exactly one gateway create (the retry's).
    assert_eq!(state.gateway.mock_create_count(), 1);
    let (_, st) = state.db.get_order_status(&mid).unwrap().unwrap();
    assert_eq!(st, "completed");
    // Nonce stays consumed by the identical owner (no replay).
    assert!(!state.db.try_claim_nonce(&nonce).unwrap());
    assert!(state.db.verify_chain().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_pending_lookup_error_stays_pending_with_503() {
    let (app, state, master) = failing_app(FailureMode::Error);
    let agent = "reclaim-err";
    let agent_key = ensure_agent_key(&app, &master, agent).await;
    let (mandate, sig) = issue(&app, &agent_key, agent).await;
    let mid = mandate["mandate_id"].as_str().unwrap().to_string();
    let nonce = mandate["nonce"].as_str().unwrap().to_string();
    crash_with_stale_pending(&state, &mid, &nonce, 1000);
    let (status, _) = checkout(&app, &agent_key, &mandate, &sig).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    // Row stays pending for a later retry; no order created.
    let (oid, st) = state.db.get_order_status(&mid).unwrap().unwrap();
    assert_eq!(oid, "__PENDING__");
    assert_eq!(st, "pending");
    assert!(state.db.get_cached_order(&mid).unwrap().is_none());
    assert!(state.db.verify_chain().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_retries_on_stale_row_single_winner() {
    let (app, state, master) = mock_app();
    let agent = "reclaim-race";
    let agent_key = ensure_agent_key(&app, &master, agent).await;
    let (mandate, sig) = issue(&app, &agent_key, agent).await;
    let mid = mandate["mandate_id"].as_str().unwrap().to_string();
    let nonce = mandate["nonce"].as_str().unwrap().to_string();
    crash_with_stale_pending(&state, &mid, &nonce, 1000);
    let ((s1, b1), (s2, b2)) = tokio::join!(
        checkout(&app, &agent_key, &mandate, &sig),
        checkout(&app, &agent_key, &mandate, &sig),
    );
    // Exactly one gateway create and exactly one completed order (no
    // double-charge). The loser either REJECTs on the CAS loss or, if the
    // winner already finalized, returns the same order via idempotent replay
    // — both are safe, never a second order.
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    let mut allow_ids = Vec::new();
    for b in [&b1, &b2] {
        if b["decision"] == "ALLOW" {
            allow_ids.push(b["order_id"].as_str().unwrap().to_string());
        }
    }
    assert!(
        !allow_ids.is_empty(),
        "at least one winner: {s1:?} {b1:?} / {s2:?} {b2:?}"
    );
    assert_eq!(state.gateway.mock_create_count(), 1);
    let (completed_id, completed_status) = state.db.get_order_status(&mid).unwrap().unwrap();
    assert_eq!(completed_status, "completed");
    for id in &allow_ids {
        assert_eq!(id, &completed_id);
    }
    assert_eq!(
        state.db.get_cached_order(&mid).unwrap().as_deref(),
        Some(completed_id.as_str())
    );
    assert!(state.db.verify_chain().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn different_mandate_same_nonce_stays_replay() {
    let (app, state, master) = mock_app();
    let agent = "reclaim-replay";
    let agent_key = ensure_agent_key(&app, &master, agent).await;
    let (mandate_a, sig_a) = issue(&app, &agent_key, agent).await;
    // First mandate succeeds, consuming its nonce.
    let (status, _) = checkout(&app, &agent_key, &mandate_a, &sig_a).await;
    assert_eq!(status, StatusCode::OK);
    let nonce = mandate_a["nonce"].as_str().unwrap().to_string();
    // Different mandate_id reusing the same nonce, freshly signed.
    let mut b: Mandate = serde_json::from_value(mandate_a.clone()).unwrap();
    b.mandate_id = format!("{}-other", b.mandate_id);
    let sig_b = state.authority.sign(&b).unwrap();
    let mandate_b = serde_json::to_value(&b).unwrap();
    let (status_b, body_b) = checkout(&app, &agent_key, &mandate_b, &sig_b).await;
    assert_eq!(status_b, StatusCode::OK);
    assert_eq!(body_b["decision"], "REJECT");
    assert!(body_b["reason"].as_str().unwrap().contains("nonce"));
    // No order for the forged id, original nonce never freed.
    assert!(state.db.get_order_status(&b.mandate_id).unwrap().is_none());
    assert!(!state.db.try_claim_nonce(&nonce).unwrap());
    assert!(state.db.verify_chain().unwrap());
}

/// Two concurrent identical retries both find the same gateway order and race
/// on finalizing the pending row. Only the caller whose UPDATE changes the row
/// may write the decision; the loser returns the same ALLOW + order_id without
/// a second row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_adopts_of_same_order_write_single_decision() {
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let (app, state, master) = mock_app_with_gateway(Gateway::mock_with_find_barrier_for_tests(
        Arc::clone(&barrier),
    ));
    let agent = "reclaim-adopt-race";
    let agent_key = ensure_agent_key(&app, &master, agent).await;
    let (mandate, sig) = issue(&app, &agent_key, agent).await;
    let mid = mandate["mandate_id"].as_str().unwrap().to_string();
    let nonce = mandate["nonce"].as_str().unwrap().to_string();
    crash_with_stale_pending(&state, &mid, &nonce, 1000);
    let m: Mandate = serde_json::from_value(mandate.clone()).unwrap();
    let created = state.gateway.create_order(&m, 1000).await.unwrap();
    assert_eq!(state.gateway.mock_create_count(), 1);

    let spawn_checkout = |app: axum::Router, key: String, mandate: Value, sig: String| {
        tokio::spawn(async move { checkout(&app, &key, &mandate, &sig).await })
    };
    let h1 = spawn_checkout(app.clone(), agent_key.clone(), mandate.clone(), sig.clone());
    let h2 = spawn_checkout(app.clone(), agent_key.clone(), mandate.clone(), sig.clone());
    // Both retries are parked inside find_order_by_receipt; release together.
    barrier.wait().await;
    let (s1, b1) = h1.await.unwrap();
    let (s2, b2) = h2.await.unwrap();

    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    for body in [&b1, &b2] {
        assert_eq!(body["decision"], "ALLOW");
        assert_eq!(body["order_id"].as_str().unwrap(), created.id.as_str());
    }
    assert_eq!(state.gateway.mock_create_count(), 1);
    let checkouts: Vec<_> = state
        .db
        .list_recent(10)
        .unwrap()
        .into_iter()
        .filter(|r| r.endpoint == "/v1/checkout")
        .collect();
    assert_eq!(checkouts.len(), 1, "exactly one decision row");
    assert_eq!(checkouts[0].decision, "ALLOW");
    let (oid, st) = state.db.get_order_status(&mid).unwrap().unwrap();
    assert_eq!(oid, created.id);
    assert_eq!(st, "completed");
    assert!(state.db.verify_chain().unwrap());
}
