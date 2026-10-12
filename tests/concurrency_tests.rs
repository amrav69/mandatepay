#[allow(dead_code)]
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::{ensure_agent_key, test_app};
use mandatepay::mandates::{Authority, unix_now};
use serde_json::{Value, json};
use std::collections::HashSet;
use tower::util::ServiceExt;

async fn issue_mandate(app: &axum::Router, agent_key: &str, agent: &str) -> (Value, String) {
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

async fn post_checkout(app: &axum::Router, agent_key: &str, mandate: &Value, sig: &str) -> Value {
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
    assert_eq!(resp.status(), StatusCode::OK);
    serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn same_mandate_barrage_once(round: usize) {
    let (app, master) = test_app();
    let agent = format!("conc-b2-{round}");
    let agent_key = ensure_agent_key(&app, &master, &agent).await;
    let (mandate, sig) = issue_mandate(&app, &agent_key, &agent).await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(10));
    let mut handles = Vec::new();
    for _ in 0..10 {
        let (a, k, m, s, b) = (
            app.clone(),
            agent_key.clone(),
            mandate.clone(),
            sig.clone(),
            barrier.clone(),
        );
        handles.push(tokio::spawn(async move {
            b.wait().await;
            post_checkout(&a, &k, &m, &s).await
        }));
    }
    let mut allow = 0;
    let mut reject = 0;
    let mut orders = HashSet::new();
    for h in handles {
        let body = h.await.unwrap();
        match body["decision"].as_str().unwrap() {
            "ALLOW" => {
                allow += 1;
                orders.insert(body["order_id"].as_str().unwrap().to_string());
            }
            "REJECT" => reject += 1,
            d => panic!("round {round}: unexpected decision {d}"),
        }
    }
    assert_eq!(allow + reject, 10, "round {round}: every task must answer");
    assert!(allow >= 1, "round {round}: at least the winner must ALLOW");
    assert_eq!(orders.len(), 1, "round {round}: duplicate gateway orders!");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/chain/verify")
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
    assert_eq!(
        body["chain_valid"], true,
        "round {round}: chain must verify"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_same_mandate_nonce_agent_single_order() {
    for round in 0..5 {
        same_mandate_barrage_once(round).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_same_agent_velocity_never_exceeded() {
    let (app, master) = test_app();
    let agent_key = ensure_agent_key(&app, &master, "conc-vel").await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/v1/agents/conc-vel")
                .header("content-type", "application/json")
                .header("x-api-key", &master)
                .body(Body::from(json!({"velocity_limit": 5}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let authority = Authority::from_seed([7u8; 32]);
    let now = unix_now();
    let mut bodies = Vec::new();
    for i in 0..20 {
        let mandate = serde_json::to_value(mandatepay::mandates::Mandate {
            version: 1,
            mandate_id: format!("mnd_conc_vel_{i}"),
            agent_id: "conc-vel".into(),
            merchant_id: "merchant-001".into(),
            action: "create_order".into(),
            currency: "INR".into(),
            max_amount_minor: 50_000,
            issued_at: now - 1,
            expires_at: now + 3_600,
            nonce: format!("n_conc_vel_{i}"),
        })
        .unwrap();
        let m: mandatepay::mandates::Mandate = serde_json::from_value(mandate.clone()).unwrap();
        let sig = authority.sign(&m).unwrap();
        bodies.push((mandate, sig));
    }
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(20));
    let mut handles = Vec::new();
    for (mandate, sig) in bodies {
        let (a, k, b) = (app.clone(), agent_key.clone(), barrier.clone());
        handles.push(tokio::spawn(async move {
            b.wait().await;
            post_checkout(&a, &k, &mandate, &sig).await
        }));
    }
    let mut allow = 0;
    let mut velocity_reject = 0;
    let mut orders = HashSet::new();
    for h in handles {
        let body = h.await.unwrap();
        match body["decision"].as_str().unwrap() {
            "ALLOW" => {
                allow += 1;
                orders.insert(body["order_id"].as_str().unwrap().to_string());
            }
            "REJECT" => {
                let reason = body["reason"].as_str().unwrap();
                assert!(
                    reason.contains("velocity limit exceeded"),
                    "non-velocity reject under barrage: {reason}"
                );
                velocity_reject += 1;
            }
            d => panic!("unexpected decision {d}"),
        }
    }
    assert_eq!(allow, 5, "velocity limit 5 must admit exactly 5");
    assert_eq!(velocity_reject, 15);
    assert_eq!(orders.len(), 5);
}

#[test]
fn concurrent_same_nonce_single_claim_at_db_level() {
    use mandatepay::store::Db;
    use std::sync::Arc;
    let db = Arc::new(Db::open(":memory:").unwrap());
    let mut handles = Vec::new();
    for _ in 0..20 {
        let d = db.clone();
        handles.push(std::thread::spawn(move || {
            d.try_claim_nonce("n_race").unwrap()
        }));
    }
    let trues = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|&b| b)
        .count();
    assert_eq!(trues, 1, "exactly one thread must claim the nonce");
    let mut handles = Vec::new();
    for _ in 0..20 {
        let d = db.clone();
        handles.push(std::thread::spawn(move || {
            d.try_reserve_order("mnd_race", 100).unwrap()
        }));
    }
    let trues = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|&b| b)
        .count();
    assert_eq!(trues, 1, "exactly one thread must reserve the mandate");
}
