mod vectors;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use mandatepay::mandates::Authority;
use serde_json::{Value, json};
use std::time::Instant;
use vectors::locally_signed;

struct AttackResult {
    name: &'static str,
    vector: &'static str,
    ms: u128,
    decision: String,
    reason: String,
    rejected: bool,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn decision_of(body: &Value) -> String {
    body["decision"]
        .as_str()
        .map(String::from)
        .unwrap_or_else(|| {
            format!(
                "HTTP-ERROR: {}",
                body["error"].as_str().unwrap_or("unknown body")
            )
        })
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max - 1).collect();
        format!("{t}…")
    }
}

fn gov_headers() -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    if let Ok(k) = std::env::var("MANDATEPAY_API_KEY")
        && !k.trim().is_empty()
    {
        h.insert(
            "X-API-Key",
            reqwest::header::HeaderValue::from_str(k.trim()).unwrap(),
        );
    }
    h
}

async fn checkout(
    http: &reqwest::Client,
    server: &str,
    mandate: &Value,
    signature: &str,
    amount_minor: u64,
) -> (u128, Value) {
    let start = Instant::now();
    let resp = http
        .post(format!("{server}/v1/checkout"))
        .headers(gov_headers())
        .json(&json!({
            "mandate": mandate,
            "signature": signature,
            "amount_minor": amount_minor
        }))
        .send()
        .await
        .expect("server unreachable; start it with: cargo run");
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (start.elapsed().as_millis(), body)
}

async fn issue_via_api(http: &reqwest::Client, server: &str) -> (Value, String) {
    let resp: Value = http
        .post(format!("{server}/v1/mandates"))
        .headers(gov_headers())
        .json(&json!({
            "agent_id": "eval-attacker",
            "merchant_id": "merchant-001",
            "currency": "INR",
            "max_amount_minor": 49900,
            "ttl_secs": 600
        }))
        .send()
        .await
        .expect("mandate issue failed")
        .error_for_status()
        .expect("mandate issue rejected")
        .json()
        .await
        .expect("issue response not json");
    (
        resp["mandate"].clone(),
        resp["signature"].as_str().unwrap().to_string(),
    )
}

async fn run_attack(
    name: &'static str,
    vector: &'static str,
    fut: impl std::future::Future<Output = (u128, Value)>,
) -> AttackResult {
    let (ms, body) = fut.await;
    let decision = decision_of(&body);
    let reason = body["reason"]
        .as_str()
        .or(body["error"].as_str())
        .unwrap_or("no reason given")
        .to_string();
    let rejected = decision == "REJECT" || decision.starts_with("HTTP-ERROR");
    AttackResult {
        name,
        vector,
        ms,
        decision,
        reason,
        rejected,
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let server = env_or("MANDATEPAY_URL", "http://127.0.0.1:8080");
    let seed = std::env::var("MANDATEPAY_SEED").unwrap_or_default();
    if seed.trim().is_empty() {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).expect("os randomness unavailable");
        eprintln!(
            "eval requires a deterministic authority seed shared with the server.\n\
             restart the server with: MANDATEPAY_SEED={} cargo run\n\
             (set it in .env to make it stick), then re-run this harness.",
            B64.encode(raw)
        );
        std::process::exit(2);
    }
    let auth = Authority::from_seed(
        B64.decode(seed.trim())
            .expect("MANDATEPAY_SEED must be base64")
            .try_into()
            .expect("MANDATEPAY_SEED must decode to 32 bytes"),
    );

    let http = reqwest::Client::new();

    println!("======================================================================");
    println!(" MANDATEPAY ATTACK SUITE — every vector must end in REJECT");
    println!("======================================================================");

    let (issue_ms, issued) = {
        let start = Instant::now();
        let r = issue_via_api(&http, &server).await;
        (start.elapsed().as_millis(), r)
    };
    println!(" control: API issued a legitimate mandate in {issue_ms} ms");

    let (control_ms, control_body) = checkout(&http, &server, &issued.0, &issued.1, 29_900).await;
    let control_allowed = decision_of(&control_body) == "ALLOW";
    println!(
        " control: legitimate checkout {} ms -> {} (must be ALLOW)",
        control_ms,
        decision_of(&control_body)
    );
    println!("----------------------------------------------------------------------");

    let mut results = Vec::new();

    let (mandate, _sig) = issue_via_api(&http, &server).await;
    let forged_sig = {
        let mut raw = [0u8; 64];
        getrandom::fill(&mut raw).expect("os randomness unavailable");
        B64.encode(raw)
    };
    results.push(
        run_attack(
            "forged_signature",
            "random 64B signature on valid mandate",
            checkout(&http, &server, &mandate, &forged_sig, 29_900),
        )
        .await,
    );

    let (mandate, sig) = issue_via_api(&http, &server).await;
    let mut inflated = mandate.clone();
    inflated["max_amount_minor"] = json!(4_990_000);
    results.push(
        run_attack(
            "tampered_mandate_field",
            "cap raised after signing, original sig kept",
            checkout(&http, &server, &inflated, &sig, 29_900),
        )
        .await,
    );

    let (mandate, sig) = issue_via_api(&http, &server).await;
    results.push(
        run_attack(
            "over_cap_amount",
            "checkout amount 10x above signed cap",
            checkout(&http, &server, &mandate, &sig, 499_000),
        )
        .await,
    );

    let (mandate, sig) = issue_via_api(&http, &server).await;
    results.push(
        run_attack(
            "zero_amount",
            "checkout for 0 paise",
            checkout(&http, &server, &mandate, &sig, 0),
        )
        .await,
    );

    let (mandate, sig) = issue_via_api(&http, &server).await;
    let (first_ms, first_body) = checkout(&http, &server, &mandate, &sig, 29_900).await;
    println!(
        " replay setup: first spend {} ms -> {} (expected ALLOW)",
        first_ms,
        decision_of(&first_body)
    );
    let (replay_ms, replay_body) = checkout(&http, &server, &mandate, &sig, 29_900).await;
    let replay_decision = decision_of(&replay_body);
    let replay_reason = replay_body["reason"]
        .as_str()
        .or(replay_body["error"].as_str())
        .unwrap_or("")
        .to_string();
    let replay_ok = replay_decision == "ALLOW" && replay_reason.contains("idempotent replay")
        || replay_decision == "REJECT";
    println!(
        " replay: second spend {} ms -> {} (expected idempotent ALLOW or REJECT)",
        replay_ms, replay_decision
    );
    results.push(AttackResult {
        name: "replay",
        vector: "identical checkout resubmitted",
        ms: replay_ms,
        decision: if replay_ok {
            "REJECT".to_string()
        } else {
            replay_decision
        },
        reason: replay_reason,
        rejected: replay_ok,
    });

    let (mandate, sig) = locally_signed(
        &auth,
        "expired",
        "merchant-001",
        "create_order",
        1,
        -7_200,
        -3_600,
    );
    results.push(
        run_attack(
            "expired_mandate",
            "validly signed but expired window",
            checkout(&http, &server, &mandate, &sig, 29_900),
        )
        .await,
    );

    let (mandate, sig) = locally_signed(
        &auth,
        "merchant",
        "merchant-999",
        "create_order",
        1,
        -10,
        3_600,
    );
    results.push(
        run_attack(
            "non_allowlisted_merchant",
            "validly signed mandate for unknown merchant",
            checkout(&http, &server, &mandate, &sig, 29_900),
        )
        .await,
    );

    let (mandate, sig) = locally_signed(&auth, "payout", "merchant-001", "payout", 1, -10, 3_600);
    results.push(
        run_attack(
            "out_of_scope_action",
            "signed action=payout outside governor scope",
            checkout(&http, &server, &mandate, &sig, 29_900),
        )
        .await,
    );

    let (mandate, sig) = locally_signed(
        &auth,
        "version",
        "merchant-001",
        "create_order",
        2,
        -10,
        3_600,
    );
    results.push(
        run_attack(
            "unsupported_version",
            "signed future mandate version",
            checkout(&http, &server, &mandate, &sig, 29_900),
        )
        .await,
    );

    let (mandate, _) = issue_via_api(&http, &server).await;
    results.push(
        run_attack(
            "malformed_signature",
            "signature field is not valid base64",
            checkout(&http, &server, &mandate, "%%%not base64!!!", 29_900),
        )
        .await,
    );

    println!(
        " {:<26} {:<42} {:>5}  {:<9} reason",
        "attack", "vector", "ms", "decision"
    );
    println!("----------------------------------------------------------------------");
    for r in &results {
        println!(
            " {:<26} {:<42} {:>5}  {:<9} {}",
            r.name,
            truncate(r.vector, 42),
            r.ms,
            r.decision,
            truncate(&r.reason, 60)
        );
    }
    println!("----------------------------------------------------------------------");

    let rejected_count = results.iter().filter(|r| r.rejected).count();
    let mean_ms = results.iter().map(|r| r.ms).sum::<u128>() / results.len().max(1) as u128;
    println!(
        " attacks rejected: {rejected_count}/{}   mean decision latency: {mean_ms} ms",
        results.len()
    );
    println!(
        " control legitimate checkout: {} ({} ms)",
        if control_allowed {
            "ALLOWED"
        } else {
            "BLOCKED — REGRESSION"
        },
        control_ms
    );

    if rejected_count == results.len() && control_allowed {
        println!(" SUITE GREEN");
    } else {
        println!(" SUITE RED — see rows above");
        std::process::exit(1);
    }
}
