use serde_json::{Value, json};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn master_key() -> String {
    std::env::var("MANDATEPAY_API_KEY")
        .map(|k| k.trim().to_string())
        .unwrap_or_default()
}

fn agent_headers(agent_key: &str) -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    if !agent_key.trim().is_empty() {
        if let Ok(v) = reqwest::header::HeaderValue::from_str(agent_key.trim()) {
            h.insert("X-API-Key", v);
        } else {
            eprintln!("chaos: agent key contains invalid header chars, sending unauthenticated");
        }
    }
    h
}

/// C1: master -> per-agent key for chaos-agent.
async fn ensure_agent_key(
    http: &reqwest::Client,
    server: &str,
    master: &str,
    agent_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let resp: Value = http
        .post(format!("{server}/v1/agents"))
        .header("X-API-Key", master)
        .json(&json!({"agent_id": agent_id}))
        .send()
        .await?
        .json()
        .await?;
    if let Some(k) = resp["api_key"].as_str() {
        return Ok(k.to_string());
    }
    let resp: Value = http
        .post(format!("{server}/v1/agents/{agent_id}/rotate"))
        .header("X-API-Key", master)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    resp["api_key"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "rotate did not return api_key".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let server = env_or("MANDATEPAY_URL", "http://127.0.0.1:8080");
    let http = reqwest::Client::new();
    let master = master_key();
    let agent_key = ensure_agent_key(&http, &server, &master, "chaos-agent").await?;

    println!("======================================================================");
    println!(" MANDATEPAY CHAOS — 10 concurrent checkouts on the SAME mandate");
    println!(
        " Expected: at-most-once with idempotent replay — allow+reject==10, 1 unique order, allow>=1"
    );
    println!("======================================================================");

    let issued: Value = http
        .post(format!("{server}/v1/mandates"))
        .headers(agent_headers(&agent_key))
        .json(&json!({
            "agent_id": "chaos-agent",
            "merchant_id": "merchant-001",
            "currency": "INR",
            "max_amount_minor": 50000,
            "ttl_secs": 600
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mandate = issued["mandate"].clone();
    let sig = issued["signature"].as_str().unwrap().to_string();
    println!(" minted {}", mandate["mandate_id"]);

    let mut handles = Vec::new();
    for i in 0..10 {
        let h = http.clone();
        let s = server.clone();
        let m = mandate.clone();
        let sig_c = sig.clone();
        let ak = agent_key.clone();
        handles.push(tokio::spawn(async move {
            let resp: Value = h
                .post(format!("{s}/v1/checkout"))
                .headers(agent_headers(&ak))
                .json(&json!({
                    "mandate": m,
                    "signature": sig_c,
                    "amount_minor": 10000
                }))
                .send()
                .await
                .expect("checkout send failed")
                .json()
                .await
                .unwrap_or(Value::Null);
            (i, resp)
        }));
    }

    let mut allow = 0;
    let mut reject = 0;
    let mut order_ids = std::collections::HashSet::new();
    for h in handles {
        let (i, body) = h.await?;
        let dec = body["decision"].as_str().unwrap_or("UNKNOWN");
        let reason = body["reason"].as_str().unwrap_or("");
        let oid = body["order_id"].as_str().map(|s| s.to_string());
        println!(
            "  task {i:2} -> {dec:6} {reason} order={}",
            oid.clone().unwrap_or_else(|| "-".into())
        );
        if dec == "ALLOW" {
            allow += 1;
            if let Some(id) = oid {
                order_ids.insert(id);
            }
        } else if dec == "REJECT" {
            reject += 1;
        }
    }

    println!("----------------------------------------------------------------------");
    println!(
        " result: {allow} ALLOW, {reject} REJECT, unique orders: {}",
        order_ids.len()
    );
    // With B17 idempotent early-cache (before nonce), concurrent retries that hit the
    // cache correctly return ALLOW with "idempotent replay: cached order returned"
    // instead of REJECT. So the strict 1/9 expectation is outdated — the invariant is
    // at-most-once: allow+reject==10, exactly 1 unique order, and at least 1 ALLOW.
    if allow + reject == 10 && order_ids.len() == 1 && allow >= 1 {
        println!(
            " CHAOS GREEN — at-most-once held under concurrent race (idempotent replay allowed)"
        );
        Ok(())
    } else {
        eprintln!(
            " CHAOS RED — expected allow+reject==10 with 1 unique order and allow>=1 (got {allow} ALLOW / {reject} REJECT)"
        );
        std::process::exit(1);
    }
}
