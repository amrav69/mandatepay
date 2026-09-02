use serde_json::{Value, json};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let server = env_or("MANDATEPAY_URL", "http://127.0.0.1:8080");
    let http = reqwest::Client::new();

    println!("======================================================================");
    println!(" MANDATEPAY CHAOS — 10 concurrent checkouts on the SAME mandate");
    println!(
        " Expected: at-most-once with idempotent replay — allow+reject==10, 1 unique order, allow>=1"
    );
    println!("======================================================================");

    let issued: Value = http
        .post(format!("{server}/v1/mandates"))
        .headers(gov_headers())
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
        handles.push(tokio::spawn(async move {
            let resp: Value = h
                .post(format!("{s}/v1/checkout"))
                .headers(gov_headers())
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
