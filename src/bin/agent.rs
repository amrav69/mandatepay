use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Instant;

#[derive(Deserialize)]
struct LlmResponse {
    choices: Vec<LlmChoice>,
}

#[derive(Deserialize)]
struct LlmChoice {
    message: LlmMessage,
}

#[derive(Deserialize)]
struct LlmMessage {
    content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Proposal {
    item: String,
    merchant_id: String,
    amount_minor: u64,
    reasoning: String,
}

#[derive(Deserialize)]
struct IssuedResponse {
    mandate: serde_json::Value,
    signature: String,
}

#[derive(Deserialize)]
struct CheckoutResponse {
    decision: String,
    reason: String,
    order_id: Option<String>,
    gateway: String,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn extract_json(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end < start {
        None
    } else {
        Some(&text[start..=end])
    }
}

fn fallback_proposal(budget: u64) -> Proposal {
    Proposal {
        item: "wired earphones (deterministic fallback, no LLM key configured)".into(),
        merchant_id: "merchant-001".into(),
        amount_minor: budget * 3 / 5,
        reasoning: "LLM_API_KEY not set; deterministic mid-budget proposal used to exercise the mandate loop".into(),
    }
}

async fn ask_llm(
    http: &reqwest::Client,
    base_url: &str,
    model: &str,
    api_key: &str,
    goal: &str,
    budget: u64,
) -> Result<(Proposal, u128), Box<dyn std::error::Error>> {
    let system = format!(
        "You are an autonomous shopping agent with a hard wallet budget of {budget} paise \
         (INR minor units; 100 paise = 1 rupee). Respond with ONLY a JSON object, no prose, \
         no markdown fences, in exactly this shape: \
         {{\"item\": string, \"merchant_id\": string, \"amount_minor\": integer, \"reasoning\": string}}. \
         merchant_id must be exactly \"merchant-001\". amount_minor must be a realistic price \
         for the requested item and must not exceed the budget."
    );
    let body = json!({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": goal}
        ],
        "temperature": 0.2,
        "max_tokens": 2048
    });

    let start = Instant::now();
    let resp: LlmResponse = http
        .post(format!("{base_url}/chat/completions"))
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let elapsed = start.elapsed().as_millis();

    let content = resp
        .choices
        .first()
        .and_then(|c| c.message.content.clone())
        .unwrap_or_default();
    let raw = extract_json(&content).ok_or("model returned no JSON object")?;
    let proposal: Proposal = serde_json::from_str(raw)?;
    Ok((proposal, elapsed))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let server = env_or("MANDATEPAY_URL", "http://127.0.0.1:8080");
    let base_url = env_or("LLM_BASE_URL", "https://integrate.api.nvidia.com/v1");
    let model = env_or("LLM_MODEL", "nvidia/nemotron-3-super-120b-a12b");
    let agent_id = env_or("AGENT_ID", "agent-llm-01");
    let goal = env_or(
        "AGENT_GOAL",
        "Buy a good pair of wired earphones from merchant-001 at a fair market price",
    );
    let budget: u64 = env_or("AGENT_BUDGET_MINOR", "50000")
        .parse()
        .expect("AGENT_BUDGET_MINOR must be an integer");

    let api_key = std::env::var("LLM_API_KEY").unwrap_or_default();
    let gov_key = std::env::var("MANDATEPAY_API_KEY").unwrap_or_default();
    let http = reqwest::Client::new();

    println!("[agent] goal: {goal}");
    println!(
        "[agent] budget: {budget} minor (₹{:.2})",
        budget as f64 / 100.0
    );

    let (proposal, llm_ms) = if api_key.is_empty() {
        eprintln!("[agent] LLM_API_KEY missing -> deterministic fallback proposal");
        (fallback_proposal(budget), 0)
    } else {
        match ask_llm(&http, &base_url, &model, &api_key, &goal, budget).await {
            Ok((p, ms)) => {
                println!("[agent] model {model} responded in {ms} ms");
                (p, ms)
            }
            Err(e) => {
                eprintln!("[agent] LLM call failed ({e}); falling back to deterministic proposal");
                (fallback_proposal(budget), 0)
            }
        }
    };
    let _ = llm_ms;

    println!("[agent] proposal: {}", serde_json::to_string(&proposal)?);

    if proposal.amount_minor > budget {
        eprintln!(
            "[agent] ABORT: proposal {} exceeds wallet budget {budget}; refusing to request a mandate",
            proposal.amount_minor
        );
        std::process::exit(2);
    }
    if proposal.amount_minor == 0 {
        eprintln!("[agent] ABORT: proposal amount is zero; refusing to proceed");
        std::process::exit(2);
    }

    let mut req = http.post(format!("{server}/v1/mandates")).json(&json!({
        "agent_id": agent_id,
        "merchant_id": proposal.merchant_id,
        "currency": "INR",
        "max_amount_minor": budget,
        "ttl_secs": 600
    }));
    if !gov_key.is_empty() {
        req = req.header("X-API-Key", &gov_key);
    }
    let issued: IssuedResponse = req.send().await?.error_for_status()?.json().await?;
    println!("[agent] mandate issued: {}", issued.mandate["mandate_id"]);

    let mut req = http.post(format!("{server}/v1/checkout")).json(&json!({
        "mandate": issued.mandate,
        "signature": issued.signature,
        "amount_minor": proposal.amount_minor
    }));
    if !gov_key.is_empty() {
        req = req.header("X-API-Key", &gov_key);
    }
    let decision: CheckoutResponse = req.send().await?.error_for_status()?.json().await?;

    println!("[agent] decision: {}", decision.decision);
    println!("[agent] reason: {}", decision.reason);
    println!("[agent] gateway: {}", decision.gateway);
    match decision.order_id {
        Some(id) => println!("[agent] order: {id}"),
        None => println!("[agent] order: none"),
    }

    if decision.decision == "ALLOW" {
        println!("[agent] purchase complete within bounded mandate");
        Ok(())
    } else {
        eprintln!("[agent] purchase rejected; reporting honestly, not retrying");
        std::process::exit(1);
    }
}
