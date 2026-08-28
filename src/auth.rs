use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use subtle::ConstantTimeEq;

pub fn resolve_api_key() -> String {
    if let Ok(k) = std::env::var("MANDATEPAY_API_KEY")
        && !k.trim().is_empty()
    {
        return k.trim().to_string();
    }
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).expect("os randomness unavailable");
    let k = B64.encode(raw);
    eprintln!("MANDATEPAY_API_KEY not set — generated ephemeral key: {k}");
    eprintln!("Set MANDATEPAY_API_KEY in .env to keep the same key across restarts.");
    k
}

pub fn verify_api_key(provided: &str, expected: &str) -> bool {
    if provided.is_empty() || expected.is_empty() {
        return false;
    }
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

pub fn extract_api_key(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok())
        && !v.trim().is_empty()
    {
        return Some(v.trim().to_string());
    }
    if let Some(v) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let t = v.trim();
        if let Some(rest) = t.strip_prefix("Bearer ") {
            if !rest.trim().is_empty() {
                return Some(rest.trim().to_string());
            }
        } else if let Some(rest) = t.strip_prefix("bearer ")
            && !rest.trim().is_empty()
        {
            return Some(rest.trim().to_string());
        }
    }
    None
}
