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
    tracing::warn!(ephemeral_key = %k, "MANDATEPAY_API_KEY not set — generated ephemeral key; set in .env to persist");
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn verify_rejects_empty() {
        assert!(!verify_api_key("", "abc"));
        assert!(!verify_api_key("abc", ""));
        assert!(!verify_api_key("", ""));
    }

    #[test]
    fn verify_matches_exact_and_rejects_mismatch() {
        assert!(verify_api_key("secret123", "secret123"));
        assert!(!verify_api_key("secret123", "secret124"));
    }

    #[test]
    fn extract_from_x_api_key() {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_static("my-key"));
        assert_eq!(extract_api_key(&h).as_deref(), Some("my-key"));
    }

    #[test]
    fn extract_from_bearer() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my-token"),
        );
        assert_eq!(extract_api_key(&h).as_deref(), Some("my-token"));
    }

    #[test]
    fn extract_prefers_x_api_key_over_bearer() {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_static("x-key"));
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer bearer-key"),
        );
        assert_eq!(extract_api_key(&h).as_deref(), Some("x-key"));
    }

    #[test]
    fn extract_missing_returns_none() {
        let h = HeaderMap::new();
        assert!(extract_api_key(&h).is_none());
    }
}
