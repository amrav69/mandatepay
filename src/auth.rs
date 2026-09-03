use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use sha2::{Digest, Sha256};
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
    let hash = hex::encode(Sha256::digest(k.as_bytes()));
    tracing::warn!(ephemeral_key_hash = %hash[..16], "MANDATEPAY_API_KEY not set — generated ephemeral key; set in .env to persist");
    k
}

pub fn verify_api_key(provided: &str, expected: &str) -> bool {
    if provided.is_empty() || expected.is_empty() {
        return false;
    }
    // M8: length-constant comparison — hash both to fixed 32B before ct_eq so
    // `subtle::ConstantTimeEq` on slices (which short-circuits on length mismatch)
    // does not leak the expected key length.
    let p_hash = Sha256::digest(provided.as_bytes());
    let e_hash = Sha256::digest(expected.as_bytes());
    p_hash.as_slice().ct_eq(e_hash.as_slice()).into()
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

    #[test]
    fn verify_different_lengths_rejected_length_constant() {
        // Regression for M8: verify must not leak length via early return.
        // Hash-before-compare ensures fixed-length ct_eq, so different lengths still
        // correctly return false without leaking.
        assert!(!verify_api_key("short", "very-long-secret-key-value"));
        assert!(!verify_api_key("very-long-secret-key-value", "short"));
        assert!(!verify_api_key("a", "ab"));
        // Same length but different content also rejected
        assert!(!verify_api_key("secret1234", "secret1235"));
        // Empty already covered but ensure consistent
        assert!(!verify_api_key("", "not-empty"));
    }
}
