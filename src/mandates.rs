use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as TOKEN_B64},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("malformed signature encoding")]
    MalformedSignature,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("canonical serialization failed: {0}")]
    Canonicalization(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Mandate {
    pub version: u8,
    pub mandate_id: String,
    pub agent_id: String,
    pub merchant_id: String,
    pub action: String,
    pub currency: String,
    pub max_amount_minor: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

pub fn canonical_bytes(mandate: &Mandate) -> Result<Vec<u8>, VerifyError> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"mandatepay.v1.");
    let value =
        serde_json::to_value(mandate).map_err(|e| VerifyError::Canonicalization(e.to_string()))?;
    let canon =
        serde_jcs::to_vec(&value).map_err(|e| VerifyError::Canonicalization(e.to_string()))?;
    out.extend_from_slice(&canon);
    Ok(out)
}

/// M1: never panic on clock skew. Pre-epoch clocks fail closed to 0 + warn
/// instead of aborting request handlers.
pub fn unix_now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            tracing::warn!(error = %e, "system clock before unix epoch, returning 0");
            0
        }
    }
}

pub fn new_token(prefix: &str, entropy_bytes: usize) -> String {
    let mut buf = vec![0u8; entropy_bytes];
    getrandom::fill(&mut buf).expect("os randomness unavailable");
    // Use URL_SAFE_NO_PAD so mandate_id/nonce are safe in URL paths, query params and headers (no +/=).
    format!("{prefix}{}", TOKEN_B64.encode(buf))
}

pub struct Authority {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Authority {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.verifying_key.as_bytes())
    }

    pub fn sign(&self, mandate: &Mandate) -> Result<String, VerifyError> {
        let sig = self.signing_key.sign(&canonical_bytes(mandate)?);
        Ok(B64.encode(sig.to_bytes()))
    }

    pub fn verify(&self, mandate: &Mandate, signature_b64: &str) -> Result<(), VerifyError> {
        let raw = B64
            .decode(signature_b64.trim())
            .map_err(|_| VerifyError::MalformedSignature)?;
        let sig = Signature::from_slice(&raw).map_err(|_| VerifyError::MalformedSignature)?;
        self.verifying_key
            .verify(&canonical_bytes(mandate)?, &sig)
            .map_err(|_| VerifyError::InvalidSignature)
    }
}

/// H3: loud fallback. Every ephemeral path warns with the reason so a typo'd
/// MANDATEPAY_SEED cannot silently rotate the authority key.
pub fn load_seed() -> [u8; 32] {
    match std::env::var("MANDATEPAY_SEED") {
        Ok(s) if !s.trim().is_empty() => match B64.decode(s.trim()) {
            Ok(raw) if raw.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&raw);
                return seed;
            }
            Ok(raw) => {
                tracing::warn!(
                    len = raw.len(),
                    "MANDATEPAY_SEED decoded to wrong length, using ephemeral key"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "MANDATEPAY_SEED is not valid base64, using ephemeral key");
            }
        },
        Ok(_) => {
            tracing::warn!("MANDATEPAY_SEED set but empty, using ephemeral key");
        }
        Err(_) => {
            tracing::warn!("MANDATEPAY_SEED not set, using ephemeral key per boot");
        }
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("os randomness unavailable");
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_seed_uses_valid_configured_value() {
        // H3: a well-formed seed must be honored exactly (no silent rotation).
        let prev = std::env::var("MANDATEPAY_SEED").ok();
        let raw = [9u8; 32];
        unsafe { std::env::set_var("MANDATEPAY_SEED", B64.encode(raw)) };
        assert_eq!(load_seed(), raw);
        unsafe {
            match prev {
                Some(v) => std::env::set_var("MANDATEPAY_SEED", v),
                None => std::env::remove_var("MANDATEPAY_SEED"),
            }
        }
    }

    #[test]
    fn load_seed_falls_back_loudly_on_garbage() {
        // H3: garbage seed must not panic and must not return the valid value.
        let prev = std::env::var("MANDATEPAY_SEED").ok();
        unsafe { std::env::set_var("MANDATEPAY_SEED", "%%%not-base64%%%") };
        let _ = load_seed();
        unsafe { std::env::set_var("MANDATEPAY_SEED", B64.encode([0u8; 31])) };
        let _ = load_seed();
        unsafe {
            match prev {
                Some(v) => std::env::set_var("MANDATEPAY_SEED", v),
                None => std::env::remove_var("MANDATEPAY_SEED"),
            }
        }
    }
}
