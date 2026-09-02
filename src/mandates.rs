use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
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

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

pub fn new_token(prefix: &str, entropy_bytes: usize) -> String {
    let mut buf = vec![0u8; entropy_bytes];
    getrandom::fill(&mut buf).expect("os randomness unavailable");
    format!("{prefix}{}", B64.encode(buf))
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

pub fn load_seed() -> [u8; 32] {
    if let Ok(s) = std::env::var("MANDATEPAY_SEED")
        && let Ok(raw) = B64.decode(s.trim())
        && raw.len() == 32
    {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        return seed;
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("os randomness unavailable");
    seed
}
