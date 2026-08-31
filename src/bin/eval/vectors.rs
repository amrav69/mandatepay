use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use mandatepay::mandates::{Authority, Mandate, unix_now};
use serde_json::Value;

pub fn locally_signed(
    auth: &Authority,
    nonce: &str,
    merchant: &str,
    action: &str,
    version: u8,
    issued_offset_secs: i64,
    expires_offset_secs: i64,
) -> (Value, String) {
    let now = unix_now() as i64;
    let m = Mandate {
        version,
        mandate_id: format!("mnd_eval_{nonce}"),
        agent_id: "eval-attacker".into(),
        merchant_id: merchant.into(),
        action: action.into(),
        currency: "INR".into(),
        max_amount_minor: 49_900,
        issued_at: (now + issued_offset_secs) as u64,
        expires_at: (now + expires_offset_secs) as u64,
        nonce: format!("n_eval_{nonce}"),
    };
    let sig = auth.sign(&m).expect("local signing failed");
    (serde_json::to_value(&m).unwrap(), sig)
}

#[allow(dead_code)]
pub fn forged_signature() -> String {
    let mut raw = [0u8; 64];
    getrandom::fill(&mut raw).expect("os randomness unavailable");
    B64.encode(raw)
}
