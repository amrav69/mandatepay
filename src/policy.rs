use crate::mandates::{Authority, Mandate, unix_now};
use crate::store::Db;

pub enum Decision {
    Allow { reason: String },
    Reject { reason: String },
}

fn reject(reason: impl Into<String>) -> Decision {
    Decision::Reject {
        reason: reason.into(),
    }
}

/// H11: side-effect-free validator shared by `evaluate` and the idempotency
/// early-cache path, so the cache cannot drift from the policy. Covers every
/// gate except the nonce claim (which has a DB side effect and stays in
/// `evaluate`).
pub fn validate_stateless(
    authority: &Authority,
    mandate: &Mandate,
    signature_b64: &str,
    amount_minor: u64,
    allowed_merchants: &[String],
) -> Decision {
    if mandate.version != 1 {
        return reject("unsupported mandate version");
    }
    if mandate.action != "create_order" {
        return reject(format!(
            "action '{}' is outside governor scope",
            mandate.action
        ));
    }
    if mandate.currency != "INR" {
        return reject(format!("currency '{}' not supported", mandate.currency));
    }
    if mandate.max_amount_minor == 0 {
        return reject("max_amount_minor must be positive");
    }
    if mandate.expires_at <= mandate.issued_at {
        return reject("expires_at must be after issued_at");
    }
    if mandate.agent_id.trim().is_empty() || mandate.merchant_id.trim().is_empty() {
        return reject("agent_id and merchant_id are required");
    }
    // 60s leeway for clock skew; beyond that reject future-dated mandates.
    if mandate.issued_at > unix_now().saturating_add(60) {
        return reject("issued_at is too far in the future");
    }
    if unix_now() >= mandate.expires_at {
        return reject("mandate expired");
    }

    if authority.verify(mandate, signature_b64).is_err() {
        return reject("invalid signature");
    }

    if !allowed_merchants.iter().any(|m| m == &mandate.merchant_id) {
        return reject(format!(
            "merchant '{}' is not allowlisted",
            mandate.merchant_id
        ));
    }
    if amount_minor == 0 {
        return reject("amount_minor must be positive");
    }
    if amount_minor > mandate.max_amount_minor {
        return reject(format!(
            "amount {amount_minor} exceeds mandate cap {}",
            mandate.max_amount_minor
        ));
    }

    Decision::Allow {
        reason: "stateless checks passed".into(),
    }
}

pub fn evaluate(
    authority: &Authority,
    mandate: &Mandate,
    signature_b64: &str,
    amount_minor: u64,
    allowed_merchants: &[String],
    db: &Db,
) -> Decision {
    // H11: reuse the shared validator so evaluate and early-cache agree.
    if let Decision::Reject { reason } = validate_stateless(
        authority,
        mandate,
        signature_b64,
        amount_minor,
        allowed_merchants,
    ) {
        return Decision::Reject { reason };
    }

    match db.try_claim_nonce(&mandate.nonce) {
        Ok(true) => {}
        Ok(false) => return reject("nonce already consumed: possible replay"),
        Err(e) => return reject(format!("nonce ledger failure: {e}")),
    }

    Decision::Allow {
        reason: "signature, scope, merchant, amount, expiry and replay checks passed".into(),
    }
}
