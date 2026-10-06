use crate::mandates::{Authority, Mandate, unix_now};
use crate::store::Db;

/// Maximum tolerated clock skew between issuer and verifier. A mandate whose
/// `issued_at` lies further in the future is rejected as not-yet-valid.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;

pub enum Decision {
    Allow { reason: String },
    Reject { reason: String },
}

fn reject(reason: impl Into<String>) -> Decision {
    Decision::Reject {
        reason: reason.into(),
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
    if unix_now() >= mandate.expires_at {
        return reject("mandate expired");
    }
    if mandate.issued_at > unix_now().saturating_add(MAX_CLOCK_SKEW_SECS) {
        return reject("mandate issued_at is in the future");
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

    match db.try_claim_nonce(&mandate.nonce) {
        Ok(true) => {}
        Ok(false) => {
            // The nonce is already claimed. That usually means a replay — but
            // it can also mean the original attempt crashed after claiming the
            // nonce and reserving a pending order without ever reaching the
            // gateway. If that pending reservation is stale (older than
            // PENDING_TTL_SECS), reclaim frees the dead claim; retry the claim
            // exactly once. Fresh pending rows are never touched, so a live
            // concurrent attempt still wins and this stays a replay reject.
            let reclaimed = db
                .reclaim_stale_pending(&mandate.mandate_id)
                .unwrap_or(false);
            if reclaimed {
                match db.try_claim_nonce(&mandate.nonce) {
                    Ok(true) => {}
                    _ => return reject("nonce already consumed: possible replay"),
                }
            } else {
                return reject("nonce already consumed: possible replay");
            }
        }
        Err(e) => return reject(format!("nonce ledger failure: {e}")),
    }

    Decision::Allow {
        reason: "signature, scope, merchant, amount, expiry and replay checks passed".into(),
    }
}
