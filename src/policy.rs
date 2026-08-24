use crate::mandates::{unix_now, Authority, Mandate, VerifyError};
use crate::store::Db;

pub enum Decision {
    Allow { reason: String },
    Reject { reason: String },
}

fn reject(reason: impl Into<String>) -> Decision {
    Decision::Reject { reason: reason.into() }
}

pub fn evaluate(
    authority: &Authority,
    mandate: &Mandate,
    signature_b64: &str,
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

    if let Err(e) = authority.verify(mandate, signature_b64) {
        return reject(match e {
            VerifyError::MalformedSignature => "malformed signature encoding",
            VerifyError::InvalidSignature => "signature does not verify against mandate authority",
            VerifyError::Canonicalization(_) => "canonical serialization failed",
        });
    }

    if unix_now() >= mandate.expires_at {
        return reject("mandate expired");
    }

    match db.try_claim_nonce(&mandate.nonce) {
        Ok(true) => {}
        Ok(false) => return reject("nonce already consumed: possible replay"),
        Err(e) => return reject(format!("nonce ledger failure: {e}")),
    }

    Decision::Allow {
        reason: "signature, scope, expiry and replay checks passed".into(),
    }
}
