use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::canonical::{cart_bytes, intent_hash};
use crate::error::Reject;
use crate::types::{CURRENCY, CartMandate, IntentMandate, PrincipalApproval, VERSION};

/// Checks that the human really approved `intent_hash`.
/// Phase 1 ships [`Ed25519Principal`]; phase 2 adds a WebAuthn (passkey) verifier.
pub trait ApprovalVerifier {
    fn verify(&self, intent_hash: &[u8; 32], approval: &PrincipalApproval) -> Result<(), Reject>;
}

/// A principal whose approval key is a plain Ed25519 key the human holds.
/// Useful for tests and CLI demos. The server only ever has the public half.
pub struct Ed25519Principal {
    pub principal_id: String,
    pub public_key: VerifyingKey,
}

impl ApprovalVerifier for Ed25519Principal {
    fn verify(&self, intent_hash: &[u8; 32], approval: &PrincipalApproval) -> Result<(), Reject> {
        if approval.principal_id != self.principal_id {
            return Err(Reject::Approval);
        }
        let sig = decode_sig(&approval.signature).ok_or(Reject::Approval)?;
        self.public_key
            .verify(intent_hash, &sig)
            .map_err(|_| Reject::Approval)
    }
}

/// What a passing checkout is allowed to charge.
#[derive(Debug, PartialEq, Eq)]
pub struct Approved {
    pub amount_minor: u64,
    pub merchant_id: String,
    /// The caller must claim this atomically (e.g. SQLite PRIMARY KEY) and
    /// add `amount_minor` to the intent's spent total in the same transaction.
    pub cart_nonce: String,
}

fn decode_sig(b64: &str) -> Option<Signature> {
    let raw = B64.decode(b64.trim()).ok()?;
    Signature::from_slice(&raw).ok()
}

fn decode_pubkey(b64: &str) -> Option<VerifyingKey> {
    let raw: [u8; 32] = B64.decode(b64.trim()).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&raw).ok()
}

/// The whole policy, in order. Pure: same inputs, same answer.
///
/// `spent_minor` is what has already been charged under this intent.
pub fn verify_checkout(
    intent: &IntentMandate,
    approval: &PrincipalApproval,
    verifier: &dyn ApprovalVerifier,
    cart: &CartMandate,
    cart_signature: &str,
    spent_minor: u64,
    now: u64,
) -> Result<Approved, Reject> {
    // 1. Shape of the intent.
    if intent.version != VERSION || cart.version != VERSION {
        return Err(Reject::Version);
    }
    if intent.currency != CURRENCY || cart.currency != CURRENCY {
        return Err(Reject::Currency);
    }
    if intent.per_order_cap_minor == 0
        || intent.total_budget_minor == 0
        || intent.merchants.is_empty()
        || intent.principal_id != approval.principal_id
    {
        return Err(Reject::Malformed);
    }
    if intent.expires_at <= intent.issued_at || now < intent.issued_at || now >= intent.expires_at {
        return Err(Reject::Window);
    }

    // 2. The human approved exactly this intent.
    let ih = intent_hash(intent)?;
    verifier.verify(&ih, approval)?;

    // 3. The cart points at this intent and was signed by this intent's agent.
    if cart.intent_hash != hex::encode(ih) {
        return Err(Reject::WrongIntent);
    }
    let agent_key = decode_pubkey(&intent.agent_pubkey).ok_or(Reject::Malformed)?;
    let sig = decode_sig(cart_signature).ok_or(Reject::CartSignature)?;
    agent_key
        .verify(&cart_bytes(cart)?, &sig)
        .map_err(|_| Reject::CartSignature)?;

    // 4. What is being bought, where, and for how much.
    if !intent.merchants.iter().any(|m| m == &cart.merchant_id) {
        return Err(Reject::Merchant);
    }
    if cart.items.is_empty() || cart.items.iter().any(|i| i.qty == 0) {
        return Err(Reject::CartTotal);
    }
    let sum = cart.items.iter().try_fold(0u64, |acc, i| {
        i.unit_price_minor
            .checked_mul(u64::from(i.qty))
            .and_then(|line| acc.checked_add(line))
    });
    if sum != Some(cart.total_minor) || cart.total_minor == 0 {
        return Err(Reject::CartTotal);
    }
    if cart.total_minor > intent.per_order_cap_minor {
        return Err(Reject::OverCap);
    }
    match spent_minor.checked_add(cart.total_minor) {
        Some(t) if t <= intent.total_budget_minor => {}
        _ => return Err(Reject::OverBudget),
    }

    Ok(Approved {
        amount_minor: cart.total_minor,
        merchant_id: cart.merchant_id.clone(),
        cart_nonce: cart.nonce.clone(),
    })
}
