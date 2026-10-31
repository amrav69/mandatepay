use serde::{Deserialize, Serialize};

/// Format version this crate understands.
pub const VERSION: u8 = 2;
/// Only INR for now.
pub const CURRENCY: &str = "INR";

/// What the human approves. The agent drafts it; only the principal's
/// approval makes it spendable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntentMandate {
    pub version: u8,
    pub intent_id: String,
    /// Which human approval key must sign this (e.g. a passkey credential id).
    pub principal_id: String,
    /// Agent's Ed25519 public key, base64. Only this key may sign carts.
    pub agent_pubkey: String,
    pub merchants: Vec<String>,
    pub currency: String,
    /// Most any single cart may cost, in paise.
    pub per_order_cap_minor: u64,
    /// Most all carts under this intent may cost together, in paise.
    pub total_budget_minor: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

/// The human's signature over `intent_hash(intent)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalApproval {
    pub principal_id: String,
    /// Verifier-specific bytes, base64 (an Ed25519 signature, or a WebAuthn
    /// assertion bundle in phase 2).
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CartItem {
    pub sku: String,
    pub name: String,
    pub qty: u32,
    pub unit_price_minor: u64,
}

/// The exact purchase, signed by the agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CartMandate {
    pub version: u8,
    /// Hex sha256 of the approved intent.
    pub intent_hash: String,
    pub cart_id: String,
    pub merchant_id: String,
    pub items: Vec<CartItem>,
    pub currency: String,
    pub total_minor: u64,
    pub created_at: u64,
    /// Single-use. The caller's store must claim it after a successful verify.
    pub nonce: String,
}
