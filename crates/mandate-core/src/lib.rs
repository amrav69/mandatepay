//! # mandate-core
//!
//! Two signed documents, two different signers:
//!
//! 1. [`IntentMandate`]: written by the agent, **approved by the human**
//!    ("agent X may spend up to ₹2,000 total, ₹500 per order, at these
//!    merchants, until tomorrow"). The human's approval signs the intent's
//!    hash. The server never signs intents.
//! 2. [`CartMandate`]: the exact cart, **signed by the agent's own key**,
//!    pointing at the approved intent by hash.
//!
//! [`verify_checkout`] is pure: no HTTP, no database, no clock of its own.
//! The caller supplies `now` and the amount already spent under the intent,
//! and must claim the cart nonce atomically after an `Ok`.

mod canonical;
mod checkout;
mod error;
pub mod passkey;
mod types;

pub use canonical::{cart_hash, intent_hash};
pub use checkout::{ApprovalVerifier, Approved, Ed25519Principal, verify_checkout};
pub use error::Reject;
pub use passkey::{PasskeyAssertion, PasskeyPrincipal};
pub use types::{CURRENCY, CartItem, CartMandate, IntentMandate, PrincipalApproval, VERSION};
