use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::Reject;
use crate::types::{CartMandate, IntentMandate};

/// Domain-separated JCS bytes so an intent can never be replayed as a cart
/// (or as a v1 mandate) and vice versa.
fn canonical<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, Reject> {
    let mut out = domain.to_vec();
    out.extend(serde_jcs::to_vec(value).map_err(|_| Reject::Malformed)?);
    Ok(out)
}

pub(crate) fn intent_bytes(i: &IntentMandate) -> Result<Vec<u8>, Reject> {
    canonical(b"mandate-core.intent.v2.", i)
}

pub(crate) fn cart_bytes(c: &CartMandate) -> Result<Vec<u8>, Reject> {
    canonical(b"mandate-core.cart.v2.", c)
}

/// The 32 bytes the human signs. In phase 2 this is the WebAuthn challenge.
pub fn intent_hash(i: &IntentMandate) -> Result<[u8; 32], Reject> {
    Ok(Sha256::digest(intent_bytes(i)?).into())
}

pub fn cart_hash(c: &CartMandate) -> Result<[u8; 32], Reject> {
    Ok(Sha256::digest(cart_bytes(c)?).into())
}
