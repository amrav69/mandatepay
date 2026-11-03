//! Phase 2 registration: proves a `navigator.credentials.create()` response
//! and turns it into the [`PasskeyPrincipal`] the server will store.

use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::Reject;
use crate::passkey::{PasskeyPrincipal, b64url, check_client_data};

/// Authenticator-data flag: user presence (a physical touch this session).
const UP: u8 = 0x01;
/// Authenticator-data flag: user verification (fingerprint, face or PIN).
const UV: u8 = 0x04;
/// Authenticator-data flag: a brand-new credential was created and embedded.
const AT: u8 = 0x40;

/// What the browser hands back after a successful registration ceremony.
#[derive(Deserialize)]
pub struct RegistrationInput {
    /// Which human this registration belongs to; must be non-blank.
    pub principal_id: String,
    /// Base64url (no padding) credential id, i.e. the browser's `rawId`.
    pub credential_id: String,
    /// The signed client data JSON, base64url.
    pub client_data_json: String,
    /// Authenticator data with the new credential embedded, base64url.
    pub authenticator_data: String,
    /// The credential's public key as SPKI DER, base64url (`getPublicKey()`).
    pub public_key_spki: String,
}

/// Verifies a registration response for `challenge` at `rp_id` and `origin`,
/// and on success returns the passkey principal record to keep.
pub fn verify_registration(
    input: &RegistrationInput,
    challenge: &[u8; 32],
    rp_id: &str,
    origin: &str,
) -> Result<PasskeyPrincipal, Reject> {
    if input.principal_id.trim().is_empty() {
        return Err(Reject::Approval);
    }
    let credential_id = b64url(&input.credential_id)?;
    if credential_id.is_empty() || credential_id.len() > 1023 {
        return Err(Reject::Approval);
    }
    let client_data = b64url(&input.client_data_json)?;
    let auth = b64url(&input.authenticator_data)?;
    let public_key_spki = b64url(&input.public_key_spki)?;

    check_client_data(&client_data, "webauthn.create", challenge, origin)?;

    if auth.len() < 55 {
        return Err(Reject::Approval);
    }
    let rp_id_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if auth[..32] != rp_id_hash[..] {
        return Err(Reject::Approval);
    }
    let flags = auth[32];
    if (flags & UP) == 0 || (flags & UV) == 0 || (flags & AT) == 0 {
        return Err(Reject::Approval);
    }

    // Bytes 53..55 hold the credential id length; the id starts at byte 55.
    let id_len = u16::from_be_bytes([auth[53], auth[54]]) as usize;
    let id_end = id_len.checked_add(55).ok_or(Reject::Approval)?;
    if id_end > auth.len() || auth[55..id_end] != credential_id[..] {
        return Err(Reject::Approval);
    }

    VerifyingKey::from_public_key_der(&public_key_spki).map_err(|_| Reject::Approval)?;

    Ok(PasskeyPrincipal {
        principal_id: input.principal_id.clone(),
        credential_id: input.credential_id.trim_end_matches('=').to_string(),
        public_key_spki,
        rp_id: rp_id.to_string(),
        origin: origin.to_string(),
    })
}
