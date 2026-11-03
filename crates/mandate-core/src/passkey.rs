//! Phase 2 approval: a WebAuthn (passkey) credential instead of a raw key.
//! The human's P-256 passkey signs the 32-byte challenge `intent_hash`
//! per the WebAuthn spec; the server stores only the public key.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::pkcs8::DecodePublicKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::checkout::ApprovalVerifier;
use crate::error::Reject;
use crate::types::PrincipalApproval;

/// Authenticator-data flag: user presence (a physical touch this session).
const UP: u8 = 0x01;
/// Authenticator-data flag: user verification (fingerprint, face or PIN).
const UV: u8 = 0x04;

/// A principal whose approval key is a passkey credential's public key.
/// The server holds only the public half.
pub struct PasskeyPrincipal {
    /// Which human this is; must match the intent and the approval.
    pub principal_id: String,
    /// WebAuthn credential id, base64url with no padding.
    pub credential_id: String,
    /// Public key as DER SubjectPublicKeyInfo, from registration's getPublicKey().
    pub public_key_spki: Vec<u8>,
    /// WebAuthn relying-party id, e.g. "mandatepay.example".
    pub rp_id: String,
    /// Browser origin the assertion must carry, e.g. "https://mandatepay.example".
    pub origin: String,
}

/// The WebAuthn assertion the browser hands back, carried inside
/// `PrincipalApproval.signature` as standard base64 of this JSON.
/// All string fields are base64url with no padding.
#[derive(Deserialize)]
pub struct PasskeyAssertion {
    /// Which credential made this assertion, base64url.
    pub credential_id: String,
    /// Raw authenticator data (rp_id hash, flags, counter), base64url.
    pub authenticator_data: String,
    /// The client data the browser produced and signed, base64url.
    pub client_data_json: String,
    /// DER ECDSA P-256 signature over auth data || sha256(client data).
    pub signature: String,
}

/// Decodes base64url, tolerating trailing padding (`=`) for lenient clients.
pub(crate) fn b64url(s: &str) -> Result<Vec<u8>, Reject> {
    URL_SAFE_NO_PAD
        .decode(s.trim().trim_end_matches('='))
        .map_err(|_| Reject::Approval)
}

/// The client-data checks every WebAuthn ceremony shares: type, challenge,
/// origin, and that it is not cross-origin. `expected_type` distinguishes
/// registration ("webauthn.create") from an approval ("webauthn.get").
pub(crate) fn check_client_data(
    client_data: &[u8],
    expected_type: &str,
    challenge: &[u8; 32],
    origin: &str,
) -> Result<(), Reject> {
    let cd: serde_json::Value =
        serde_json::from_slice(client_data).map_err(|_| Reject::Approval)?;
    let field = |key: &str| cd.get(key).and_then(serde_json::Value::as_str);
    if field("type") != Some(expected_type) {
        return Err(Reject::Approval);
    }
    if field("challenge") != Some(URL_SAFE_NO_PAD.encode(challenge).as_str()) {
        return Err(Reject::Approval);
    }
    if field("origin") != Some(origin) {
        return Err(Reject::Approval);
    }
    // Approvals must come from our own page, never an iframe on another site.
    if cd.get("crossOrigin").and_then(serde_json::Value::as_bool) == Some(true) {
        return Err(Reject::Approval);
    }
    Ok(())
}

impl ApprovalVerifier for PasskeyPrincipal {
    fn verify(&self, intent_hash: &[u8; 32], approval: &PrincipalApproval) -> Result<(), Reject> {
        if approval.principal_id != self.principal_id {
            return Err(Reject::Approval);
        }
        let bundle = B64
            .decode(approval.signature.trim())
            .map_err(|_| Reject::Approval)?;
        let assertion: PasskeyAssertion =
            serde_json::from_slice(&bundle).map_err(|_| Reject::Approval)?;
        if assertion.credential_id != self.credential_id {
            return Err(Reject::Approval);
        }
        let auth = b64url(&assertion.authenticator_data)?;
        let client_data = b64url(&assertion.client_data_json)?;
        let der_sig = b64url(&assertion.signature)?;
        check_client_data(&client_data, "webauthn.get", intent_hash, &self.origin)?;

        if auth.len() < 37 {
            return Err(Reject::Approval);
        }
        let rp_id_hash: [u8; 32] = Sha256::digest(self.rp_id.as_bytes()).into();
        if auth[..32] != rp_id_hash[..] {
            return Err(Reject::Approval);
        }
        let flags = auth[32];
        if (flags & UP) == 0 || (flags & UV) == 0 {
            return Err(Reject::Approval);
        }

        let key = VerifyingKey::from_public_key_der(&self.public_key_spki)
            .map_err(|_| Reject::Approval)?;
        let signature = Signature::from_der(&der_sig).map_err(|_| Reject::Approval)?;
        let mut message = auth;
        let cd_hash: [u8; 32] = Sha256::digest(&client_data).into();
        message.extend_from_slice(&cd_hash);
        key.verify(&message, &signature)
            .map_err(|_| Reject::Approval)
    }
}
