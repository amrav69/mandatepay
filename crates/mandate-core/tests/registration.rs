//! Passkey registration tests: every one but the first is an attacker or a
//! mistake that must be refused with exactly `Reject::Approval`.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
};
use ed25519_dalek::SigningKey as AgentKey;
use mandate_core::*;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::json;
use sha2::{Digest, Sha256};

const PRINCIPAL_ID: &str = "passkey-ram";
const CRED_ID: &str = "Q1JFRC0wMDE"; // base64url of b"CRED-001"
const RP_ID: &str = "mandatepay.example";
const ORIGIN: &str = "https://mandatepay.example";
const NOW: u64 = 1_800_000_000;
const CHALLENGE: [u8; 32] = [5u8; 32];
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const AT: u8 = 0x40;

/// The 26-byte SPKI DER prefix for an uncompressed P-256 EC public key.
const SPKI_P256_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The fake authenticator's P-256 key: fixed seed bytes, no randomness.
fn passkey() -> SigningKey {
    let seed = [7u8; 32];
    SigningKey::from_bytes(&seed.into()).unwrap()
}

/// The fake authenticator's public key as SPKI DER, as getPublicKey() returns.
fn spki(key: &SigningKey) -> Vec<u8> {
    let point = key.verifying_key().to_sec1_point(false);
    let mut out = SPKI_P256_PREFIX.to_vec();
    out.extend_from_slice(point.as_bytes());
    out
}

/// Base64url, no padding.
fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Registration auth data: rpIdHash || flags || counter || aaguid(||cred||tail).
fn registration_auth(rp: &str, flags: u8, credential: &[u8], tail: &[u8]) -> Vec<u8> {
    let rp_hash: [u8; 32] = Sha256::digest(rp.as_bytes()).into();
    let mut data = rp_hash.to_vec();
    data.push(flags);
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&(credential.len() as u16).to_be_bytes());
    data.extend_from_slice(credential);
    data.extend_from_slice(tail);
    data
}

/// 37-byte assertion auth data: rpIdHash || flags || counter.
fn assertion_auth(rp: &str, flags: u8) -> Vec<u8> {
    let rp_hash: [u8; 32] = Sha256::digest(rp.as_bytes()).into();
    let mut data = rp_hash.to_vec();
    data.push(flags);
    data.extend_from_slice(&1u32.to_be_bytes());
    data
}

/// Client data JSON the browser would produce; crossOrigin only when Some.
fn client_data(
    challenge: &[u8; 32],
    typ: &str,
    origin: &str,
    cross_origin: Option<bool>,
) -> String {
    let mut value = json!({
        "type": typ,
        "challenge": b64u(challenge),
        "origin": origin,
    });
    if let Some(flag) = cross_origin {
        value["crossOrigin"] = json!(flag);
    }
    value.to_string()
}

/// DER-encode a raw r||s ECDSA signature: SEQ { INTEGER r, INTEGER s }.
fn der_encode(raw: &[u8]) -> Vec<u8> {
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let mut skip = 0;
        while skip < bytes.len() - 1 && bytes[skip] == 0 {
            skip += 1;
        }
        let mut body = bytes[skip..].to_vec();
        if body[0] & 0x80 != 0 {
            body.insert(0, 0);
        }
        let mut out = vec![0x02, body.len() as u8];
        out.extend(body);
        out
    }
    let r = integer(&raw[..32]);
    let s = integer(&raw[32..]);
    let mut out = vec![0x30, (r.len() + s.len()) as u8];
    out.extend(r);
    out.extend(s);
    out
}

/// A registration response. `key: None` stands in for a garbage SPKI field.
fn response_of(
    principal_id: &str,
    credential_id: &str,
    auth: &[u8],
    client_json: &str,
    key: Option<&SigningKey>,
) -> RegistrationInput {
    RegistrationInput {
        principal_id: principal_id.into(),
        credential_id: credential_id.into(),
        client_data_json: b64u(client_json.as_bytes()),
        authenticator_data: b64u(auth),
        public_key_spki: match key {
            Some(k) => b64u(&spki(k)),
            None => b64u(&[9u8; 91]),
        },
    }
}

/// The good registration, with a few trailing bytes after the credential id.
fn valid_registration() -> RegistrationInput {
    let client_json = client_data(&CHALLENGE, "webauthn.create", ORIGIN, None);
    response_of(
        PRINCIPAL_ID,
        CRED_ID,
        &registration_auth(RP_ID, UP | UV | AT, b"CRED-001", &[0x69, 0x2D]),
        &client_json,
        Some(&passkey()),
    )
}

/// Verifies a registration response; failing tests assert `.err()`.
fn run(reg: &RegistrationInput) -> Result<PasskeyPrincipal, Reject> {
    verify_registration(reg, &CHALLENGE, RP_ID, ORIGIN)
}

/// A passkey assertion for the intent's hash, signed by the same key.
fn approval_for_intent(key: &SigningKey, intent: &IntentMandate) -> PrincipalApproval {
    let hash = intent_hash(intent).unwrap();
    let auth = assertion_auth(RP_ID, UP | UV);
    let client_json = client_data(&hash, "webauthn.get", ORIGIN, None);
    let mut message = auth.clone();
    let cd_hash: [u8; 32] = Sha256::digest(client_json.as_bytes()).into();
    message.extend_from_slice(&cd_hash);
    let sig: Signature = key.sign(&message);
    let bundle = json!({
        "credential_id": CRED_ID,
        "authenticator_data": b64u(&auth),
        "client_data_json": b64u(client_json.as_bytes()),
        "signature": b64u(&der_encode(&sig.to_vec())),
    });
    PrincipalApproval {
        principal_id: intent.principal_id.clone(),
        signature: B64.encode(bundle.to_string()),
    }
}

fn sign_cart(agent: &AgentKey, cart: &CartMandate) -> String {
    let mut bytes = b"mandate-core.cart.v2.".to_vec();
    bytes.extend(serde_jcs::to_vec(cart).unwrap());
    B64.encode(agent.sign(&bytes).to_bytes())
}

#[test]
fn valid_registration_returns_principal() {
    let principal = run(&valid_registration()).unwrap();
    assert_eq!(principal.principal_id, PRINCIPAL_ID);
    assert_eq!(principal.credential_id, CRED_ID);
    assert_eq!(principal.credential_id.len(), 11);
    assert_eq!(principal.public_key_spki, spki(&passkey()));
    assert_eq!(principal.rp_id, RP_ID);
    assert_eq!(principal.origin, ORIGIN);
}

#[test]
fn wrong_type_fails() {
    let mut reg = valid_registration();
    reg.client_data_json = b64u(client_data(&CHALLENGE, "webauthn.get", ORIGIN, None).as_bytes());
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn wrong_challenge_fails() {
    let mut reg = valid_registration();
    reg.client_data_json =
        b64u(client_data(&[9u8; 32], "webauthn.create", ORIGIN, None).as_bytes());
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn wrong_origin_fails() {
    let mut reg = valid_registration();
    reg.client_data_json =
        b64u(client_data(&CHALLENGE, "webauthn.create", "https://evil.example", None).as_bytes());
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn cross_origin_true_fails() {
    let mut reg = valid_registration();
    reg.client_data_json =
        b64u(client_data(&CHALLENGE, "webauthn.create", ORIGIN, Some(true)).as_bytes());
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn wrong_rp_id_hash_fails() {
    let reg = response_of(
        PRINCIPAL_ID,
        CRED_ID,
        &registration_auth("evil.example", UP | UV | AT, b"CRED-001", &[0x69, 0x2D]),
        &client_data(&CHALLENGE, "webauthn.create", ORIGIN, None),
        Some(&passkey()),
    );
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn missing_up_fails() {
    let reg = response_of(
        PRINCIPAL_ID,
        CRED_ID,
        &registration_auth(RP_ID, UV | AT, b"CRED-001", &[]),
        &client_data(&CHALLENGE, "webauthn.create", ORIGIN, None),
        Some(&passkey()),
    );
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn missing_uv_fails() {
    let reg = response_of(
        PRINCIPAL_ID,
        CRED_ID,
        &registration_auth(RP_ID, UP | AT, b"CRED-001", &[]),
        &client_data(&CHALLENGE, "webauthn.create", ORIGIN, None),
        Some(&passkey()),
    );
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn missing_at_flag_fails() {
    let reg = response_of(
        PRINCIPAL_ID,
        CRED_ID,
        &registration_auth(RP_ID, UP | UV, b"CRED-001", &[]),
        &client_data(&CHALLENGE, "webauthn.create", ORIGIN, None),
        Some(&passkey()),
    );
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn credential_id_mismatch_fails() {
    let reg = response_of(
        PRINCIPAL_ID,
        CRED_ID,
        &registration_auth(RP_ID, UP | UV | AT, b"OTHER-009", &[]),
        &client_data(&CHALLENGE, "webauthn.create", ORIGIN, None),
        Some(&passkey()),
    );
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn credential_length_past_end_fails() {
    let mut reg = valid_registration();
    let mut auth = URL_SAFE_NO_PAD.decode(&reg.authenticator_data).unwrap();
    auth[53] = 0x01; // L = 500, far past the end of this ~66-byte buffer.
    auth[54] = 0xF4;
    reg.authenticator_data = b64u(&auth);
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn auth_data_under_55_bytes_fails() {
    let reg = response_of(
        PRINCIPAL_ID,
        CRED_ID,
        &assertion_auth(RP_ID, UP | UV | AT),
        &client_data(&CHALLENGE, "webauthn.create", ORIGIN, None),
        Some(&passkey()),
    );
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn garbage_spki_fails() {
    let reg = response_of(
        PRINCIPAL_ID,
        CRED_ID,
        &registration_auth(RP_ID, UP | UV | AT, b"CRED-001", &[]),
        &client_data(&CHALLENGE, "webauthn.create", ORIGIN, None),
        None,
    );
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn blank_principal_fails() {
    let mut reg = valid_registration();
    reg.principal_id = "   ".into();
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn empty_credential_id_fails() {
    let reg = response_of(
        PRINCIPAL_ID,
        "",
        &registration_auth(RP_ID, UP | UV | AT, b"", &[]),
        &client_data(&CHALLENGE, "webauthn.create", ORIGIN, None),
        Some(&passkey()),
    );
    assert_eq!(run(&reg).err(), Some(Reject::Approval));
}

#[test]
fn registered_principal_verifies_an_assertion() {
    let principal = run(&valid_registration()).unwrap();
    let agent = AgentKey::from_bytes(&[2u8; 32]);
    let intent = IntentMandate {
        version: VERSION,
        intent_id: "int_1".into(),
        principal_id: PRINCIPAL_ID.into(),
        agent_pubkey: B64.encode(agent.verifying_key().as_bytes()),
        merchants: vec!["merchant-001".into()],
        currency: CURRENCY.into(),
        per_order_cap_minor: 50_000,
        total_budget_minor: 200_000,
        issued_at: NOW - 10,
        expires_at: NOW + 86_400,
        nonce: "n_intent".into(),
    };
    let cart = CartMandate {
        version: VERSION,
        intent_hash: hex::encode(intent_hash(&intent).unwrap()),
        cart_id: "cart_1".into(),
        merchant_id: "merchant-001".into(),
        items: vec![CartItem {
            sku: "EAR-01".into(),
            name: "wired earphones".into(),
            qty: 1,
            unit_price_minor: 45_000,
        }],
        currency: CURRENCY.into(),
        total_minor: 45_000,
        created_at: NOW,
        nonce: "n_cart_1".into(),
    };
    let approval = approval_for_intent(&passkey(), &intent);
    assert_eq!(
        verify_checkout(
            &intent,
            &approval,
            &principal,
            &cart,
            &sign_cart(&agent, &cart),
            0,
            NOW,
        ),
        Ok(Approved {
            amount_minor: 45_000,
            merchant_id: "merchant-001".into(),
            cart_nonce: "n_cart_1".into()
        })
    );
}
