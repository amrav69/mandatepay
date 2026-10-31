//! Passkey (WebAuthn) approval tests: every one but the first is an attacker
//! or a mistake that must be refused with exactly `Reject::Approval`.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
};
use ed25519_dalek::SigningKey as AgentKey;
use mandate_core::*;
use p256::ecdsa::{SigningKey, signature::Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PRINCIPAL_ID: &str = "passkey-shanmukh";
const CREDENTIAL_ID: &str = "ZmFrZS1jcmVkZW50aWFsLWlk";
const RP_ID: &str = "mandatepay.example";
const ORIGIN: &str = "https://mandatepay.example";
const NOW: u64 = 1_800_000_000;
const UP: u8 = 0x01;
const UV: u8 = 0x04;

/// The 26-byte SPKI DER prefix for an uncompressed P-256 EC public key.
const SPKI_P256_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

struct World {
    principal: PasskeyPrincipal,
    intent: IntentMandate,
    approval: PrincipalApproval,
    cart: CartMandate,
    cart_sig: String,
}

/// The fake authenticator's P-256 key: fixed seed bytes, no randomness.
fn passkey() -> SigningKey {
    let seed = [7u8; 32];
    SigningKey::from_bytes(&seed.into()).unwrap()
}

/// The fake authenticator's public key as SPKI DER, as registration returns.
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

/// `sha256(rp_id) || flags || 4-byte counter`: exactly 37 bytes.
fn auth_data_for(rp: &str, flags: u8, counter: u32) -> Vec<u8> {
    let rp_hash: [u8; 32] = Sha256::digest(rp.as_bytes()).into();
    let mut data = rp_hash.to_vec();
    data.push(flags);
    data.extend_from_slice(&counter.to_be_bytes());
    data
}

fn auth_data(flags: u8, counter: u32) -> Vec<u8> {
    auth_data_for(RP_ID, flags, counter)
}

/// Client data JSON the browser would produce for this challenge.
fn client_data(challenge: &[u8; 32], typ: &str, origin: &str) -> String {
    json!({
        "type": typ,
        "challenge": b64u(challenge),
        "origin": origin,
    })
    .to_string()
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

/// The human approves with an assertion over `auth || sha256(client_data_json)`.
fn approval_of(
    key: &SigningKey,
    auth: &[u8],
    client_data_json: &str,
    principal_id: &str,
) -> PrincipalApproval {
    let mut message = auth.to_vec();
    let cd_hash: [u8; 32] = Sha256::digest(client_data_json.as_bytes()).into();
    message.extend_from_slice(&cd_hash);
    let sig: p256::ecdsa::Signature = key.sign(&message);
    let der = der_encode(&sig.to_vec());
    let bundle = json!({
        "credential_id": CREDENTIAL_ID,
        "authenticator_data": b64u(auth),
        "client_data_json": b64u(client_data_json.as_bytes()),
        "signature": b64u(&der),
    });
    PrincipalApproval {
        principal_id: principal_id.into(),
        signature: B64.encode(bundle.to_string()),
    }
}

/// A valid approval for `w.intent`: real challenge, correct origin and rp_id.
fn approval_for(w: &World) -> PrincipalApproval {
    let hash = intent_hash(&w.intent).unwrap();
    approval_of(
        &passkey(),
        &auth_data(UP | UV, 1),
        &client_data(&hash, "webauthn.get", ORIGIN),
        PRINCIPAL_ID,
    )
}

/// Edit the JSON bundle inside `approval.signature` without re-signing it.
fn patch(w: &mut World, edit: impl FnOnce(&mut Value)) {
    let mut value: Value =
        serde_json::from_slice(&B64.decode(&w.approval.signature).unwrap()).unwrap();
    edit(&mut value);
    w.approval.signature = B64.encode(value.to_string());
}

fn run(w: &World, approval: &PrincipalApproval) -> Result<(), Reject> {
    w.principal
        .verify(&intent_hash(&w.intent).unwrap(), approval)
}

fn sign_cart(agent: &AgentKey, cart: &CartMandate) -> String {
    let mut bytes = b"mandate-core.cart.v2.".to_vec();
    bytes.extend(serde_jcs::to_vec(cart).unwrap());
    B64.encode(agent.sign(&bytes).to_bytes())
}

/// The good case straight out of a browser, with an honest agent's cart.
fn world() -> World {
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
    let hash = intent_hash(&intent).unwrap();
    let approval = approval_of(
        &passkey(),
        &auth_data(UP | UV, 1),
        &client_data(&hash, "webauthn.get", ORIGIN),
        PRINCIPAL_ID,
    );
    let cart = CartMandate {
        version: VERSION,
        intent_hash: hex::encode(hash),
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
    let cart_sig = sign_cart(&agent, &cart);
    World {
        principal: PasskeyPrincipal {
            principal_id: PRINCIPAL_ID.into(),
            credential_id: CREDENTIAL_ID.into(),
            public_key_spki: spki(&passkey()),
            rp_id: RP_ID.into(),
            origin: ORIGIN.into(),
        },
        intent,
        approval,
        cart,
        cart_sig,
    }
}

#[test]
fn valid_assertion_passes() {
    let w = world();
    assert_eq!(run(&w, &w.approval), Ok(()));
}

#[test]
fn wrong_challenge_fails() {
    let w = world();
    let approval = approval_of(
        &passkey(),
        &auth_data(UP | UV, 1),
        &client_data(&[9u8; 32], "webauthn.get", ORIGIN),
        PRINCIPAL_ID,
    );
    assert_eq!(run(&w, &approval), Err(Reject::Approval));
}

#[test]
fn wrong_origin_fails() {
    let w = world();
    let hash = intent_hash(&w.intent).unwrap();
    let approval = approval_of(
        &passkey(),
        &auth_data(UP | UV, 1),
        &client_data(&hash, "webauthn.get", "https://evil.example"),
        PRINCIPAL_ID,
    );
    assert_eq!(run(&w, &approval), Err(Reject::Approval));
}

#[test]
fn wrong_type_fails() {
    let w = world();
    let hash = intent_hash(&w.intent).unwrap();
    let approval = approval_of(
        &passkey(),
        &auth_data(UP | UV, 1),
        &client_data(&hash, "webauthn.create", ORIGIN),
        PRINCIPAL_ID,
    );
    assert_eq!(run(&w, &approval), Err(Reject::Approval));
}

#[test]
fn wrong_rp_id_hash_fails() {
    let w = world();
    let hash = intent_hash(&w.intent).unwrap();
    let approval = approval_of(
        &passkey(),
        &auth_data_for("evil.example", UP | UV, 1),
        &client_data(&hash, "webauthn.get", ORIGIN),
        PRINCIPAL_ID,
    );
    assert_eq!(run(&w, &approval), Err(Reject::Approval));
}

#[test]
fn missing_up_flag_fails() {
    let w = world();
    let hash = intent_hash(&w.intent).unwrap();
    let approval = approval_of(
        &passkey(),
        &auth_data(UV, 1),
        &client_data(&hash, "webauthn.get", ORIGIN),
        PRINCIPAL_ID,
    );
    assert_eq!(run(&w, &approval), Err(Reject::Approval));
}

#[test]
fn missing_uv_flag_fails() {
    let w = world();
    let hash = intent_hash(&w.intent).unwrap();
    let approval = approval_of(
        &passkey(),
        &auth_data(UP, 1),
        &client_data(&hash, "webauthn.get", ORIGIN),
        PRINCIPAL_ID,
    );
    assert_eq!(run(&w, &approval), Err(Reject::Approval));
}

#[test]
fn flipped_signature_bit_fails() {
    let mut w = world();
    patch(&mut w, |value| {
        let mut sig = URL_SAFE_NO_PAD
            .decode(value["signature"].as_str().unwrap())
            .unwrap();
        *sig.last_mut().unwrap() ^= 0x01;
        value["signature"] = json!(b64u(&sig));
    });
    assert_eq!(run(&w, &w.approval), Err(Reject::Approval));
}

#[test]
fn tampered_authenticator_data_fails() {
    let mut w = world();
    patch(&mut w, |value| {
        let mut auth = URL_SAFE_NO_PAD
            .decode(value["authenticator_data"].as_str().unwrap())
            .unwrap();
        auth[0] ^= 0x80;
        value["authenticator_data"] = json!(b64u(&auth));
    });
    assert_eq!(run(&w, &w.approval), Err(Reject::Approval));
}

#[test]
fn wrong_credential_id_fails() {
    let mut w = world();
    patch(&mut w, |value| {
        value["credential_id"] = json!("another-credential")
    });
    assert_eq!(run(&w, &w.approval), Err(Reject::Approval));
}

#[test]
fn signed_by_a_different_key_fails() {
    let w = world();
    let other_seed = [9u8; 32];
    let other = SigningKey::from_bytes(&other_seed.into()).unwrap();
    let hash = intent_hash(&w.intent).unwrap();
    let approval = approval_of(
        &other,
        &auth_data(UP | UV, 1),
        &client_data(&hash, "webauthn.get", ORIGIN),
        PRINCIPAL_ID,
    );
    assert_eq!(run(&w, &approval), Err(Reject::Approval));
}

#[test]
fn wrong_principal_id_fails() {
    let w = world();
    let mut approval = approval_for(&w);
    approval.principal_id = "someone-else".into();
    assert_eq!(run(&w, &approval), Err(Reject::Approval));
}

#[test]
fn garbage_base64_or_json_fails() {
    let mut w = world();
    w.approval.signature = "not base64 %%%".into();
    assert_eq!(run(&w, &w.approval), Err(Reject::Approval));
    let mut w = world();
    w.approval.signature = B64.encode("{ not json ]");
    assert_eq!(run(&w, &w.approval), Err(Reject::Approval));
    // Undecodable base64url inside an otherwise well-formed bundle.
    let mut w = world();
    patch(&mut w, |value| value["authenticator_data"] = json!("%%%"));
    assert_eq!(run(&w, &w.approval), Err(Reject::Approval));
}

#[test]
fn short_authenticator_data_fails() {
    let w = world();
    let hash = intent_hash(&w.intent).unwrap();
    // 36 bytes, one short: must be refused without an out-of-bounds panic.
    let short = &auth_data(UP | UV, 1)[..36];
    let approval = approval_of(
        &passkey(),
        short,
        &client_data(&hash, "webauthn.get", ORIGIN),
        PRINCIPAL_ID,
    );
    assert_eq!(run(&w, &approval), Err(Reject::Approval));
}

#[test]
fn passkey_checkout_end_to_end() {
    let w = world();
    assert_eq!(
        verify_checkout(
            &w.intent,
            &w.approval,
            &w.principal,
            &w.cart,
            &w.cart_sig,
            0,
            NOW
        ),
        Ok(Approved {
            amount_minor: 45_000,
            merchant_id: "merchant-001".into(),
            cart_nonce: "n_cart_1".into()
        })
    );
}
