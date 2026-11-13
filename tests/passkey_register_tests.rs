//! Phase 2.3 server-side passkey registration: the happy path stores the
//! credential; every attacker variation (reused, expired or wrong-purpose
//! challenge, wrong origin, garbage body) is refused without leaking why.

// This binary uses only the helpers it needs; the agent-key helper stays for
// the other integration tests that share this module.
#[allow(dead_code)]
mod common;

use axum::{Router, body::Body, http::Request};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mandate_core::RegistrationInput;
use mandatepay::{
    app::{AppState, build_router},
    gateway::Gateway,
    mandates::Authority,
    store::Db,
};
use p256::ecdsa::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::util::ServiceExt;

const PRINCIPAL_ID: &str = "passkey-ram";
const CRED_ID: &str = "Q1JFRC0wMDE"; // base64url of b"CRED-001"
const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:8080";
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const AT: u8 = 0x40;

/// The 26-byte SPKI DER prefix for an uncompressed P-256 EC public key.
const SPKI_P256_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// A router plus the Db handle it serves, so tests can seed rows directly.
fn app_with_db() -> (Router, Db, String) {
    let api_key = common::random_test_key();
    let db = Db::open(":memory:").expect("in-memory db");
    let state = Arc::new(AppState {
        authority: Authority::from_seed([7u8; 32]),
        db: db.clone(),
        gateway: Gateway::Mock,
        api_key: api_key.clone(),
        max_mandate_cap: 100_000,
        rp_id: RP_ID.to_string(),
        origin: ORIGIN.to_string(),
    });
    (build_router(state), db, api_key)
}

/// POST JSON (or a raw body) with an optional x-api-key; returns (status, body).
async fn send(app: &Router, uri: &str, key: Option<&str>, body: Body) -> (u16, Value) {
    let builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    let request = match key {
        Some(k) => builder.header("x-api-key", k),
        None => builder,
    }
    .body(body)
    .expect("valid request");
    let resp = app.clone().oneshot(request).await.expect("infallible");
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("body bytes");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// POST a JSON value with an optional x-api-key.
async fn post_json(app: &Router, uri: &str, key: Option<&str>, body: Value) -> (u16, Value) {
    send(app, uri, key, Body::from(body.to_string())).await
}

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

/// Registration auth data: rpIdHash || flags || counter || aaguid || cred.
fn registration_auth(rp: &str, flags: u8, credential: &[u8]) -> Vec<u8> {
    let rp_hash: [u8; 32] = Sha256::digest(rp.as_bytes()).into();
    let mut data = rp_hash.to_vec();
    data.push(flags);
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&(credential.len() as u16).to_be_bytes());
    data.extend_from_slice(credential);
    data
}

/// Client data JSON the browser would produce.
fn client_data(challenge: &[u8], typ: &str, origin: &str) -> String {
    json!({
        "type": typ,
        "challenge": b64u(challenge),
        "origin": origin,
    })
    .to_string()
}

/// The server's 32-byte challenge, decoded from the options response.
fn decode_challenge(value: &Value) -> [u8; 32] {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_str().expect("challenge is a string"))
        .expect("challenge decodes");
    <[u8; 32]>::try_from(bytes.as_slice()).expect("challenge is exactly 32 bytes")
}

/// A valid browser registration response for `challenge` at `origin`.
fn build_registration(challenge: &[u8], origin: &str, credential: &[u8]) -> RegistrationInput {
    RegistrationInput {
        principal_id: PRINCIPAL_ID.into(),
        credential_id: b64u(credential),
        client_data_json: b64u(client_data(challenge, "webauthn.create", origin).as_bytes()),
        authenticator_data: b64u(&registration_auth(RP_ID, UP | UV | AT, credential)),
        public_key_spki: b64u(&spki(&passkey())),
    }
}

/// RegistrationInput is not Serialize; this is the exact JSON the browser sends.
fn input_json(reg: &RegistrationInput) -> Value {
    json!({
        "principal_id": reg.principal_id,
        "credential_id": reg.credential_id,
        "client_data_json": reg.client_data_json,
        "authenticator_data": reg.authenticator_data,
        "public_key_spki": reg.public_key_spki,
    })
}

/// The full register request body.
fn register_body(challenge_id: &str, reg: &RegistrationInput) -> Value {
    json!({ "challenge_id": challenge_id, "input": input_json(reg) })
}

/// Run the options endpoint and return (challenge_id, challenge bytes).
async fn get_options(app: &Router, key: &str) -> (String, [u8; 32]) {
    let (status, options) = post_json(
        app,
        "/v1/passkeys/register/options",
        Some(key),
        json!({ "principal_id": PRINCIPAL_ID }),
    )
    .await;
    assert_eq!(status, 200, "options failed: {options}");
    let challenge_id = options["challenge_id"]
        .as_str()
        .expect("challenge_id is a string")
        .to_string();
    (challenge_id, decode_challenge(&options["challenge"]))
}

/// Every field of the uniform 400 failure body.
fn assert_rejected(status: u16, body: &Value) {
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body, &json!({ "error": "registration rejected" }));
}

#[tokio::test]
async fn options_returns_32_byte_challenge_and_user_handle() {
    let (app, key) = common::test_app();
    let (status, options) = post_json(
        &app,
        "/v1/passkeys/register/options",
        Some(&key),
        json!({ "principal_id": PRINCIPAL_ID }),
    )
    .await;
    assert_eq!(status, 200, "body: {options}");
    assert_eq!(options["rp_id"], RP_ID);
    // The challenge decodes to exactly 32 bytes (asserted inside the helper).
    let challenge = decode_challenge(&options["challenge"]);
    assert_eq!(challenge.len(), 32);
    // The user handle is base64url of the principal id.
    let user_id = URL_SAFE_NO_PAD
        .decode(options["user_id"].as_str().expect("user_id is a string"))
        .expect("user_id decodes");
    assert_eq!(user_id, PRINCIPAL_ID.as_bytes());
    // A challenge id is present for the follow-up call.
    assert!(
        !options["challenge_id"]
            .as_str()
            .expect("challenge_id is a string")
            .is_empty()
    );
}

#[tokio::test]
async fn happy_path_registers_and_stores_the_passkey() {
    let (app, db, key) = app_with_db();
    let (challenge_id, challenge) = get_options(&app, &key).await;
    let reg = build_registration(&challenge, ORIGIN, b"CRED-001");
    let (status, body) = post_json(
        &app,
        "/v1/passkeys/register",
        Some(&key),
        register_body(&challenge_id, &reg),
    )
    .await;
    assert_eq!(status, 201, "body: {body}");
    assert_eq!(body["status"], "registered");
    assert_eq!(body["credential_id"], CRED_ID);

    let principal = db
        .get_passkey(CRED_ID)
        .expect("query works")
        .expect("stored");
    assert_eq!(principal.principal_id, PRINCIPAL_ID);
    assert_eq!(principal.credential_id, CRED_ID);
    assert_eq!(principal.rp_id, RP_ID);
    assert_eq!(principal.origin, ORIGIN);
    assert_eq!(principal.public_key_spki, spki(&passkey()));
}

#[tokio::test]
async fn missing_or_wrong_master_key_is_401() {
    let (app, _) = common::test_app();
    let (options_none, _) = post_json(
        &app,
        "/v1/passkeys/register/options",
        None,
        json!({ "principal_id": PRINCIPAL_ID }),
    )
    .await;
    assert_eq!(options_none, 401);
    let (options_wrong, _) = post_json(
        &app,
        "/v1/passkeys/register/options",
        Some("not-the-master-key"),
        json!({ "principal_id": PRINCIPAL_ID }),
    )
    .await;
    assert_eq!(options_wrong, 401);
    let (register_none, _) = post_json(&app, "/v1/passkeys/register", None, json!({})).await;
    assert_eq!(register_none, 401);
    let (register_wrong, _) = post_json(
        &app,
        "/v1/passkeys/register",
        Some("not-the-master-key"),
        json!({}),
    )
    .await;
    assert_eq!(register_wrong, 401);
}

#[tokio::test]
async fn reused_challenge_is_rejected() {
    let (app, key) = common::test_app();
    let (challenge_id, challenge) = get_options(&app, &key).await;
    let first = build_registration(&challenge, ORIGIN, b"CRED-001");
    let (status, _) = post_json(
        &app,
        "/v1/passkeys/register",
        Some(&key),
        register_body(&challenge_id, &first),
    )
    .await;
    assert_eq!(status, 201);

    // Same challenge, different credential: only the first may use it.
    let second = build_registration(&challenge, ORIGIN, b"CRED-002");
    let (status, body) = post_json(
        &app,
        "/v1/passkeys/register",
        Some(&key),
        register_body(&challenge_id, &second),
    )
    .await;
    assert_rejected(status, &body);
}

#[tokio::test]
async fn expired_challenge_is_rejected() {
    let (app, db, key) = app_with_db();
    let challenge = [9u8; 32];
    db.insert_challenge_row("ch-expired", &challenge, "register", 1, false)
        .expect("seed row");
    let reg = build_registration(&challenge, ORIGIN, b"CRED-003");
    let (status, body) = post_json(
        &app,
        "/v1/passkeys/register",
        Some(&key),
        register_body("ch-expired", &reg),
    )
    .await;
    assert_rejected(status, &body);
}

#[tokio::test]
async fn wrong_purpose_challenge_is_rejected() {
    let (app, db, key) = app_with_db();
    let challenge = [8u8; 32];
    // Unexpired and unused, but minted for a different ceremony.
    db.insert_challenge_row("ch-login", &challenge, "login", 4_000_000_000, false)
        .expect("seed row");
    let reg = build_registration(&challenge, ORIGIN, b"CRED-004");
    let (status, body) = post_json(
        &app,
        "/v1/passkeys/register",
        Some(&key),
        register_body("ch-login", &reg),
    )
    .await;
    assert_rejected(status, &body);
}

#[tokio::test]
async fn wrong_origin_is_rejected() {
    let (app, key) = common::test_app();
    let (challenge_id, challenge) = get_options(&app, &key).await;
    let reg = build_registration(&challenge, "https://evil.example", b"CRED-005");
    let (status, body) = post_json(
        &app,
        "/v1/passkeys/register",
        Some(&key),
        register_body(&challenge_id, &reg),
    )
    .await;
    assert_rejected(status, &body);
}

#[tokio::test]
async fn duplicate_credential_is_409() {
    let (app, db, key) = app_with_db();
    let (first_id, first_challenge) = get_options(&app, &key).await;
    let first = build_registration(&first_challenge, ORIGIN, b"CRED-001");
    let (status, _) = post_json(
        &app,
        "/v1/passkeys/register",
        Some(&key),
        register_body(&first_id, &first),
    )
    .await;
    assert_eq!(status, 201);

    // Fresh challenge, same credential id: a second registration must 409.
    let (second_id, second_challenge) = get_options(&app, &key).await;
    let second = build_registration(&second_challenge, ORIGIN, b"CRED-001");
    let (status, body) = post_json(
        &app,
        "/v1/passkeys/register",
        Some(&key),
        register_body(&second_id, &second),
    )
    .await;
    assert_eq!(status, 409, "body: {body}");
    assert_eq!(body, json!({ "error": "credential already registered" }));
    // The stored row is still the first registration's principal.
    let principal = db
        .get_passkey(CRED_ID)
        .expect("query works")
        .expect("stored");
    assert_eq!(principal.principal_id, PRINCIPAL_ID);
}

#[tokio::test]
async fn garbage_body_is_400() {
    let (app, key) = common::test_app();
    // Not JSON at all.
    let (status, body) = send(
        &app,
        "/v1/passkeys/register",
        Some(&key),
        Body::from("not json"),
    )
    .await;
    assert_rejected(status, &body);
    // JSON but missing the input field.
    let (status, body) = post_json(
        &app,
        "/v1/passkeys/register",
        Some(&key),
        json!({ "challenge_id": "nope" }),
    )
    .await;
    assert_rejected(status, &body);
    // Wrong types everywhere.
    let (status, body) = post_json(
        &app,
        "/v1/passkeys/register",
        Some(&key),
        json!({ "challenge_id": 5, "input": null }),
    )
    .await;
    assert_rejected(status, &body);
}
