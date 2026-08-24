use mandatepay::mandates::{Authority, Mandate, unix_now};
use mandatepay::policy::{self, Decision};
use mandatepay::store::Db;
use tempfile::TempDir;

const CAP: u64 = 49_900;

fn allowlist() -> Vec<String> {
    vec!["merchant-001".to_string()]
}

fn sample_mandate(nonce: &str) -> Mandate {
    let now = unix_now();
    Mandate {
        version: 1,
        mandate_id: "mnd_test_0001".into(),
        agent_id: "agent-trusted-01".into(),
        merchant_id: "merchant-001".into(),
        action: "create_order".into(),
        currency: "INR".into(),
        max_amount_minor: CAP,
        issued_at: now - 10,
        expires_at: now + 3_600,
        nonce: nonce.into(),
    }
}

fn test_db() -> (TempDir, Db) {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(dir.path().join("test.db").to_str().unwrap()).expect("db open");
    (dir, db)
}

#[test]
fn sign_then_verify_roundtrip_succeeds() {
    let auth = Authority::from_seed([7u8; 32]);
    let m = sample_mandate("n_roundtrip");
    let sig = auth.sign(&m).unwrap();
    assert!(auth.verify(&m, &sig).is_ok());
}

#[test]
fn tampered_amount_fails_verification() {
    let auth = Authority::from_seed([7u8; 32]);
    let m = sample_mandate("n_tamper");
    let sig = auth.sign(&m).unwrap();
    let mut forged = m.clone();
    forged.max_amount_minor *= 10;
    assert!(auth.verify(&forged, &sig).is_err());
}

#[test]
fn foreign_authority_rejected() {
    let issuer = Authority::from_seed([7u8; 32]);
    let impostor = Authority::from_seed([9u8; 32]);
    let m = sample_mandate("n_foreign");
    let sig = issuer.sign(&m).unwrap();
    assert!(impostor.verify(&m, &sig).is_err());
}

#[test]
fn valid_mandate_allowed_by_policy() {
    let auth = Authority::from_seed([7u8; 32]);
    let (_dir, db) = test_db();
    let allow = allowlist();
    let m = sample_mandate("n_happy");
    let sig = auth.sign(&m).unwrap();
    assert!(matches!(
        policy::evaluate(&auth, &m, &sig, CAP, &allow, &db),
        Decision::Allow { .. }
    ));
}

#[test]
fn over_cap_amount_rejected_by_policy() {
    let auth = Authority::from_seed([7u8; 32]);
    let (_dir, db) = test_db();
    let allow = allowlist();
    let m = sample_mandate("n_overcap");
    let sig = auth.sign(&m).unwrap();
    assert!(
        matches!(
            policy::evaluate(&auth, &m, &sig, CAP * 10, &allow, &db),
            Decision::Reject { reason } if reason.contains("exceeds mandate cap")
        ),
        "spending beyond the signed cap must be rejected"
    );
}

#[test]
fn zero_amount_rejected_by_policy() {
    let auth = Authority::from_seed([7u8; 32]);
    let (_dir, db) = test_db();
    let allow = allowlist();
    let m = sample_mandate("n_zero");
    let sig = auth.sign(&m).unwrap();
    assert!(matches!(
        policy::evaluate(&auth, &m, &sig, 0, &allow, &db),
        Decision::Reject { .. }
    ));
}

#[test]
fn non_allowlisted_merchant_rejected_by_policy() {
    let auth = Authority::from_seed([7u8; 32]);
    let (_dir, db) = test_db();
    let allow = allowlist();
    let mut m = sample_mandate("n_merchant");
    m.merchant_id = "merchant-999".into();
    let sig = auth.sign(&m).unwrap();
    assert!(
        matches!(
            policy::evaluate(&auth, &m, &sig, CAP, &allow, &db),
            Decision::Reject { reason } if reason.contains("not allowlisted")
        ),
        "mandates for unknown merchants must be rejected"
    );
}

#[test]
fn expired_mandate_rejected_by_policy() {
    let auth = Authority::from_seed([7u8; 32]);
    let (_dir, db) = test_db();
    let allow = allowlist();
    let mut m = sample_mandate("n_expired");
    m.issued_at = unix_now() - 7_200;
    m.expires_at = unix_now() - 3_600;
    let sig = auth.sign(&m).unwrap();
    assert!(matches!(
        policy::evaluate(&auth, &m, &sig, CAP, &allow, &db),
        Decision::Reject { .. }
    ));
}

#[test]
fn replayed_nonce_rejected_second_time() {
    let auth = Authority::from_seed([7u8; 32]);
    let (_dir, db) = test_db();
    let allow = allowlist();
    let m = sample_mandate("n_replay");
    let sig = auth.sign(&m).unwrap();
    assert!(matches!(
        policy::evaluate(&auth, &m, &sig, CAP, &allow, &db),
        Decision::Allow { .. }
    ));
    assert!(
        matches!(
            policy::evaluate(&auth, &m, &sig, CAP, &allow, &db),
            Decision::Reject { reason } if reason.contains("replay")
        ),
        "second evaluation must be rejected as replay"
    );
}
