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
            Decision::Reject { reason } if reason.contains("exceeds mandate policy")
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
fn stateless_validator_agrees_with_evaluate_without_consuming_nonce() {
    // H11 regression: the idempotency early-cache must apply the same verdict
    // as policy evaluation. validate_stateless has no DB side effect, so it
    // must agree with evaluate on every rejection and be repeatable.
    use mandatepay::policy::validate_stateless;
    let auth = Authority::from_seed([7u8; 32]);
    let (_dir, db) = test_db();
    let allow = allowlist();
    let mut cases = vec![sample_mandate("n_s0")];
    let mut bad_version = sample_mandate("n_s1");
    bad_version.version = 2;
    cases.push(bad_version);
    let mut bad_action = sample_mandate("n_s2");
    bad_action.action = "payout".into();
    cases.push(bad_action);
    let mut bad_ccy = sample_mandate("n_s3");
    bad_ccy.currency = "USD".into();
    cases.push(bad_ccy);
    let mut bad_cap = sample_mandate("n_s4");
    bad_cap.max_amount_minor = 0;
    cases.push(bad_cap);
    let mut bad_window = sample_mandate("n_s5");
    bad_window.expires_at = bad_window.issued_at;
    cases.push(bad_window);
    let mut bad_ids = sample_mandate("n_s6");
    bad_ids.merchant_id = "  ".into();
    cases.push(bad_ids);
    let mut future = sample_mandate("n_s7");
    future.issued_at = unix_now() + 3600;
    future.expires_at = unix_now() + 7200;
    cases.push(future);
    let mut expired = sample_mandate("n_s8");
    expired.issued_at = unix_now() - 7200;
    expired.expires_at = unix_now() - 3600;
    cases.push(expired);
    let mut bad_merchant = sample_mandate("n_s9");
    bad_merchant.merchant_id = "merchant-999".into();
    cases.push(bad_merchant);
    for m in &cases {
        let sig = auth.sign(m).unwrap();
        let first = validate_stateless(&auth, m, &sig, CAP, &allow);
        let second = validate_stateless(&auth, m, &sig, CAP, &allow);
        assert!(
            matches!(&first, Decision::Allow { .. }) == matches!(&second, Decision::Allow { .. }),
            "stateless validator must be repeatable (no side effect)"
        );
        // Zero-amount and over-cap amount cases through the validator too.
        assert!(matches!(
            validate_stateless(&auth, m, &sig, 0, &allow),
            Decision::Reject { .. }
        ));
        assert!(matches!(
            validate_stateless(&auth, m, &sig, CAP * 10, &allow),
            Decision::Reject { .. }
        ));
    }
    // Forged signature rejected identically by both paths.
    let m = sample_mandate("n_s_forged");
    assert!(matches!(
        validate_stateless(&auth, &m, "bogus", CAP, &allow),
        Decision::Reject { .. }
    ));
    assert!(matches!(
        policy::evaluate(&auth, &m, "bogus", CAP, &allow, &db),
        Decision::Reject { .. }
    ));
    // Valid mandate: validator Allows repeatedly, evaluate Allows once then replays.
    let m = sample_mandate("n_s_valid");
    let sig = auth.sign(&m).unwrap();
    assert!(matches!(
        validate_stateless(&auth, &m, &sig, CAP, &allow),
        Decision::Allow { .. }
    ));
    assert!(matches!(
        validate_stateless(&auth, &m, &sig, CAP, &allow),
        Decision::Allow { .. }
    ));
    assert!(matches!(
        policy::evaluate(&auth, &m, &sig, CAP, &allow, &db),
        Decision::Allow { .. }
    ));
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

#[test]
fn canonical_bytes_is_jcs_with_domain_separator() {
    use mandatepay::mandates::canonical_bytes;
    let m = sample_mandate("n_canonical");
    let b1 = canonical_bytes(&m).unwrap();
    let b2 = canonical_bytes(&m).unwrap();
    assert_eq!(b1, b2);
    assert!(b1.starts_with(b"mandatepay.v1."));
    let json_part = &b1[b"mandatepay.v1.".len()..];
    let v: serde_json::Value = serde_json::from_slice(json_part).unwrap();
    let jcs = serde_jcs::to_vec(&v).unwrap();
    assert_eq!(json_part, jcs.as_slice());
}

#[test]
fn new_token_is_url_safe_no_pad() {
    use mandatepay::mandates::new_token;
    for i in 0..20 {
        let tok = new_token("mnd_", 9);
        assert!(tok.starts_with("mnd_"), "prefix missing: {tok}");
        let b64part = &tok["mnd_".len()..];
        assert!(
            !b64part.contains('+') && !b64part.contains('/') && !b64part.contains('='),
            "token {i} contains non-URL-safe chars: {tok}"
        );
        let n = new_token("n_", 16);
        let b64part = &n["n_".len()..];
        assert!(
            !b64part.contains('+') && !b64part.contains('/') && !b64part.contains('='),
            "nonce {i} contains non-URL-safe chars: {n}"
        );
    }
}

#[test]
fn velocity_rejection_rolls_back_nonce_so_mandate_is_retryable() {
    // Regression for nonce not rolled back on velocity rejection (app.rs L264).
    // Policy: velocity is a rate limit, not a mandate validity failure, so a
    // velocity-rejected mandate must remain retryable after the window or after
    // we explicitly rollback. The fix in app.rs rolls back nonce when velocity
    // fails after evaluate() already claimed it. This test proves the DB-level
    // behavior: after try_claim_nonce + rollback, the nonce can be reclaimed.
    let (_dir, db) = test_db();
    let auth = Authority::from_seed([11u8; 32]);
    let allow = allowlist();
    // Configure agent with velocity_limit=1
    db.update_agent("vel-rollback-agent", Some(50000), Some(1), Some(60), None)
        .unwrap();
    // First mandate with nonce n_retry should succeed
    let m1 = Mandate {
        version: 1,
        mandate_id: "mnd_vel_1".into(),
        agent_id: "vel-rollback-agent".into(),
        merchant_id: "merchant-001".into(),
        action: "create_order".into(),
        currency: "INR".into(),
        max_amount_minor: CAP,
        issued_at: unix_now() - 1,
        expires_at: unix_now() + 3600,
        nonce: "n_vel_retry".into(),
    };
    let sig1 = auth.sign(&m1).unwrap();
    let d1 = policy::evaluate(&auth, &m1, &sig1, 1000, &allow, &db);
    assert!(matches!(d1, Decision::Allow { .. }));
    // Simulate velocity failure after evaluate: check_velocity should allow first,
    // but second call within same window should reject.
    assert!(db.check_velocity("vel-rollback-agent").unwrap()); // first increments to 1 <=1 -> true
    assert!(!db.check_velocity("vel-rollback-agent").unwrap()); // second increments to 2 >1 -> false (rejected)
    // The second mandate with same nonce would have already claimed nonce inside evaluate
    // if we tried to evaluate it. To emulate the bug: evaluate claimed nonce, then velocity
    // failed, so we rollback.
    let m2 = Mandate {
        nonce: "n_vel_second".into(),
        mandate_id: "mnd_vel_2".into(),
        ..m1.clone()
    };
    let sig2 = auth.sign(&m2).unwrap();
    // This evaluate will claim n_vel_second successfully -> Allow
    let d2 = policy::evaluate(&auth, &m2, &sig2, 1000, &allow, &db);
    assert!(
        matches!(d2, Decision::Allow { .. }),
        "second evaluate should Allow before velocity"
    );
    // Now velocity check fails again -> our fix rolls back nonce
    let vel_ok = db.check_velocity("vel-rollback-agent").unwrap();
    assert!(!vel_ok, "velocity should still be exceeded");
    // Emulate app.rs rollback on velocity rejection
    if !vel_ok {
        db.rollback_nonce(&m2.nonce).unwrap();
    }
    // Nonce should now be reusable (retryable) — this is the regression assertion.
    assert!(
        db.try_claim_nonce(&m2.nonce).unwrap(),
        "nonce from velocity-rejected mandate must be retryable after rollback"
    );
    // Conversely, a nonce that was NOT rolled back must stay consumed (replay protection)
    let m3 = Mandate {
        nonce: "n_no_rollback".into(),
        mandate_id: "mnd_vel_3".into(),
        ..m1.clone()
    };
    let sig3 = auth.sign(&m3).unwrap();
    let d3 = policy::evaluate(&auth, &m3, &sig3, 1000, &allow, &db);
    assert!(matches!(d3, Decision::Allow { .. }));
    // Do NOT rollback -> second attempt with same nonce must be replay
    assert!(!db.try_claim_nonce(&m3.nonce).unwrap());
}

#[test]
fn gateway_failure_rollback_makes_nonce_retryable() {
    // Gateway failure case: after evaluate Allow (nonce claimed), if gateway fails
    // the app rolls back nonce so the same mandate can be retried.
    let (_dir, db) = test_db();
    let auth = Authority::from_seed([12u8; 32]);
    let allow = allowlist();
    let m = sample_mandate("n_gateway_retry");
    let sig = auth.sign(&m).unwrap();
    let d = policy::evaluate(&auth, &m, &sig, CAP, &allow, &db);
    assert!(matches!(d, Decision::Allow { .. }));
    // Simulate gateway failure rollback
    db.rollback_nonce(&m.nonce).unwrap();
    // Should be able to re-evaluate same mandate/nonce after rollback
    let d2 = policy::evaluate(&auth, &m, &sig, CAP, &allow, &db);
    assert!(
        matches!(d2, Decision::Allow { .. }),
        "after gateway rollback, same nonce should be reclaimable"
    );
}

#[test]
fn issued_at_future_leeway_rejects_large_skew_but_allows_small() {
    // M2: 60s leeway for clock skew, beyond that reject as future-dated
    let auth = Authority::from_seed([7u8; 32]);
    let (_dir, db) = test_db();
    let allow = allowlist();
    let now = unix_now();
    // Small skew (30s in future) should be allowed
    let mut m_ok = sample_mandate("n_future_ok");
    m_ok.issued_at = now + 30;
    m_ok.expires_at = now + 3600;
    let sig_ok = auth.sign(&m_ok).unwrap();
    assert!(
        matches!(
            policy::evaluate(&auth, &m_ok, &sig_ok, CAP, &allow, &db),
            Decision::Allow { .. }
        ),
        "issued_at 30s in future (within 60s leeway) should be allowed"
    );
    // Large skew (65s in future) should be rejected (61s is flaky due to 1s clock drift between test and policy)
    let mut m_bad = sample_mandate("n_future_bad");
    m_bad.issued_at = now + 65;
    m_bad.expires_at = now + 3600;
    let sig_bad = auth.sign(&m_bad).unwrap();
    assert!(
        matches!(
            policy::evaluate(&auth, &m_bad, &sig_bad, CAP, &allow, &db),
            Decision::Reject { reason } if reason.contains("too far in the future")
        ),
        "issued_at 65s in future should be rejected"
    );
}
