use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mandatepay::mandates::{Authority, Mandate, canonical_bytes, unix_now};
use proptest::prelude::*;

fn arb_mandate() -> impl Strategy<Value = Mandate> {
    (
        "[a-z0-9-]{1,32}",
        "[a-z0-9-]{1,32}",
        1u64..1_000_000,
        0u64..2_000_000_000,
        60u64..86_400,
    )
        .prop_map(|(agent, merchant, cap, issued, ttl)| Mandate {
            version: 1,
            mandate_id: format!("mnd_{agent}"),
            agent_id: agent.clone(),
            merchant_id: merchant.clone(),
            action: "create_order".into(),
            currency: "INR".into(),
            max_amount_minor: cap,
            issued_at: issued,
            expires_at: issued.saturating_add(ttl),
            nonce: format!("n_{merchant}_{issued}"),
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn canonical_bytes_deterministic(m in arb_mandate()) {
        prop_assert_eq!(
            canonical_bytes(&m).unwrap(),
            canonical_bytes(&m).unwrap()
        );
    }

    #[test]
    fn single_bit_signature_mutation_fails_verify(
        m in arb_mandate(),
        bit in 0usize..512,
    ) {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        let auth = Authority::from_seed([7u8; 32]);
        let sig = auth.sign(&m).unwrap();
        let mut raw = B64.decode(sig.trim()).unwrap();
        raw[bit / 8] ^= 1 << (bit % 8);
        let mutated = B64.encode(&raw);
        prop_assert!(auth.verify(&m, &mutated).is_err());
    }

    #[test]
    fn single_byte_mandate_mutation_fails_verify(m in arb_mandate()) {
        let auth = Authority::from_seed([7u8; 32]);
        let sig = auth.sign(&m).unwrap();
        // Flip the first byte of the nonce: any change breaks the signature.
        let mut forged = m.clone();
        prop_assume!(!forged.nonce.is_empty());
        let mut nb = forged.nonce.into_bytes();
        nb[0] = nb[0].wrapping_add(1);
        forged.nonce = String::from_utf8(nb).unwrap();
        prop_assert!(auth.verify(&forged, &sig).is_err());
        // Bumping the cap breaks it too.
        let mut forged2 = m.clone();
        forged2.max_amount_minor = forged2.max_amount_minor.wrapping_add(1);
        prop_assert!(auth.verify(&forged2, &sig).is_err());
    }

    #[test]
    fn token_engine_round_trips(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let enc = URL_SAFE_NO_PAD.encode(&bytes);
        prop_assert!(!enc.contains(['+', '/', '=']));
        let back = URL_SAFE_NO_PAD.decode(&enc).unwrap();
        prop_assert_eq!(back, bytes);
    }

    #[test]
    fn garbage_signature_never_verifies_nor_panics(s in "\\PC*") {
        let auth = Authority::from_seed([7u8; 32]);
        let m = Mandate {
            version: 1,
            mandate_id: "mnd_g".into(),
            agent_id: "a".into(),
            merchant_id: "merchant-001".into(),
            action: "create_order".into(),
            currency: "INR".into(),
            max_amount_minor: 100,
            issued_at: unix_now().saturating_sub(10),
            expires_at: unix_now() + 3_600,
            nonce: "n_g".into(),
        };
        // A random string is not a valid signature for m (forgery would break
        // Ed25519); the call must return Err, never panic.
        prop_assert!(auth.verify(&m, &s).is_err());
    }

    #[test]
    fn garbage_json_never_parses_as_mandate_nor_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        // Random bytes are essentially never a valid Mandate; parsing must
        // fail cleanly, never panic.
        prop_assert!(serde_json::from_slice::<Mandate>(&bytes).is_err());
    }
}

#[test]
fn jcs_output_is_field_order_independent() {
    let a: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
    let b: serde_json::Value = serde_json::from_str(r#"{"a":2,"b":1}"#).unwrap();
    assert_eq!(
        serde_jcs::to_vec(&a).unwrap(),
        serde_jcs::to_vec(&b).unwrap()
    );
}

#[test]
fn new_token_body_decodes_to_requested_entropy() {
    let t = mandatepay::mandates::new_token("mnd_", 12);
    assert!(t.starts_with("mnd_"));
    let raw = URL_SAFE_NO_PAD.decode(&t["mnd_".len()..]).unwrap();
    assert_eq!(raw.len(), 12);
}
