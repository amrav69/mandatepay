//! Each test is one attacker or one mistake. Every one but `happy_path` must be refused.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer, SigningKey};
use mandate_core::*;

const NOW: u64 = 1_800_000_000;

struct World {
    human: SigningKey,
    agent: SigningKey,
    intent: IntentMandate,
    approval: PrincipalApproval,
    cart: CartMandate,
    cart_sig: String,
}

fn principal(w: &World) -> Ed25519Principal {
    Ed25519Principal {
        principal_id: "passkey-shanmukh".into(),
        public_key: w.human.verifying_key(),
    }
}

fn approve(human: &SigningKey, intent: &IntentMandate) -> PrincipalApproval {
    let h = intent_hash(intent).unwrap();
    PrincipalApproval {
        principal_id: intent.principal_id.clone(),
        signature: B64.encode(human.sign(&h).to_bytes()),
    }
}

fn sign_cart(agent: &SigningKey, cart: &CartMandate) -> String {
    let mut bytes = b"mandate-core.cart.v2.".to_vec();
    bytes.extend(serde_jcs::to_vec(cart).unwrap());
    B64.encode(agent.sign(&bytes).to_bytes())
}

fn world() -> World {
    let human = SigningKey::from_bytes(&[1u8; 32]);
    let agent = SigningKey::from_bytes(&[2u8; 32]);
    let intent = IntentMandate {
        version: VERSION,
        intent_id: "int_1".into(),
        principal_id: "passkey-shanmukh".into(),
        agent_pubkey: B64.encode(agent.verifying_key().as_bytes()),
        merchants: vec!["merchant-001".into()],
        currency: CURRENCY.into(),
        per_order_cap_minor: 50_000,
        total_budget_minor: 200_000,
        issued_at: NOW - 10,
        expires_at: NOW + 86_400,
        nonce: "n_intent".into(),
    };
    let approval = approve(&human, &intent);
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
    let cart_sig = sign_cart(&agent, &cart);
    World { human, agent, intent, approval, cart, cart_sig }
}

fn run(w: &World, spent: u64) -> Result<Approved, Reject> {
    verify_checkout(&w.intent, &w.approval, &principal(w), &w.cart, &w.cart_sig, spent, NOW)
}

/// Re-sign the cart after editing it, as an honest-but-buggy agent would.
fn resign(w: &mut World) {
    w.cart_sig = sign_cart(&w.agent, &w.cart);
}

#[test]
fn happy_path() {
    let w = world();
    assert_eq!(
        run(&w, 0),
        Ok(Approved { amount_minor: 45_000, merchant_id: "merchant-001".into(), cart_nonce: "n_cart_1".into() })
    );
}

#[test]
fn agent_cannot_approve_its_own_intent() {
    // The headline attack from the review: agent key signs the intent itself.
    let mut w = world();
    w.approval = approve(&w.agent, &w.intent);
    assert_eq!(run(&w, 0), Err(Reject::Approval));
}

#[test]
fn server_or_anyone_else_cannot_approve() {
    let mut w = world();
    w.approval = approve(&SigningKey::from_bytes(&[9u8; 32]), &w.intent);
    assert_eq!(run(&w, 0), Err(Reject::Approval));
}

#[test]
fn raising_the_cap_after_approval_breaks_it() {
    let mut w = world();
    w.intent.per_order_cap_minor = 5_000_000;
    assert_eq!(run(&w, 0), Err(Reject::Approval));
}

#[test]
fn adding_a_merchant_after_approval_breaks_it() {
    let mut w = world();
    w.intent.merchants.push("evil-shop".into());
    assert_eq!(run(&w, 0), Err(Reject::Approval));
}

#[test]
fn garbage_approval_signature() {
    let mut w = world();
    w.approval.signature = "%%%".into();
    assert_eq!(run(&w, 0), Err(Reject::Approval));
}

#[test]
fn approval_for_a_different_principal() {
    let mut w = world();
    w.approval.principal_id = "someone-else".into();
    assert_eq!(run(&w, 0), Err(Reject::Malformed));
}

#[test]
fn cart_for_another_intent() {
    let mut w = world();
    w.cart.intent_hash = hex::encode([0u8; 32]);
    resign(&mut w);
    assert_eq!(run(&w, 0), Err(Reject::WrongIntent));
}

#[test]
fn cart_signed_by_a_stranger() {
    let mut w = world();
    w.cart_sig = sign_cart(&SigningKey::from_bytes(&[7u8; 32]), &w.cart);
    assert_eq!(run(&w, 0), Err(Reject::CartSignature));
}

#[test]
fn cart_edited_after_agent_signed() {
    let mut w = world();
    w.cart.items[0].name = "gold chain".into();
    assert_eq!(run(&w, 0), Err(Reject::CartSignature));
}

#[test]
fn intent_signature_cannot_be_reused_as_cart_signature() {
    // Domain separation: the human's intent signature is not a cart signature.
    let mut w = world();
    w.cart_sig = w.approval.signature.clone();
    assert_eq!(run(&w, 0), Err(Reject::CartSignature));
}

#[test]
fn merchant_not_in_intent() {
    let mut w = world();
    w.cart.merchant_id = "evil-shop".into();
    resign(&mut w);
    assert_eq!(run(&w, 0), Err(Reject::Merchant));
}

#[test]
fn total_does_not_match_items() {
    let mut w = world();
    w.cart.total_minor = 100;
    resign(&mut w);
    assert_eq!(run(&w, 0), Err(Reject::CartTotal));
}

#[test]
fn zero_quantity_item() {
    let mut w = world();
    w.cart.items[0].qty = 0;
    w.cart.total_minor = 0;
    resign(&mut w);
    assert_eq!(run(&w, 0), Err(Reject::CartTotal));
}

#[test]
fn overflowing_line_items() {
    let mut w = world();
    w.cart.items[0].qty = u32::MAX;
    w.cart.items[0].unit_price_minor = u64::MAX;
    resign(&mut w);
    assert_eq!(run(&w, 0), Err(Reject::CartTotal));
}

#[test]
fn over_per_order_cap() {
    let mut w = world();
    w.cart.items[0].qty = 2; // 90,000 > 50,000
    w.cart.total_minor = 90_000;
    resign(&mut w);
    assert_eq!(run(&w, 0), Err(Reject::OverCap));
}

#[test]
fn budget_is_counted_in_rupees_not_requests() {
    // 4 x ₹450 = ₹1,800 fits the ₹2,000 budget; the 5th order does not.
    let w = world();
    assert!(run(&w, 4 * 45_000 - 45_000).is_ok());
    assert_eq!(run(&w, 4 * 45_000), Err(Reject::OverBudget));
}

#[test]
fn spent_overflow_is_refused() {
    let w = world();
    assert_eq!(run(&w, u64::MAX), Err(Reject::OverBudget));
}

#[test]
fn expired_and_future_intents() {
    let w = world();
    let p = principal(&w);
    let at = |now| verify_checkout(&w.intent, &w.approval, &p, &w.cart, &w.cart_sig, 0, now);
    assert_eq!(at(w.intent.expires_at), Err(Reject::Window));
    assert_eq!(at(w.intent.issued_at - 1), Err(Reject::Window));
}

#[test]
fn wrong_version_or_currency() {
    let mut w = world();
    w.cart.version = 1;
    assert_eq!(run(&w, 0), Err(Reject::Version));
    let mut w = world();
    w.cart.currency = "USD".into();
    assert_eq!(run(&w, 0), Err(Reject::Currency));
}

#[test]
fn errors_never_leak_policy_numbers() {
    for r in [Reject::OverCap, Reject::OverBudget, Reject::Merchant] {
        assert!(!r.to_string().chars().any(|c| c.is_ascii_digit()));
    }
}
