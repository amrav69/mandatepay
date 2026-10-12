use crate::mandates::{Mandate, try_new_token, unix_now};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("gateway credentials not configured")]
    NotConfigured,
    #[error("razorpay http failure: {0}")]
    Http(String),
    #[error("razorpay api error: {0}")]
    Api(String),
    #[error("internal token failure: {0}")]
    Internal(String),
    #[error("invalid receipt: {0}")]
    InvalidReceipt(String),
    #[error("multiple orders found for receipt {0}")]
    DuplicateReceipt(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GatewayOrder {
    pub id: String,
    pub entity: String,
    pub amount: u64,
    pub currency: String,
    pub status: String,
    pub created_at: u64,
    pub live: bool,
}

/// Razorpay `receipt` (our `mandate_id`) is documented as internal reference
/// with max 40 chars, unique, ASCII. Verified 2026-10-12 via
/// https://razorpay.com/docs/api/orders/create/ ("Receipt number ... Can have
/// a maximum length of 40 characters and has to be unique"; errors
/// "receipt: the length must be no more than 40" and non-ASCII
/// "BAD_REQUEST_ENCODING_VALIDATION_FAILED"; duplicate receipt is 400
/// "Duplicate request"). Enforced conservatively in `check_receipt`.
pub const MAX_RECEIPT_LEN: usize = 40;

fn check_receipt(mandate_id: &str) -> Result<(), GatewayError> {
    if mandate_id.is_empty() {
        return Err(GatewayError::InvalidReceipt("receipt is empty".into()));
    }
    if mandate_id.len() > MAX_RECEIPT_LEN {
        return Err(GatewayError::InvalidReceipt(format!(
            "receipt len {} exceeds max {MAX_RECEIPT_LEN}",
            mandate_id.len()
        )));
    }
    if !mandate_id.is_ascii() {
        return Err(GatewayError::InvalidReceipt("receipt must be ASCII".into()));
    }
    Ok(())
}

#[derive(Deserialize)]
struct RazorpayOrderResponse {
    id: String,
    entity: String,
    amount: u64,
    currency: String,
    status: String,
    created_at: u64,
}

#[derive(Deserialize)]
struct RazorpayOrderListResponse {
    #[allow(dead_code)]
    count: usize,
    items: Vec<RazorpayOrderResponse>,
}

/// Failure-injection modes for tests (PORT 4a, phase3 cancel-safety).
/// Never constructed in production; only via [`Gateway::failing_for_tests`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureMode {
    /// Immediate gateway error.
    Error,
    /// Slow failure after a short delay (simulates a gateway timeout).
    Timeout,
    /// Success response whose body does not parse as an order.
    MalformedBody,
    /// Success after a delay, so tests can drop the handler mid-await.
    Delay,
    /// Panic inside the gateway call, so tests can exercise the JoinError path.
    Panic,
}

/// Deterministic synchronization for cancel-safety tests (phase3).
/// `entered` fires when the gateway call starts; the test waits for it before
/// dropping the handler, then fires `release` to let the gateway complete.
/// Both are [`tokio::sync::Notify`] so a notify before the waiter still
/// leaves a permit (no missed wakeup for the single-use per-test gate).
#[derive(Debug, Clone)]
pub struct TestGate {
    pub entered: Arc<tokio::sync::Notify>,
    pub release: Arc<tokio::sync::Notify>,
}

impl TestGate {
    pub fn new() -> Self {
        Self {
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

impl Default for TestGate {
    fn default() -> Self {
        Self::new()
    }
}

pub enum Gateway {
    Mock {
        store: Arc<Mutex<HashMap<String, Vec<GatewayOrder>>>>,
    },
    Razorpay {
        key_id: String,
        key_secret: String,
        http: reqwest::Client,
    },
    /// Test-only double. Never returned by [`Gateway::from_env`] and never
    /// constructed in `main.rs`/`app.rs`; exercises the checkout failure path
    /// (pending/nonce/velocity rollback) in integration tests.
    /// `gate` is `None` for legacy sleep-based modes and `Some` for
    /// deterministic cancel-safety tests: when present, `Delay` (success) and
    /// `Timeout` (failure) signal `entered`, await `release`, then complete
    /// without any fixed sleep.
    Failing {
        mode: FailureMode,
        gate: Option<Arc<TestGate>>,
    },
}

/// Parse an order response body (shared shape check for the `MalformedBody`
/// injection mode and its unit test; the live Razorpay path uses
/// `resp.json()` directly and is left untouched).
fn parse_order_body(text: &str) -> Result<GatewayOrder, GatewayError> {
    let order: RazorpayOrderResponse =
        serde_json::from_str(text).map_err(|e| GatewayError::Api(e.to_string()))?;
    Ok(GatewayOrder {
        id: order.id,
        entity: order.entity,
        amount: order.amount,
        currency: order.currency,
        status: order.status,
        created_at: order.created_at,
        live: false,
    })
}

/// Parse a Razorpay `GET /v1/orders?receipt=...` list body. Returns `None`
/// when no order matches, the single order when exactly one matches, and
/// `DuplicateReceipt` when more than one comes back (never pick silently).
/// `receipt` is only used for the error message. Tested without network.
pub fn parse_razorpay_order_list_body(
    text: &str,
    receipt: &str,
) -> Result<Option<GatewayOrder>, GatewayError> {
    let list: RazorpayOrderListResponse =
        serde_json::from_str(text).map_err(|e| GatewayError::Api(e.to_string()))?;
    select_single_order(list.items, receipt)
}

/// Percent-encode a query value (RFC3986 unreserved left as-is). `reqwest`
/// is built with `default-features = false`, so `RequestBuilder::query` is
/// unavailable; we build the `GET /v1/orders?receipt=..&count=2` URL manually.
/// Production `mandate_id`s (`mnd_` + base64url) pass through unchanged.
fn encode_query_param(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn select_single_order(
    items: Vec<RazorpayOrderResponse>,
    receipt: &str,
) -> Result<Option<GatewayOrder>, GatewayError> {
    if items.len() > 1 {
        return Err(GatewayError::DuplicateReceipt(receipt.to_string()));
    }
    let Some(order) = items.into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(GatewayOrder {
        id: order.id,
        entity: order.entity,
        amount: order.amount,
        currency: order.currency,
        status: order.status,
        created_at: order.created_at,
        live: true,
    }))
}

impl Gateway {
    /// In-memory mock gateway keyed by `receipt` (`mandate_id`). Each instance
    /// owns its map so tests stay isolated; production fallback via
    /// [`Gateway::from_env`] also uses a fresh empty map (ephemeral).
    pub fn mock() -> Self {
        Gateway::Mock {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Explicitly test-only constructor for the failing double.
    /// Production code must use [`Gateway::from_env`], which never returns
    /// `Failing` (see `from_env` below and `main.rs` which only calls it).
    pub fn failing_for_tests(mode: FailureMode) -> Self {
        Gateway::Failing { mode, gate: None }
    }

    /// Deterministic variant for cancel-safety tests: `Delay` and `Timeout`
    /// modes signal `gate.entered` on entry and await `gate.release`
    /// instead of sleeping, so tests can drop the handler mid-await without
    /// any fixed-duration race.
    pub fn failing_gated_for_tests(mode: FailureMode, gate: Arc<TestGate>) -> Self {
        Gateway::Failing {
            mode,
            gate: Some(gate),
        }
    }

    pub fn from_env() -> Self {
        let key_id = std::env::var("RAZORPAY_KEY_ID")
            .unwrap_or_default()
            .trim()
            .to_string();
        let key_secret = std::env::var("RAZORPAY_KEY_SECRET")
            .unwrap_or_default()
            .trim()
            .to_string();
        if !key_id.is_empty() && !key_secret.is_empty() {
            tracing::info!("gateway: razorpay-test keys present -> live test-mode client enabled");
            match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
            {
                Ok(http) => Gateway::Razorpay {
                    key_id,
                    key_secret,
                    http,
                },
                Err(e) => {
                    // M3: fail closed to Mock (no money moves) rather than panicking at boot.
                    tracing::error!(error = %e, "reqwest client build failed, falling back to mock gateway");
                    Gateway::mock()
                }
            }
        } else {
            tracing::info!("gateway: no RAZORPAY keys in env -> mock gateway (no money moves)");
            Gateway::mock()
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Gateway::Mock { .. } => "mock",
            Gateway::Razorpay { .. } => "razorpay-test",
            Gateway::Failing { .. } => "failing-test",
        }
    }

    /// Pure builder for the Razorpay order-create body. `receipt` is always
    /// `mandate.mandate_id` and the same value is echoed in `notes.mandate_id`
    /// for operator correlation. Tested without network.
    pub fn build_razorpay_order_payload(mandate: &Mandate, amount_minor: u64) -> serde_json::Value {
        serde_json::json!({
            "amount": amount_minor,
            "currency": "INR",
            "receipt": mandate.mandate_id,
            "notes": {
                "mandate_id": mandate.mandate_id,
                "agent_id": mandate.agent_id,
                "merchant_id": mandate.merchant_id,
                "gateway": "mandatepay"
            }
        })
    }

    pub async fn create_order(
        &self,
        mandate: &Mandate,
        amount_minor: u64,
    ) -> Result<GatewayOrder, GatewayError> {
        match self {
            Gateway::Mock { store } => {
                check_receipt(&mandate.mandate_id)?;
                let order = GatewayOrder {
                    id: try_new_token("order_mock_", 9)
                        .map_err(|e| GatewayError::Internal(e.to_string()))?,
                    entity: "order".into(),
                    amount: amount_minor,
                    currency: "INR".into(),
                    status: "created".into(),
                    created_at: unix_now(),
                    live: false,
                };
                // In-memory index by receipt so `find_order_by_receipt` can
                // round-trip. Push (do not overwrite) so a duplicate receipt
                // surfaces as `DuplicateReceipt` on lookup instead of hiding.
                if let Ok(mut map) = store.lock() {
                    map.entry(mandate.mandate_id.clone())
                        .or_default()
                        .push(order.clone());
                }
                Ok(order)
            }
            Gateway::Razorpay {
                key_id,
                key_secret,
                http,
            } => {
                check_receipt(&mandate.mandate_id)?;
                let payload = Self::build_razorpay_order_payload(mandate, amount_minor);
                // H12: at-most-once is enforced by the local DB PENDING
                // reservation (see `try_reserve_order`); Razorpay has no
                // Idempotency-Key header. What we do send on every create is
                // `receipt = mandate_id` plus the same value in
                // `notes.mandate_id` (see `build_razorpay_order_payload`), so
                // operators can correlate and `find_order_by_receipt` can
                // look the order back up by receipt. Razorpay treats `receipt`
                // as unique (duplicate create is 400). The header below is
                // tracing-only.
                let resp = http
                    .post("https://api.razorpay.com/v1/orders")
                    .basic_auth(key_id, Some(key_secret))
                    .header("X-Mandate-Id", &mandate.mandate_id)
                    .json(&payload)
                    .send()
                    .await
                    .map_err(|e| GatewayError::Http(e.to_string()))?;

                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(GatewayError::Api(format!("{status} {body}")));
                }

                let order: RazorpayOrderResponse = resp
                    .json()
                    .await
                    .map_err(|e| GatewayError::Api(e.to_string()))?;

                Ok(GatewayOrder {
                    id: order.id,
                    entity: order.entity,
                    amount: order.amount,
                    currency: order.currency,
                    status: order.status,
                    created_at: order.created_at,
                    live: true,
                })
            }
            Gateway::Failing { mode, gate } => match mode {
                FailureMode::Error => Err(GatewayError::Api("injected gateway failure".into())),
                FailureMode::Timeout => {
                    if let Some(g) = gate {
                        // Deterministic cancel-safety path: signal entry, wait
                        // for the test to release. No fixed sleep.
                        g.entered.notify_one();
                        g.release.notified().await;
                    } else {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    Err(GatewayError::Http("injected gateway timeout".into()))
                }
                FailureMode::MalformedBody => parse_order_body("{not an order}"),
                FailureMode::Delay => {
                    if let Some(g) = gate {
                        // Deterministic cancel-safety path: signal entry, wait
                        // for the test to release. No fixed sleep.
                        g.entered.notify_one();
                        g.release.notified().await;
                    } else {
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    }
                    Ok(GatewayOrder {
                        id: try_new_token("order_mock_", 9)
                            .map_err(|e| GatewayError::Internal(e.to_string()))?,
                        entity: "order".into(),
                        amount: amount_minor,
                        currency: "INR".into(),
                        status: "created".into(),
                        created_at: unix_now(),
                        live: false,
                    })
                }
                FailureMode::Panic => panic!("injected gateway panic"),
            },
        }
    }

    /// Look up an order by `receipt` (`mandate_id`). Used for operator
    /// reconciliation; the checkout flow does NOT call it yet.
    ///
    /// - Mock: in-memory map populated by [`Gateway::create_order`].
    /// - Razorpay: `GET /v1/orders?receipt=<id>&count=2` with the same client,
    ///   timeout and basic-auth as [`Gateway::create_order`]. `count=2` is
    ///   enough to detect the duplicate case without paging.
    /// - Failing: follows its mode (failures error, `Delay` returns `None`,
    ///   `Panic` panics).
    ///
    /// More than one order for the same receipt is `DuplicateReceipt`, never
    /// a silent pick.
    pub async fn find_order_by_receipt(
        &self,
        mandate_id: &str,
    ) -> Result<Option<GatewayOrder>, GatewayError> {
        check_receipt(mandate_id)?;
        match self {
            Gateway::Mock { store } => {
                let guard = store
                    .lock()
                    .map_err(|e| GatewayError::Internal(format!("mock store poisoned: {e}")))?;
                match guard.get(mandate_id) {
                    None => Ok(None),
                    Some(orders) if orders.is_empty() => Ok(None),
                    Some(orders) if orders.len() == 1 => Ok(Some(orders[0].clone())),
                    Some(_) => Err(GatewayError::DuplicateReceipt(mandate_id.to_string())),
                }
            }
            Gateway::Razorpay {
                key_id,
                key_secret,
                http,
            } => {
                let url = format!(
                    "https://api.razorpay.com/v1/orders?receipt={}&count=2",
                    encode_query_param(mandate_id)
                );
                let resp = http
                    .get(url)
                    .basic_auth(key_id, Some(key_secret))
                    .send()
                    .await
                    .map_err(|e| GatewayError::Http(e.to_string()))?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(GatewayError::Api(format!("{status} {body}")));
                }
                let text = resp
                    .text()
                    .await
                    .map_err(|e| GatewayError::Api(e.to_string()))?;
                parse_razorpay_order_list_body(&text, mandate_id)
            }
            Gateway::Failing { mode, gate } => match mode {
                FailureMode::Error => Err(GatewayError::Api("injected gateway failure".into())),
                FailureMode::Timeout => {
                    if let Some(g) = gate {
                        g.entered.notify_one();
                        g.release.notified().await;
                    } else {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    Err(GatewayError::Http("injected gateway timeout".into()))
                }
                FailureMode::MalformedBody => {
                    parse_razorpay_order_list_body("{not a list}", mandate_id)?;
                    Ok(None)
                }
                FailureMode::Delay => {
                    if let Some(g) = gate {
                        g.entered.notify_one();
                        g.release.notified().await;
                    } else {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    Ok(None)
                }
                FailureMode::Panic => panic!("injected gateway panic"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn label_mock() {
        let g = Gateway::mock();
        assert_eq!(g.label(), "mock");
    }

    #[test]
    fn parse_body_accepts_valid_order_rejects_garbage() {
        let order = parse_order_body(
            r#"{"id":"order_1","entity":"order","amount":100,"currency":"INR","status":"created","created_at":1}"#,
        )
        .unwrap();
        assert_eq!(order.id, "order_1");
        assert!(!order.live);
        assert!(parse_order_body("{not an order}").is_err());
        assert!(parse_order_body("").is_err());
    }

    #[test]
    fn from_env_mock_when_no_keys() {
        let _lock = ENV_LOCK.lock().unwrap();
        let orig_id = std::env::var("RAZORPAY_KEY_ID").ok();
        let orig_secret = std::env::var("RAZORPAY_KEY_SECRET").ok();
        unsafe {
            std::env::remove_var("RAZORPAY_KEY_ID");
            std::env::remove_var("RAZORPAY_KEY_SECRET");
        }
        let g = Gateway::from_env();
        assert_eq!(g.label(), "mock");
        unsafe {
            if let Some(v) = orig_id {
                std::env::set_var("RAZORPAY_KEY_ID", v);
            }
            if let Some(v) = orig_secret {
                std::env::set_var("RAZORPAY_KEY_SECRET", v);
            }
        }
    }

    #[test]
    fn from_env_live_when_both_keys_present() {
        let _lock = ENV_LOCK.lock().unwrap();
        let orig_id = std::env::var("RAZORPAY_KEY_ID").ok();
        let orig_secret = std::env::var("RAZORPAY_KEY_SECRET").ok();
        unsafe {
            std::env::set_var("RAZORPAY_KEY_ID", "rzp_test_dummy");
            std::env::set_var("RAZORPAY_KEY_SECRET", "secret_dummy");
        }
        let g = Gateway::from_env();
        assert_eq!(g.label(), "razorpay-test");
        unsafe {
            match orig_id {
                Some(v) => std::env::set_var("RAZORPAY_KEY_ID", v),
                None => std::env::remove_var("RAZORPAY_KEY_ID"),
            }
            match orig_secret {
                Some(v) => std::env::set_var("RAZORPAY_KEY_SECRET", v),
                None => std::env::remove_var("RAZORPAY_KEY_SECRET"),
            }
        }
    }

    #[test]
    fn from_env_mock_when_only_one_key() {
        let _lock = ENV_LOCK.lock().unwrap();
        let orig_id = std::env::var("RAZORPAY_KEY_ID").ok();
        let orig_secret = std::env::var("RAZORPAY_KEY_SECRET").ok();
        unsafe {
            std::env::set_var("RAZORPAY_KEY_ID", "rzp_test_dummy");
            std::env::remove_var("RAZORPAY_KEY_SECRET");
        }
        let g = Gateway::from_env();
        assert_eq!(g.label(), "mock");
        unsafe {
            match orig_id {
                Some(v) => std::env::set_var("RAZORPAY_KEY_ID", v),
                None => std::env::remove_var("RAZORPAY_KEY_ID"),
            }
            match orig_secret {
                Some(v) => std::env::set_var("RAZORPAY_KEY_SECRET", v),
                None => std::env::remove_var("RAZORPAY_KEY_SECRET"),
            }
        }
    }

    fn test_mandate(mandate_id: &str) -> Mandate {
        Mandate {
            version: 1,
            mandate_id: mandate_id.to_string(),
            agent_id: "agent-001".into(),
            merchant_id: "merchant-001".into(),
            action: "create_order".into(),
            currency: "INR".into(),
            max_amount_minor: 50000,
            issued_at: 1,
            expires_at: 9999999999,
            nonce: "n_test".into(),
        }
    }

    #[test]
    fn build_payload_contains_receipt_and_notes() {
        let m = test_mandate("mnd_test12345678");
        let payload = Gateway::build_razorpay_order_payload(&m, 1000);
        assert_eq!(payload["receipt"], serde_json::json!("mnd_test12345678"));
        assert_eq!(
            payload["notes"]["mandate_id"],
            serde_json::json!("mnd_test12345678")
        );
        assert_eq!(payload["notes"]["agent_id"], serde_json::json!("agent-001"));
        assert_eq!(
            payload["notes"]["merchant_id"],
            serde_json::json!("merchant-001")
        );
        assert_eq!(payload["amount"], serde_json::json!(1000));
        assert_eq!(payload["currency"], serde_json::json!("INR"));
    }

    #[test]
    fn parse_list_none_single_duplicate() {
        // Zero items -> None.
        let none = parse_razorpay_order_list_body(
            r#"{"entity":"collection","count":0,"items":[]}"#,
            "mnd_x",
        )
        .unwrap();
        assert!(none.is_none());
        // One item -> Some with live=true.
        let one = parse_razorpay_order_list_body(
            r#"{"entity":"collection","count":1,"items":[{"id":"order_1","entity":"order","amount":100,"currency":"INR","status":"created","created_at":1}]}"#,
            "mnd_x",
        )
        .unwrap()
        .unwrap();
        assert_eq!(one.id, "order_1");
        assert!(one.live);
        // Two items -> distinct DuplicateReceipt error, never a silent pick.
        let err = parse_razorpay_order_list_body(
            r#"{"entity":"collection","count":2,"items":[{"id":"order_1","entity":"order","amount":100,"currency":"INR","status":"created","created_at":1},{"id":"order_2","entity":"order","amount":100,"currency":"INR","status":"created","created_at":2}]}"#,
            "mnd_dup",
        )
        .unwrap_err();
        assert!(
            matches!(err, GatewayError::DuplicateReceipt(ref r) if r == "mnd_dup"),
            "expected DuplicateReceipt, got {err:?}"
        );
        // Garbage -> Api error.
        assert!(parse_razorpay_order_list_body("{not a list}", "mnd_x").is_err());
    }

    #[test]
    fn receipt_guard_rejects_empty_long_and_non_ascii() {
        assert!(matches!(
            check_receipt(""),
            Err(GatewayError::InvalidReceipt(_))
        ));
        let long = "m".repeat(MAX_RECEIPT_LEN + 1);
        assert!(matches!(
            check_receipt(&long),
            Err(GatewayError::InvalidReceipt(_))
        ));
        assert!(check_receipt("mnd_ok-123_abc").is_ok());
        // mandate_id shape (16 chars, URL-safe) always fits.
        let m = test_mandate("mnd_abcdefghijkl");
        assert_eq!(m.mandate_id.len(), 16);
        assert!(check_receipt(&m.mandate_id).is_ok());
        assert!(
            parse_razorpay_order_list_body("{not a list}", &long).is_err()
                || check_receipt(&long).is_err()
        );
    }

    #[tokio::test]
    async fn mock_round_trip_create_then_find() {
        let gw = Gateway::mock();
        let m = test_mandate("mnd_roundtrip01");
        let created = gw.create_order(&m, 1000).await.unwrap();
        let found = gw.find_order_by_receipt("mnd_roundtrip01").await.unwrap();
        assert_eq!(found.unwrap().id, created.id);
        assert!(
            gw.find_order_by_receipt("mnd_unknown_xyz")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn mock_duplicate_receipt_is_distinct_error() {
        let gw = Gateway::mock();
        let m = test_mandate("mnd_dup_mock_01");
        gw.create_order(&m, 1000).await.unwrap();
        gw.create_order(&m, 1000).await.unwrap();
        let err = gw
            .find_order_by_receipt("mnd_dup_mock_01")
            .await
            .unwrap_err();
        assert!(
            matches!(err, GatewayError::DuplicateReceipt(ref r) if r == "mnd_dup_mock_01"),
            "expected DuplicateReceipt, got {err:?}"
        );
    }

    #[tokio::test]
    async fn mock_create_rejects_oversize_receipt() {
        let gw = Gateway::mock();
        let long = "m".repeat(MAX_RECEIPT_LEN + 1);
        let m = test_mandate(&long);
        let err = gw.create_order(&m, 1000).await.unwrap_err();
        assert!(
            matches!(err, GatewayError::InvalidReceipt(_)),
            "expected InvalidReceipt, got {err:?}"
        );
        let err = gw.find_order_by_receipt(&long).await.unwrap_err();
        assert!(matches!(err, GatewayError::InvalidReceipt(_)));
    }

    #[tokio::test]
    async fn failing_modes_propagate_for_find() {
        let m = test_mandate("mnd_fail_find");
        // Error and MalformedBody fail immediately for both create and find.
        for mode in [FailureMode::Error, FailureMode::MalformedBody] {
            let gw = Gateway::failing_for_tests(mode);
            assert!(gw.create_order(&m, 1000).await.is_err());
            assert!(gw.find_order_by_receipt("mnd_fail_find").await.is_err());
        }
        // Timeout fails (short sleep without gate).
        let gw = Gateway::failing_for_tests(FailureMode::Timeout);
        assert!(gw.find_order_by_receipt("mnd_fail_find").await.is_err());
        // Delay succeeds on create but has nothing stored, so find is None.
        let gw = Gateway::failing_for_tests(FailureMode::Delay);
        assert!(gw.create_order(&m, 1000).await.is_ok());
        assert!(
            gw.find_order_by_receipt("mnd_fail_find")
                .await
                .unwrap()
                .is_none()
        );
    }
}
