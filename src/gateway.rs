use crate::mandates::{Mandate, try_new_token, unix_now};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
}

#[derive(Debug, Serialize)]
pub struct GatewayOrder {
    pub id: String,
    pub entity: String,
    pub amount: u64,
    pub currency: String,
    pub status: String,
    pub created_at: u64,
    pub live: bool,
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
    Mock,
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

impl Gateway {
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
                    Gateway::Mock
                }
            }
        } else {
            tracing::info!("gateway: no RAZORPAY keys in env -> mock gateway (no money moves)");
            Gateway::Mock
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Gateway::Mock => "mock",
            Gateway::Razorpay { .. } => "razorpay-test",
            Gateway::Failing { .. } => "failing-test",
        }
    }

    pub async fn create_order(
        &self,
        mandate: &Mandate,
        amount_minor: u64,
    ) -> Result<GatewayOrder, GatewayError> {
        match self {
            Gateway::Mock => Ok(GatewayOrder {
                id: try_new_token("order_mock_", 9)
                    .map_err(|e| GatewayError::Internal(e.to_string()))?,
                entity: "order".into(),
                amount: amount_minor,
                currency: "INR".into(),
                status: "created".into(),
                created_at: unix_now(),
                live: false,
            }),
            Gateway::Razorpay {
                key_id,
                key_secret,
                http,
            } => {
                let payload = serde_json::json!({
                    "amount": amount_minor,
                    "currency": "INR",
                    "receipt": mandate.mandate_id,
                    "notes": {
                        "mandate_id": mandate.mandate_id,
                        "agent_id": mandate.agent_id,
                        "merchant_id": mandate.merchant_id,
                        "gateway": "mandatepay"
                    }
                });
                // H12: at-most-once relies on the local DB PENDING reservation, NOT on
                // this header. Razorpay /v1/orders has no documented Idempotency-Key
                // support; `receipt` carries the mandate_id for operator correlation.
                // The header below is tracing-only.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn label_mock() {
        let g = Gateway::Mock;
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
}
