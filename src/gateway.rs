use crate::mandates::{Mandate, try_new_token, unix_now};
use serde::{Deserialize, Serialize};

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

pub enum Gateway {
    Mock,
    Razorpay {
        key_id: String,
        key_secret: String,
        http: reqwest::Client,
    },
}

impl Gateway {
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
