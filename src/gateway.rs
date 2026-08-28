use crate::mandates::{Mandate, new_token, unix_now};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("gateway credentials not configured")]
    NotConfigured,
    #[error("razorpay http failure: {0}")]
    Http(String),
    #[error("razorpay api error: {0}")]
    Api(String),
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
            eprintln!("gateway: razorpay-test keys present -> live test-mode client enabled");
            Gateway::Razorpay {
                key_id,
                key_secret,
                http: reqwest::Client::new(),
            }
        } else {
            eprintln!("gateway: no RAZORPAY keys in env -> mock gateway (no money moves)");
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
                id: new_token("order_mock_", 9),
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
                let resp = http
                    .post("https://api.razorpay.com/v1/orders")
                    .basic_auth(key_id, Some(key_secret))
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
