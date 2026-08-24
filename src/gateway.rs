use crate::mandates::{Mandate, new_token, unix_now};
use serde::Serialize;

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

pub enum Gateway {
    Mock,
}

impl Gateway {
    pub fn from_env() -> Self {
        let has_keys = std::env::var("RAZORPAY_KEY_ID").is_ok()
            && std::env::var("RAZORPAY_KEY_SECRET").is_ok();
        if has_keys {
            eprintln!(
                "gateway: RAZORPAY keys present but live client arrives with the real swap; using mock"
            );
        } else {
            eprintln!("gateway: no RAZORPAY keys in env -> mock gateway (no money moves)");
        }
        Gateway::Mock
    }

    pub fn label(&self) -> &'static str {
        match self {
            Gateway::Mock => "mock",
        }
    }

    pub async fn create_order(
        &self,
        _mandate: &Mandate,
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
        }
    }
}
