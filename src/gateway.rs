use crate::error::AppError;
use crate::mandates::Mandate;

pub async fn create_test_order(_mandate: &Mandate) -> Result<String, AppError> {
    Err(AppError::Internal(
        "razorpay gateway wires up in phase 2".into(),
    ))
}
