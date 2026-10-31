use thiserror::Error;

/// Every way a checkout is refused. Messages are deliberately generic:
/// they never echo caps, budgets or merchant lists back to the caller.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Reject {
    #[error("malformed mandate")]
    Malformed,
    #[error("unsupported mandate version")]
    Version,
    #[error("currency not supported")]
    Currency,
    #[error("mandate not yet valid or expired")]
    Window,
    #[error("principal approval invalid")]
    Approval,
    #[error("cart does not belong to this intent")]
    WrongIntent,
    #[error("cart signature invalid")]
    CartSignature,
    #[error("merchant not permitted")]
    Merchant,
    #[error("cart total does not match its items")]
    CartTotal,
    #[error("amount exceeds mandate policy")]
    OverCap,
    #[error("amount exceeds remaining budget")]
    OverBudget,
}
