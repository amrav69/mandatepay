use mandatepay::{
    app::{AppState, build_router},
    gateway::Gateway,
    mandates::Authority,
    store::Db,
};
use std::sync::Arc;

pub fn test_app() -> (axum::Router, String) {
    let api_key = "test-key-123".to_string();
    let authority = Authority::from_seed([7u8; 32]);
    let db = Db::open(":memory:").expect("in-memory db");
    let gateway = Gateway::Mock;
    let state = Arc::new(AppState {
        authority,
        db,
        gateway,
        api_key: api_key.clone(),
        max_mandate_cap: 100_000,
    });
    (build_router(state), api_key)
}
