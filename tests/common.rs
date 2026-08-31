use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use mandatepay::{
    app::{AppState, build_router},
    gateway::Gateway,
    mandates::Authority,
    store::Db,
};
use std::sync::Arc;

pub fn random_test_key() -> String {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("os randomness unavailable");
    B64.encode(raw)
}

pub fn test_app() -> (axum::Router, String) {
    let api_key = random_test_key();
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

