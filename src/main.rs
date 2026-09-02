use std::{net::SocketAddr, sync::Arc};

use mandatepay::{
    app::{build_router, parse_max_cap},
    auth::resolve_api_key,
    gateway::Gateway,
    mandates::{self, Authority},
    store::Db,
};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let authority = Authority::from_seed(mandates::load_seed());
    tracing::info!(authority_key = %authority.public_key_b64(), "authority public key");

    let gateway = Gateway::from_env();
    let db = Db::open("mandatepay.db").expect("failed to open sqlite ledger");
    let api_key = resolve_api_key();
    let max_mandate_cap = parse_max_cap();
    tracing::info!(
        mandate_cap = max_mandate_cap,
        rupees = max_mandate_cap as f64 / 100.0,
        "mandate cap"
    );
    let state = Arc::new(mandatepay::app::AppState {
        authority,
        db,
        gateway,
        api_key: api_key.clone(),
        max_mandate_cap,
    });

    let app = build_router(state);

    let host = std::env::var("BIND_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let addr: SocketAddr = format!("{host}:8080").parse().expect("invalid BIND_HOST");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("port 8080 already in use");
    tracing::info!(%addr, "listening");
    axum::serve(listener, app).await.expect("server crashed");
}
