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
    // M37: malformed .env files were silently swallowed; surface parse errors.
    // A missing file is fine (fresh clone / Docker), a malformed one is not.
    if let Err(e) = dotenvy::dotenv() {
        let msg = e.to_string();
        if !msg.contains("not found") && !msg.contains("No such") {
            eprintln!(".env parse warning: {e}");
        }
    }
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let authority = Authority::from_seed(mandates::load_seed());
    tracing::info!(authority_key = %authority.public_key_b64(), "authority public key");

    let gateway = Gateway::from_env();
    let db = match Db::open("mandatepay.db") {
        Ok(d) => d,
        Err(e) => {
            eprintln!("failed to open sqlite ledger mandatepay.db: {e}");
            std::process::exit(1);
        }
    };
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
    let addr: SocketAddr = match format!("{host}:8080").parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid BIND_HOST '{host}': {e}");
            std::process::exit(1);
        }
    };
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind {addr} (port 8080 already in use?): {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(%addr, "listening");
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
