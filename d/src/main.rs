mod appstate;
mod auth;
mod config;
mod db;
mod dlq;
mod error;
mod models;
mod security;
mod webhook;
mod worker;

use std::sync::Arc;

use crate::appstate::{build_router, AppState};
use crate::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,webhook_delivery=debug".into()),
        )
        .init();

    let config = Arc::new(Config::from_env());
    auth::set_api_key(config.api_key.clone());

    let db = db::Db::open(&config.db_path)?;
    tracing::info!(db = %config.db_path.display(), "opened database");

    let state = AppState { db: db.clone(), config: config.clone() };
    let app = build_router(state);

    // Start delivery worker.
    let worker_config = config.clone();
    tokio::spawn(async move {
        worker::run_worker(db, worker_config).await;
    });

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, "webhook delivery service listening");
    axum::serve(listener, app).await?;
    Ok(())
}

