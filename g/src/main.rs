use std::sync::Arc;

use tokio::{net::TcpListener, sync::Semaphore};
use webhook_delivery::{config::Config, db, deliver, routes, worker, AppState};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = Arc::new(Config::from_env());

    let pool = db::init_pool(&cfg.database_url, cfg.db_max_connections)
        .await
        .expect("failed to initialize database");

    let reclaimed = db::reset_processing(&pool)
        .await
        .expect("failed to reset in-flight deliveries");
    if reclaimed > 0 {
        tracing::warn!(
            reclaimed,
            "returned interrupted deliveries from previous run to the queue"
        );
    }

    let state = AppState {
        cfg: cfg.clone(),
        pool,
        http: deliver::build_http_client(cfg.delivery_timeout_secs),
        sema: Arc::new(Semaphore::new(cfg.max_concurrent_deliveries)),
    };

    tokio::spawn(worker::run(state.clone()));

    let app = routes::router(state);
    let listener = TcpListener::bind(cfg.bind_addr)
        .await
        .expect("failed to bind listen address");

    tracing::info!(
        addr = %listener.local_addr().unwrap(),
        allow_private_destinations = cfg.allow_private_destinations,
        max_attempts = cfg.max_attempts,
        "webhook delivery service listening"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install ctrl-c handler");
    tracing::info!("shutdown signal received");
}
