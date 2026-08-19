use std::sync::Arc;

use tracing_subscriber::EnvFilter;
use webhook_delivery::config::Config;
use webhook_delivery::db::Db;
use webhook_delivery::routes::{build_router, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // RUST_LOG overrides; default to `info`.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let bind_addr = config.bind_addr.clone();

    let db = Db::connect(&config).await?;
    let state = AppState {
        db,
        config: Arc::new(config),
    };

    let shutdown = tokio_util::sync::CancellationToken::new();
    let workers = webhook_delivery::worker::spawn_workers(state.clone(), shutdown.clone());

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!(%bind_addr, "webhook-delivery listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.ok();
        })
        .await?;

    // The HTTP server has stopped: tell the workers to wind down and give them
    // a bounded time to finish their in-flight work before exiting.
    shutdown.cancel();
    if tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for handle in workers {
            if let Err(e) = handle.await {
                tracing::warn!(error = %e, "worker task failed to join cleanly");
            }
        }
    })
    .await
    .is_err()
    {
        tracing::warn!("timed out waiting for delivery workers to stop; exiting anyway");
    }
    Ok(())
}
