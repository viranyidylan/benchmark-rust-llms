//! webhook-delivery library (PLAN.md, T9/T10).
//!
//! Public modules: `api`, `config`, `db`, `delivery`, `model`, `security`.
//! The binary in `src/main.rs` is a thin wrapper around [`run`]; the
//! integration tests in `tests/` drive the same public API in-process.

pub mod api;
pub mod config;
pub mod db;
pub mod delivery;
pub mod model;
pub mod security;

use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use api::{router, AppState, Metrics};
use config::Config;
use db::Db;
use delivery::worker::{build_client, Worker};
use security::ratelimit::RateLimiter;
use security::ssrf::SsrfPolicy;

/// Run the full service (PLAN.md, T9): config -> database -> workers ->
/// HTTP server -> graceful shutdown on SIGINT/SIGTERM.
pub async fn run() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(1);
        }
    };

    // Create the database's parent directory if needed.
    if let Some(parent) = std::path::Path::new(&cfg.database_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("failed to create database directory: {e}");
            std::process::exit(1);
        }
    }

    let db = match Db::new(&cfg.database_path) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("database error: {e}");
            std::process::exit(1);
        }
    };

    let metrics = Metrics::new();
    let ssrf = SsrfPolicy::new(cfg.allow_private_destinations, vec![80, 443]);
    let limiter = Arc::new(RateLimiter::new(
        cfg.rate_limit_per_min,
        Duration::from_secs(60),
    ));
    let state = AppState {
        db: db.clone(),
        cfg: cfg.clone(),
        metrics: metrics.clone(),
        ssrf: ssrf.clone(),
        limiter: limiter.clone(),
    };

    let client = build_client(&cfg);

    // Housekeeping: periodically drop expired rate-limiter keys.
    {
        let limiter = limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                limiter.prune();
            }
        });
    }

    let listener = match tokio::net::TcpListener::bind(cfg.listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind {}: {e}", cfg.listen_addr);
            std::process::exit(1);
        }
    };
    tracing::info!(%cfg.listen_addr, "listening");

    // Spawn the delivery workers, each with its own shutdown receiver.
    let mut shutdown_txs = Vec::with_capacity(cfg.worker_count);
    let mut workers = Vec::with_capacity(cfg.worker_count);
    for _ in 0..cfg.worker_count {
        let (tx, rx) = watch::channel(false);
        shutdown_txs.push(tx);
        let worker = Worker::new(
            db.clone(),
            cfg.clone(),
            client.clone(),
            ssrf.clone(),
            metrics.clone(),
        );
        workers.push(tokio::spawn(async move {
            let mut rx = rx;
            worker.run(&mut rx).await;
        }));
    }

    let app = router(state);

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    let terminated = async {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "ctrl_c",
            _ = sigterm.recv() => "sigterm",
        }
    };

    tokio::select! {
        res = axum::serve(listener, app).into_future() => {
            if let Err(e) = res {
                tracing::error!(error = %e, "server error");
            }
        },
        sig = terminated => {
            tracing::info!(signal = sig, "shutdown signal received");
        }
    }

    // Ask the workers to stop and wait for them to drain.
    for tx in shutdown_txs {
        let _ = tx.send_replace(true);
    }
    for w in workers {
        let _ = w.await;
    }
    tracing::info!(
        active_rate_limit_keys = limiter.active_keys(),
        "workers drained; shutting down"
    );
    // `db` is dropped here, closing the SQLite connection cleanly.
}
