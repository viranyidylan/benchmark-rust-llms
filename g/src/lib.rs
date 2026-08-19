pub mod config;
pub mod db;
pub mod deliver;
pub mod error;
pub mod models;
pub mod routes;
pub mod security;
pub mod worker;

use std::sync::Arc;

use sqlx::SqlitePool;
use tokio::sync::Semaphore;

/// Shared application state handed to the HTTP handlers and the delivery worker.
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<config::Config>,
    pub pool: SqlitePool,
    pub http: reqwest::Client,
    /// Bounds the number of concurrent outbound deliveries.
    pub sema: Arc<Semaphore>,
}
