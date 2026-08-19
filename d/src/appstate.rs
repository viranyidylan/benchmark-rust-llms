use std::sync::Arc;

use crate::config::Config;
use crate::db::Db;

/// Shared application state passed to axum handlers via `State`.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<Config>,
}

use axum::{middleware, routing::{get, post}, Router};
use tower_http::limit::RequestBodyLimitLayer;
use crate::auth;

/// Build the full axum application: webhook endpoint, DLQ endpoints, and
/// security middleware (auth + body-size limit).
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/webhook", post(crate::webhook::create_webhook))
        .route("/dlq", get(crate::dlq::list_dlq))
        .route("/dlq/:id/redeliver", post(crate::dlq::redeliver))
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(1_048_576)) // 1 MiB body cap
        .layer(middleware::from_fn(auth::require_api_key))
}
