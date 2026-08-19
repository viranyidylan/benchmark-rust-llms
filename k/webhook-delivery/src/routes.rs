//! HTTP API: `POST /webhook`, `GET /health`, and the DLQ endpoints.
//!
//! The router is built by [`build_router`]; shared state is [`AppState`].

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::config::Config;
use crate::db::Db;
use crate::error::ApiError;
use crate::models::{DlqEntry, WebhookAccepted, WebhookRequest};
use crate::security::{self, SecurityError};

/// Shared application state handed to every handler (cheap to clone).
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<Config>,
}

/// Build the HTTP router with all routes and middleware.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        // /webhook bypasses axum's default 2 MiB body limit; the handler enforces
        // config.max_payload_bytes itself so the limit is configurable and yields
        // our JSON 413 error instead of axum's built-in rejection.
        .route(
            "/webhook",
            post(post_webhook).layer(DefaultBodyLimit::disable()),
        )
        .route("/health", get(health))
        .route("/dlq", get(list_dlq))
        .route("/dlq/:id/retry", post(retry_dlq))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// `POST /webhook` — accept a webhook delivery request.
///
/// Order of checks: size limit (413) → JSON parse (400) → SSRF guard (400).
/// Durability first: the job is INSERTed as `pending` *before* the `202` is
/// returned, so an acknowledged webhook can never be lost (at-least-once).
async fn post_webhook(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<(StatusCode, Json<WebhookAccepted>), ApiError> {
    security::enforce_size(body.len(), state.config.max_payload_bytes)
        .map_err(|_| ApiError::PayloadTooLarge)?;

    let req: WebhookRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::Validation(format!("invalid JSON body: {e}")))?;

    security::validate_destination(&req.destination, state.config.allow_private_destinations)
        .await
        .map_err(security_error_to_api)?;

    // db.insert_job serializes `data` to compact JSON before storing.
    let id = Uuid::new_v4();
    state
        .db
        .insert_job(id, &req.destination, &req.data, state.config.max_attempts)
        .await?;

    tracing::info!(%id, destination = %req.destination, "webhook accepted");
    Ok((StatusCode::ACCEPTED, Json(WebhookAccepted { id })))
}

/// `GET /health` — liveness probe.
async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// `GET /dlq` — list up to 100 dead-lettered jobs, most recently updated first.
async fn list_dlq(State(state): State<AppState>) -> Result<Json<Vec<DlqEntry>>, ApiError> {
    let dead = state.db.list_dead(100).await?;
    Ok(Json(dead.into_iter().map(DlqEntry::from).collect()))
}

/// `POST /dlq/:id/retry` — move a dead job back to `pending` for a fresh
/// round of delivery attempts. 404 when no dead job with that id exists.
async fn retry_dlq(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if state.db.requeue_dead(id).await? {
        tracing::info!(%id, "dead job requeued");
        Ok((StatusCode::OK, Json(json!({ "requeued": true }))))
    } else {
        Ok((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("no dead job with id {id}") })),
        ))
    }
}

/// Map security-layer failures onto API errors: size limits → 413,
/// everything else (bad URL, bad scheme, credentials, blocked IP, DNS) → 400.
fn security_error_to_api(err: SecurityError) -> ApiError {
    match err {
        SecurityError::PayloadTooLarge { .. } => ApiError::PayloadTooLarge,
        other => ApiError::Validation(other.to_string()),
    }
}
