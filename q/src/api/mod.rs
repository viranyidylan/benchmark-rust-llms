//! HTTP API (PLAN.md, T5+).

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::db::Db;
use crate::security::ratelimit::RateLimiter;
use crate::security::ssrf::SsrfPolicy;

pub mod admin;
pub mod health;
pub mod webhook;

/// Shared application state, passed to axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub cfg: Config,
    pub metrics: Metrics,
    pub ssrf: SsrfPolicy,
    pub limiter: Arc<RateLimiter>,
}

/// Process-wide counters (PLAN.md, T5).
#[derive(Clone)]
pub struct Metrics {
    pub submitted: Arc<AtomicU64>,
    pub delivered: Arc<AtomicU64>,
    pub dead_lettered: Arc<AtomicU64>,
    pub permanent_failures: Arc<AtomicU64>,
    pub retryable_failures: Arc<AtomicU64>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            submitted: Arc::new(AtomicU64::new(0)),
            delivered: Arc::new(AtomicU64::new(0)),
            dead_lettered: Arc::new(AtomicU64::new(0)),
            permanent_failures: Arc::new(AtomicU64::new(0)),
            retryable_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_submitted(&self) {
        Self::inc(&self.submitted);
    }
    pub fn inc_delivered(&self) {
        Self::inc(&self.delivered);
    }
    pub fn inc_dead_lettered(&self) {
        Self::inc(&self.dead_lettered);
    }
    pub fn inc_permanent_failures(&self) {
        Self::inc(&self.permanent_failures);
    }
    pub fn inc_retryable_failures(&self) {
        Self::inc(&self.retryable_failures);
    }

    /// Current counter values (for `GET /admin/stats`, T8).
    pub fn snapshot(&self) -> serde_json::Value {
        json!({
            "submitted": self.submitted.load(Ordering::Relaxed),
            "delivered": self.delivered.load(Ordering::Relaxed),
            "dead_lettered": self.dead_lettered.load(Ordering::Relaxed),
            "permanent_failures": self.permanent_failures.load(Ordering::Relaxed),
            "retryable_failures": self.retryable_failures.load(Ordering::Relaxed),
        })
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// API error with a client-safe message (PLAN.md §4: never leak internals).
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized".to_string(),
        }
    }

    pub fn too_many_requests() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "rate limit exceeded".to_string(),
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = json!({ "error": self.message });
        (self.status, axum::Json(body)).into_response()
    }
}

/// Build the API router (PLAN.md §4).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/webhook", post(webhook::webhook_handler))
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .route("/deliveries/{id}", get(admin::get_delivery))
        .route("/admin/dead-letters", get(admin::list_dead_letters))
        .route("/admin/dead-letters/{id}/replay", post(admin::replay))
        .route("/admin/stats", get(admin::stats))
        .with_state(state.clone())
        .layer(RequestBodyLimitLayer::new(
            state.cfg.max_payload_bytes as usize,
        ))
        .layer(TraceLayer::new_for_http())
}
