//! Liveness / readiness endpoints (PLAN.md, T9).

use axum::extract::State;
use axum::http::StatusCode;

use crate::api::AppState;

/// `GET /healthz` — liveness: the process is up and serving.
pub async fn healthz() -> (StatusCode, &'static str) {
    (StatusCode::OK, "ok")
}

/// `GET /readyz` — readiness: the database is reachable.
pub async fn readyz(State(state): State<AppState>) -> StatusCode {
    if state.db.ping() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Method, Request};
    use axum::routing::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::api::{router, AppState, Metrics};
    use crate::config::Config;
    use crate::db::Db;
    use crate::security::ratelimit::RateLimiter;
    use crate::security::ssrf::SsrfPolicy;

    fn app(db: Arc<Db>) -> Router {
        let cfg = Config::test_defaults();
        let state = AppState {
            db,
            cfg: cfg.clone(),
            metrics: Metrics::new(),
            ssrf: SsrfPolicy::new(cfg.allow_private_destinations, vec![80, 443]),
            limiter: Arc::new(RateLimiter::new(
                cfg.rate_limit_per_min,
                Duration::from_secs(60),
            )),
        };
        router(state)
    }

    #[tokio::test]
    async fn healthz_200_ok() {
        let db = Arc::new(Db::new(":memory:").unwrap());
        let app = app(db);
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes, "ok");
    }

    #[tokio::test]
    async fn readyz_200_when_db_healthy() {
        let db = Arc::new(Db::new(":memory:").unwrap());
        let app = app(db);
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
