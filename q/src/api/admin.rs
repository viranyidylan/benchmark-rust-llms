//! Dead-letter queue & admin endpoints (PLAN.md, T8).
//!
//! All routes are guarded by [`admin_authorized`] (401 otherwise).

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::{ApiError, AppState};
use crate::db::DbError;
use crate::model::{Delivery, DeliveryStatus, DlqEntry, Stats};
use crate::security::auth::admin_authorized;

/// Default page size for `GET /admin/dead-letters`.
const DEFAULT_LIMIT: u32 = 50;
/// Hard cap on the `limit` query parameter.
const MAX_LIMIT: u32 = 1000;

fn require_admin(headers: &HeaderMap, admin_key: &str) -> Result<(), ApiError> {
    if admin_authorized(headers, admin_key) {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

fn db_err(e: DbError) -> ApiError {
    ApiError::internal(format!("db error: {e}"))
}

fn payload_value(payload: &[u8]) -> serde_json::Value {
    serde_json::from_slice(payload).unwrap_or(serde_json::Value::String(
        String::from_utf8_lossy(payload).into_owned(),
    ))
}

/// Wire representation of a `deliveries` row (PLAN.md §4: `200` full record).
#[derive(Debug, Serialize)]
pub struct DeliveryResponse {
    pub id: Uuid,
    pub idempotency_key: Option<String>,
    pub destination: String,
    pub payload: serde_json::Value,
    pub status: DeliveryStatus,
    pub attempts: u32,
    pub max_attempts: u32,
    pub next_retry_at: i64,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<&Delivery> for DeliveryResponse {
    fn from(d: &Delivery) -> Self {
        Self {
            id: d.id,
            idempotency_key: d.idempotency_key.clone(),
            destination: d.destination.clone(),
            payload: payload_value(&d.payload),
            status: d.status,
            attempts: d.attempts,
            max_attempts: d.max_attempts,
            next_retry_at: d.next_retry_at,
            last_error: d.last_error.clone(),
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

/// Wire representation of a `dead_letters` row.
#[derive(Debug, Serialize)]
pub struct DlqEntryResponse {
    pub id: Uuid,
    pub delivery_id: String,
    pub destination: String,
    pub payload: serde_json::Value,
    pub attempts: u32,
    pub last_error: Option<String>,
    pub dead_lettered_at: i64,
}

impl From<&DlqEntry> for DlqEntryResponse {
    fn from(e: &DlqEntry) -> Self {
        Self {
            id: e.id,
            delivery_id: e.delivery_id.clone(),
            destination: e.destination.clone(),
            payload: payload_value(&e.payload),
            attempts: e.attempts,
            last_error: e.last_error.clone(),
            dead_lettered_at: e.dead_lettered_at,
        }
    }
}

#[derive(Deserialize)]
pub struct DlqQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// `GET /admin/dead-letters?limit=&offset=` — list DLQ entries, oldest first.
pub async fn list_dead_letters(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DlqQuery>,
) -> Result<Json<Vec<DlqEntryResponse>>, ApiError> {
    require_admin(&headers, &state.cfg.admin_key)?;
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let offset = q.offset.unwrap_or(0) as usize;
    let entries = state.db.list_dead_letters(limit, offset).map_err(db_err)?;
    Ok(Json(entries.iter().map(DlqEntryResponse::from).collect()))
}

/// `POST /admin/dead-letters/{id}/replay` — requeue the dead-lettered
/// delivery (pending, attempts = 0, due now); the DLQ row is kept for audit.
/// `{id}` is the DLQ entry id from `GET /admin/dead-letters`.
pub async fn replay(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    require_admin(&headers, &state.cfg.admin_key)?;
    let entry = state
        .db
        .find_dlq_entry(&id)
        .map_err(db_err)?
        .ok_or_else(|| ApiError::not_found("unknown dead-letter id"))?;
    let delivery_id = Uuid::parse_str(&entry.delivery_id)
        .map_err(|_| ApiError::internal("corrupt dead-letter row"))?;
    if !state.db.replay_dead_letter(&delivery_id).map_err(db_err)? {
        return Err(ApiError::not_found("delivery is not dead-lettered"));
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "requeued": true, "delivery_id": delivery_id })),
    ))
}

/// `GET /deliveries/{id}` — full delivery record.
pub async fn get_delivery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<DeliveryResponse>, ApiError> {
    require_admin(&headers, &state.cfg.admin_key)?;
    let d = state
        .db
        .find(&id)
        .map_err(db_err)?
        .ok_or_else(|| ApiError::not_found("unknown delivery id"))?;
    Ok(Json(DeliveryResponse::from(&d)))
}

/// `GET /admin/stats` — queue counters (DB) + process counters (Metrics).
pub async fn stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<StatsResponse>, ApiError> {
    require_admin(&headers, &state.cfg.admin_key)?;
    let queue = state.db.stats().map_err(db_err)?;
    Ok(Json(StatsResponse {
        queue,
        process: state.metrics.snapshot(),
    }))
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub queue: Stats,
    pub process: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::IntoFuture;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use axum::body::Body;
    use axum::http::header::AUTHORIZATION;
    use axum::http::{Method, Request};
    use axum::routing::Router;
    use axum::serve;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::api::{router, AppState, Metrics};
    use crate::config::Config;
    use crate::db::Db;
    use crate::delivery::worker::{build_client, Worker};
    use crate::model::{Delivery, DeliveryStatus, NewDelivery};
    use crate::security::ratelimit::RateLimiter;
    use crate::security::ssrf::SsrfPolicy;

    const ADMIN: &str = "Bearer test-admin";

    fn app(db: Arc<Db>, cfg: Config, metrics: Metrics) -> Router {
        let state = AppState {
            db,
            cfg: cfg.clone(),
            metrics,
            ssrf: SsrfPolicy::new(cfg.allow_private_destinations, vec![80, 443]),
            limiter: Arc::new(RateLimiter::new(
                cfg.rate_limit_per_min,
                Duration::from_secs(60),
            )),
        };
        router(state)
    }

    async fn call(
        app: &Router,
        method: Method,
        uri: &str,
        auth: Option<&str>,
    ) -> axum::response::Response {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        if let Some(a) = auth {
            req.headers_mut().insert(AUTHORIZATION, a.parse().unwrap());
        }
        app.clone().oneshot(req).await.unwrap()
    }

    async fn body_json(res: axum::response::Response) -> serde_json::Value {
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Mock destination that answers every request with `status`.
    async fn start_always(status: u16) -> (String, u16) {
        let app = Router::new().fallback(move || {
            let s = status;
            async move { StatusCode::from_u16(s).unwrap() }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, app).into_future());
        (format!("http://{}:{}", addr.ip(), addr.port()), addr.port())
    }

    /// Run a worker (sharing `metrics` with the app) until the delivery is
    /// dead-lettered, then shut it down.
    async fn dead_letter_via_worker(
        db: &Arc<Db>,
        cfg: &Config,
        port: u16,
        metrics: Metrics,
        id: &Uuid,
    ) -> Delivery {
        let worker = Worker::new(
            db.clone(),
            cfg.clone(),
            build_client(cfg),
            SsrfPolicy::new(cfg.allow_private_destinations, vec![80, 443, port]),
            metrics,
        );
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(async move { worker.run(&mut rx).await });
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut row = None;
        while Instant::now() < deadline {
            if let Some(d) = db.find(id).unwrap() {
                if d.status == DeliveryStatus::DeadLetter {
                    row = Some(d);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let row = row.unwrap_or_else(|| panic!("delivery did not reach dead_letter"));
        let _ = tx.send_replace(true);
        handle.await.unwrap();
        row
    }

    #[tokio::test]
    async fn always_500_max_attempts_2_dlq_replay_stats() {
        let (dest, port) = start_always(500).await;
        let mut cfg = Config::test_defaults();
        cfg.max_attempts = 2;
        let db = Arc::new(Db::new(":memory:").unwrap());
        let id = Uuid::new_v4();
        db.insert(&NewDelivery {
            id,
            idempotency_key: None,
            destination: dest.clone(),
            payload: br#"{"dlq": "test"}"#.to_vec(),
            max_attempts: 2,
        })
        .unwrap();

        let metrics = Metrics::new();
        let row = dead_letter_via_worker(&db, &cfg, port, metrics.clone(), &id).await;
        assert_eq!(row.status, DeliveryStatus::DeadLetter);
        assert!(row.last_error.unwrap().contains("500"));

        let app = app(db.clone(), cfg, metrics);

        // The row appears in the dead-letters list.
        let res = call(&app, Method::GET, "/admin/dead-letters", Some(ADMIN)).await;
        assert_eq!(res.status(), StatusCode::OK);
        let v = body_json(res).await;
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["delivery_id"], id.to_string());
        assert_eq!(v[0]["attempts"], 1);
        assert!(v[0]["last_error"].as_str().unwrap().contains("500"));
        let entry_id = v[0]["id"].as_str().unwrap().to_string();

        // Full delivery record.
        let res = call(&app, Method::GET, &format!("/deliveries/{id}"), Some(ADMIN)).await;
        assert_eq!(res.status(), StatusCode::OK);
        let v = body_json(res).await;
        assert_eq!(v["status"], "dead_letter");
        assert_eq!(v["destination"], dest);
        assert_eq!(v["payload"]["dlq"], "test");

        // Replay: 202, delivery reset to pending / attempts 0.
        let res = call(
            &app,
            Method::POST,
            &format!("/admin/dead-letters/{entry_id}/replay"),
            Some(ADMIN),
        )
        .await;
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let v = body_json(res).await;
        assert_eq!(v["requeued"], true);
        assert_eq!(v["delivery_id"], id.to_string());

        let res = call(&app, Method::GET, &format!("/deliveries/{id}"), Some(ADMIN)).await;
        assert_eq!(res.status(), StatusCode::OK);
        let v = body_json(res).await;
        assert_eq!(v["status"], "pending");
        assert_eq!(v["attempts"], 0);

        // DLQ row kept for audit.
        let res = call(&app, Method::GET, "/admin/dead-letters", Some(ADMIN)).await;
        assert_eq!(res.status(), StatusCode::OK);
        let v = body_json(res).await;
        assert_eq!(v.as_array().unwrap().len(), 1);

        // Stats reflect the counts (queue + process counters).
        let res = call(&app, Method::GET, "/admin/stats", Some(ADMIN)).await;
        assert_eq!(res.status(), StatusCode::OK);
        let v = body_json(res).await;
        assert_eq!(v["queue"]["submitted"], 1);
        assert_eq!(v["queue"]["delivered"], 0);
        assert_eq!(v["queue"]["pending"], 1);
        assert_eq!(v["queue"]["dead_letters"], 1);
        assert_eq!(v["process"]["dead_lettered"], 1);
        assert_eq!(v["process"]["retryable_failures"], 1);
    }

    #[tokio::test]
    async fn unauthorized_401() {
        let db = Arc::new(Db::new(":memory:").unwrap());
        let cfg = Config::test_defaults();
        let app = app(db, cfg, Metrics::new());
        let unknown = Uuid::new_v4();
        let uris: Vec<(Method, String)> = vec![
            (Method::GET, "/admin/dead-letters".to_string()),
            (
                Method::POST,
                format!("/admin/dead-letters/{unknown}/replay"),
            ),
            (Method::GET, format!("/deliveries/{unknown}")),
            (Method::GET, "/admin/stats".to_string()),
        ];
        for (method, uri) in uris {
            // No auth header at all.
            let res = call(&app, method.clone(), &uri, None).await;
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no auth: {uri}");
            // Wrong key.
            let res = call(&app, method, &uri, Some("Bearer nope")).await;
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "bad key: {uri}");
        }
    }

    #[tokio::test]
    async fn unknown_ids_404() {
        let db = Arc::new(Db::new(":memory:").unwrap());
        let cfg = Config::test_defaults();
        let app = app(db, cfg, Metrics::new());
        let unknown = Uuid::new_v4();
        let res = call(
            &app,
            Method::GET,
            &format!("/deliveries/{unknown}"),
            Some(ADMIN),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let res = call(
            &app,
            Method::POST,
            &format!("/admin/dead-letters/{unknown}/replay"),
            Some(ADMIN),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
