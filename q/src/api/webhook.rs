//! Ingestion endpoint `POST /webhook` (PLAN.md, T5).
//!
//! Auth is applied in T6; this handler assumes the request is already
//! authenticated.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use url::Url;
use uuid::Uuid;

use crate::api::{ApiError, AppState};
use crate::db::DbError;
use crate::model::NewDelivery;
use crate::security::ssrf::{SsrfError, SsrfPolicy, SystemResolver};

/// `POST /webhook`
///
/// Body: `{"data": <any JSON>, "destination": "<url>"}`, optional
/// `Idempotency-Key` header. Returns `202 {"id", "status"}` on success, or
/// `200 {"id", "status", "duplicate": true}` when the idempotency key was
/// already used.
pub async fn webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    // Auth (T6): bearer or HMAC (fallback to bearer when the signature
    // header is absent). Rate limit by API key (or anonymous bucket).
    if !crate::security::auth::authorized(
        &headers,
        &body,
        &state.cfg.hmac_secret,
        &state.cfg.api_keys,
    ) {
        return Err(ApiError::unauthorized());
    }
    let rl_key = crate::security::auth::bearer_token(&headers)
        .unwrap_or("anonymous")
        .to_string();
    if !state.limiter.check(&rl_key) {
        return Err(ApiError::too_many_requests());
    }

    #[derive(Deserialize)]
    struct IngestRequest {
        /// Raw JSON of the submitted payload (stored verbatim, re-sent on
        /// delivery in T7).
        data: Box<serde_json::value::RawValue>,
        destination: String,
    }

    let req: IngestRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::bad_request("malformed JSON body"))?;
    let url = Url::parse(&req.destination)
        .map_err(|_| ApiError::bad_request("invalid destination url"))?;

    let id = Uuid::new_v4();
    let idempotency_key = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let payload = req.data.get().as_bytes().to_vec();
    let destination = req.destination;

    let input = IngestInput {
        url,
        id,
        idempotency_key,
        destination,
        payload,
        max_attempts: state.cfg.max_attempts,
    };
    let (db, ssrf, metrics) = (state.db.clone(), state.ssrf.clone(), state.metrics.clone());

    // DNS resolution and SQLite are blocking: run off the async runtime.
    let result = tokio::task::spawn_blocking(move || ingest_sync(&db, &ssrf, &input)).await;

    match result {
        Ok(Ok(IngestOutcome::Created)) => {
            metrics.inc_submitted();
            Ok((
                StatusCode::ACCEPTED,
                Json(json!({ "id": id.to_string(), "status": "pending" })),
            ))
        }
        Ok(Ok(IngestOutcome::Duplicate(existing, status))) => Ok((
            StatusCode::OK,
            Json(json!({
                "id": existing.to_string(),
                "status": status,
                "duplicate": true,
            })),
        )),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ApiError::internal("internal error")),
    }
}

enum IngestOutcome {
    Created,
    Duplicate(Uuid, String),
}

struct IngestInput {
    url: Url,
    id: Uuid,
    idempotency_key: Option<String>,
    destination: String,
    payload: Vec<u8>,
    max_attempts: u32,
}

fn ingest_sync(
    db: &crate::db::Db,
    ssrf: &SsrfPolicy,
    input: &IngestInput,
) -> Result<IngestOutcome, ApiError> {
    let resolver = SystemResolver;
    ssrf.validate(&input.url, &resolver).map_err(ssrf_error)?;
    let d = NewDelivery {
        id: input.id,
        idempotency_key: input.idempotency_key.clone(),
        destination: input.destination.clone(),
        payload: input.payload.clone(),
        max_attempts: input.max_attempts,
    };
    match db.insert(&d) {
        Ok(()) => Ok(IngestOutcome::Created),
        Err(DbError::IdempotencyConflict(existing)) => {
            let status = match db.find(&existing) {
                Ok(Some(d)) => d.status.as_str().to_string(),
                Ok(None) | Err(_) => "unknown".to_string(),
            };
            Ok(IngestOutcome::Duplicate(existing, status))
        }
        Err(e) => Err(ApiError::internal(format!("db insert failed: {e}"))),
    }
}

fn ssrf_error(e: SsrfError) -> ApiError {
    match e {
        SsrfError::BadScheme => ApiError::bad_request("destination scheme must be http or https"),
        SsrfError::MissingHost => ApiError::bad_request("destination has no host"),
        SsrfError::Userinfo => ApiError::forbidden("destination must not contain userinfo"),
        SsrfError::BadPort(port) => {
            ApiError::forbidden(format!("destination port {port} not allowed"))
        }
        SsrfError::PrivateIp(ip) => {
            ApiError::forbidden(format!("destination resolves to blocked IP {ip}"))
        }
        SsrfError::ResolutionFailed(e) => {
            ApiError::forbidden(format!("destination resolution failed: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{router, Metrics};
    use crate::config::Config;
    use crate::db::Db;
    use crate::security::ratelimit::RateLimiter;
    use axum::body::Body;
    use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> (axum::Router, std::sync::Arc<Db>) {
        let mut cfg = Config::test_defaults();
        cfg.allow_private_destinations = false;
        let db = std::sync::Arc::new(Db::new(":memory:").unwrap());
        let state = AppState {
            db: db.clone(),
            cfg: cfg.clone(),
            metrics: Metrics::new(),
            ssrf: SsrfPolicy::new(cfg.allow_private_destinations, vec![80, 443]),
            limiter: std::sync::Arc::new(RateLimiter::new(
                cfg.rate_limit_per_min,
                std::time::Duration::from_secs(60),
            )),
        };
        (router(state), db)
    }

    fn app_with_rate_limit(limit: u32) -> axum::Router {
        let mut cfg = Config::test_defaults();
        cfg.allow_private_destinations = false;
        cfg.rate_limit_per_min = limit;
        let db = std::sync::Arc::new(Db::new(":memory:").unwrap());
        let state = AppState {
            db,
            cfg: cfg.clone(),
            metrics: Metrics::new(),
            ssrf: SsrfPolicy::new(cfg.allow_private_destinations, vec![80, 443]),
            limiter: std::sync::Arc::new(RateLimiter::new(
                cfg.rate_limit_per_min,
                std::time::Duration::from_secs(60),
            )),
        };
        router(state)
    }

    async fn post(app: &axum::Router, body: &str, idem: Option<&str>) -> axum::response::Response {
        let mut req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/webhook")
            .body(Body::from(body.as_bytes().to_vec()))
            .unwrap();
        req.headers_mut()
            .insert(CONTENT_TYPE, "application/json".parse().unwrap());
        req.headers_mut()
            .insert(CONTENT_LENGTH, body.len().to_string().parse().unwrap());
        req.headers_mut()
            .insert(AUTHORIZATION, "Bearer test-key".parse().unwrap());
        if let Some(k) = idem {
            req.headers_mut()
                .insert("Idempotency-Key", k.parse().unwrap());
        }
        app.clone().oneshot(req).await.unwrap()
    }

    async fn post_unauth(app: &axum::Router, body: &str) -> axum::response::Response {
        let mut req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/webhook")
            .body(Body::from(body.as_bytes().to_vec()))
            .unwrap();
        req.headers_mut()
            .insert(CONTENT_TYPE, "application/json".parse().unwrap());
        req.headers_mut()
            .insert(CONTENT_LENGTH, body.len().to_string().parse().unwrap());
        app.clone().oneshot(req).await.unwrap()
    }

    async fn body_bytes(res: axum::response::Response) -> Vec<u8> {
        res.into_body().collect().await.unwrap().to_bytes().to_vec()
    }

    #[tokio::test]
    async fn happy_path_202_and_row_in_db() {
        let (app, db) = app();
        let body = r#"{"data": {"hello": "world"}, "destination": "https://93.184.216.34/hook"}"#;
        let res = post(&app, body, None).await;
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let v: serde_json::Value = serde_json::from_slice(&body_bytes(res).await).unwrap();
        assert_eq!(v["status"], "pending");
        let id = Uuid::parse_str(v["id"].as_str().unwrap()).unwrap();
        let row = db.find(&id).unwrap().unwrap();
        assert_eq!(row.destination, "https://93.184.216.34/hook");
        // RawValue stores the payload verbatim, exactly as submitted.
        assert_eq!(row.payload, r#"{"hello": "world"}"#.as_bytes());
    }

    #[tokio::test]
    async fn bad_json_400() {
        let (app, _) = app();
        let res = post(&app, "not json", None).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ftp_scheme_400() {
        let (app, _) = app();
        let body = r#"{"data": {}, "destination": "ftp://example.com/x"}"#;
        let res = post(&app, body, None).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn blocked_private_destination_403() {
        let (app, _) = app();
        let body = r#"{"data": {}, "destination": "http://127.0.0.1:9/x"}"#;
        let res = post(&app, body, None).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn duplicate_idempotency_key_200() {
        let (app, _) = app();
        let body = r#"{"data": {"n": 1}, "destination": "https://93.184.216.34/hook"}"#;
        let first = post(&app, body, Some("key-1")).await;
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let first_v: serde_json::Value = serde_json::from_slice(&body_bytes(first).await).unwrap();

        let second = post(&app, body, Some("key-1")).await;
        assert_eq!(second.status(), StatusCode::OK);
        let second_v: serde_json::Value =
            serde_json::from_slice(&body_bytes(second).await).unwrap();
        assert_eq!(second_v["duplicate"], true);
        assert_eq!(second_v["id"], first_v["id"]);
        assert_eq!(second_v["status"], "pending");
    }

    #[tokio::test]
    async fn missing_auth_401() {
        let (app, _) = app();
        let body = r#"{"data": {}, "destination": "https://93.184.216.34/"}"#;
        let res = post_unauth(&app, body).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_api_key_401() {
        let (app, _) = app();
        let mut req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/webhook")
            .body(Body::from(
                r#"{"data": {}, "destination": "https://93.184.216.34/"}"#
                    .as_bytes()
                    .to_vec(),
            ))
            .unwrap();
        req.headers_mut()
            .insert(CONTENT_TYPE, "application/json".parse().unwrap());
        req.headers_mut()
            .insert(AUTHORIZATION, "Bearer wrong-key".parse().unwrap());
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rate_limited_429() {
        let app = app_with_rate_limit(1);
        let body = r#"{"data": {}, "destination": "https://93.184.216.34/"}"#;
        let first = post(&app, body, None).await;
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let second = post(&app, body, None).await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn oversized_body_413() {
        let (app, _) = app();
        // test_defaults: max_payload_bytes = 1 MiB; send ~2 MiB.
        let big = "a".repeat(2 * 1024 * 1024);
        let body = format!(
            "{{\"data\": \"{}\", \"destination\": \"https://93.184.216.34/\"}}",
            big
        );
        let res = post(&app, &body, None).await;
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
