use std::collections::HashMap;

use axum::{
    extract::{
        rejection::JsonRejection, DefaultBodyLimit, Path, Query, Request, State,
    },
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{error::ApiError, models, security, AppState};

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/webhook", post(create_webhook))
        .route("/webhook/{id}", get(get_webhook))
        .route("/dlq", get(list_dlq))
        .route("/dlq/{id}/requeue", post(requeue_from_dlq))
        .route("/stats", get(get_stats))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_token,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .merge(protected)
        .layer(DefaultBodyLimit::max(state.cfg.max_payload_bytes))
        .with_state(state)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// If an API token is configured, require it (constant-time comparison) on
/// every route except /healthz.
async fn require_token(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if let Some(expected) = state.cfg.api_token.as_deref() {
        let provided = req
            .headers()
            .get("x-api-token")
            .and_then(|v| v.to_str().ok());
        let ok = provided
            .map(|p| constant_time_eq(p.as_bytes(), expected.as_bytes()))
            .unwrap_or(false);
        if !ok {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "missing or invalid API token" })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Deserialize)]
pub struct WebhookRequest {
    pub data: serde_json::Value,
    pub destination: String,
}

#[derive(serde::Serialize)]
pub struct EnqueueResponse {
    pub id: String,
    pub status: &'static str,
}

/// Accept a webhook for delivery. The job is durably persisted (SQLite WAL,
/// synchronous=FULL) before the 202 is returned, so an accepted webhook is
/// never lost, even if the process crashes immediately afterwards.
async fn create_webhook(
    State(state): State<AppState>,
    payload: Result<Json<WebhookRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<EnqueueResponse>), ApiError> {
    let Json(req) = payload.map_err(|e| {
        let text = e.body_text();
        match e.into_response().status() {
            StatusCode::PAYLOAD_TOO_LARGE => {
                ApiError::PayloadTooLarge(format!("request body exceeds the configured limit: {text}"))
            }
            _ => ApiError::BadRequest(format!("invalid request body: {text}")),
        }
    })?;

    if req.data.is_null() {
        return Err(ApiError::BadRequest("'data' must not be null".to_string()));
    }

    security::validate_destination(&req.destination, state.cfg.allow_private_destinations)
        .await
        .map_err(ApiError::Unprocessable)?;

    let body = serde_json::to_string(&req.data)
        .map_err(|e| ApiError::BadRequest(format!("payload is not serializable: {e}")))?;
    if body.len() > state.cfg.max_payload_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "serialized payload is {} bytes, exceeding the maximum of {} bytes",
            body.len(),
            state.cfg.max_payload_bytes
        )));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp_millis();

    sqlx::query(
        "INSERT INTO deliveries
            (id, destination, payload, status, attempts, max_attempts,
             next_attempt_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?6, ?6)",
    )
    .bind(&id)
    .bind(&req.destination)
    .bind(&body)
    .bind(models::STATUS_PENDING)
    .bind(state.cfg.max_attempts)
    .bind(now)
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::info!(id = %id, destination = %req.destination, "webhook accepted");
    Ok((
        StatusCode::ACCEPTED,
        Json(EnqueueResponse {
            id,
            status: models::STATUS_PENDING,
        }),
    ))
}

async fn get_webhook(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<models::DeliveryStatus>, ApiError> {
    let row = sqlx::query("SELECT * FROM deliveries WHERE id = ?1")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    match row {
        Some(row) => Ok(Json(
            models::map_row(&row).map_err(|e| ApiError::Internal(e.to_string()))?,
        )),
        None => Err(ApiError::NotFound),
    }
}

async fn list_dlq(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .clamp(1, 500);

    let rows = sqlx::query(
        "SELECT * FROM deliveries WHERE status = ?1 ORDER BY updated_at DESC LIMIT ?2",
    )
    .bind(models::STATUS_DEAD_LETTERED)
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    let deliveries: Vec<models::DeliveryStatus> = rows
        .iter()
        .map(models::map_row)
        .collect::<Result<_, _>>()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let count = deliveries.len();
    Ok(Json(json!({ "count": count, "deliveries": deliveries })))
}

/// Move a dead-lettered delivery back to the queue with a fresh attempt
/// budget.
async fn requeue_from_dlq(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = sqlx::query("SELECT status FROM deliveries WHERE id = ?1")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let Some(row) = row else {
        return Err(ApiError::NotFound);
    };

    let status: String = sqlx::Row::try_get(&row, "status")
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    if status != models::STATUS_DEAD_LETTERED {
        return Err(ApiError::Conflict(format!(
            "delivery is '{status}': only dead-lettered deliveries can be requeued"
        )));
    }

    let now = Utc::now().timestamp_millis();
    sqlx::query(
        "UPDATE deliveries
         SET status = ?1, attempts = 0, next_attempt_at = ?2, updated_at = ?2,
             last_error = NULL, delivered_at = NULL
         WHERE id = ?3",
    )
    .bind(models::STATUS_PENDING)
    .bind(now)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::info!(id = %id, "dead-lettered delivery requeued");
    Ok(Json(json!({ "id": id, "status": models::STATUS_PENDING })))
}

async fn get_stats(
    State(state): State<AppState>,
    _headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rows = sqlx::query("SELECT status, COUNT(*) AS count FROM deliveries GROUP BY status")
        .fetch_all(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let mut counts = serde_json::Map::new();
    for row in rows {
        let status: String = sqlx::Row::try_get(&row, "status")
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let count: i64 = sqlx::Row::try_get(&row, "count")
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        counts.insert(status, json!(count));
    }

    Ok(Json(serde_json::Value::Object(counts)))
}
