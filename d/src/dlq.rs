use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::error::AppError;
use crate::appstate::AppState;

pub async fn list_dlq(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let entries = state.db.list_dlq().map_err(AppError::from)?;
    let items: Vec<Value> = entries
        .into_iter()
        .map(|e| {
            json!({
                "id": e.id.to_string(),
                "job_id": e.job_id.to_string(),
                "payload": e.payload,
                "destination": e.destination,
                "attempts": e.attempts,
                "last_error": e.last_error,
                "moved_at": e.moved_at.to_rfc3339(),
            })
        })
        .collect();
    Ok(Json(json!({ "entries": items, "count": items.len() })))
}

pub async fn redeliver(
    State(state): State<AppState>,
    Path(entry_id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    match state
        .db
        .redeliver(&entry_id, state.config.max_attempts)
        .map_err(AppError::from)?
    {
        Some(job) => Ok((
            StatusCode::ACCEPTED,
            Json(json!({ "status": "requeued", "job_id": job.id.to_string() })),
        )),
        None => Err(AppError::BadRequest("dead letter entry not found".into())),
    }
}
