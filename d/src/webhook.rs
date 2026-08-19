use axum::{extract::State, http::StatusCode, Json};
use serde_json::json;

use crate::error::AppError;
use crate::models::{WebhookJob, WebhookRequest};
use crate::appstate::AppState;

pub async fn create_webhook(
    State(state): State<AppState>,
    Json(req): Json<WebhookRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    crate::security::validate_destination(&req.destination)
        .map_err(|e| AppError::BadRequest(e))?;

    let job = WebhookJob::new(&req, state.config.max_attempts);
    state.db.enqueue(&job).map_err(AppError::from)?;

    tracing::info!(job_id = %job.id, destination = %job.destination, "webhook enqueued");
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "id": job.id.to_string(), "status": "queued" })),
    ))
}
