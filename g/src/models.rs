use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{sqlite::SqliteRow, Row};

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_PROCESSING: &str = "processing";
pub const STATUS_DELIVERED: &str = "delivered";
pub const STATUS_DEAD_LETTERED: &str = "dead_lettered";

/// A delivery job atomically claimed by the worker.
#[derive(Debug, Clone)]
pub struct ClaimedJob {
    pub id: String,
    pub destination: String,
    /// Canonical serialized `data`; delivered byte-for-byte on every attempt
    /// so the signature stays valid across retries.
    pub payload: String,
    pub attempts: i64,
    pub max_attempts: i64,
}

#[derive(Debug, Serialize)]
pub struct DeliveryStatus {
    pub id: String,
    pub status: String,
    pub destination: String,
    pub attempts: i64,
    pub max_attempts: i64,
    pub created_at: String,
    pub updated_at: String,
    pub next_attempt_at: Option<String>,
    pub delivered_at: Option<String>,
    pub last_error: Option<String>,
}

fn millis_to_rfc3339(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ms.to_string())
}

pub fn map_row(row: &SqliteRow) -> Result<DeliveryStatus, sqlx::Error> {
    Ok(DeliveryStatus {
        id: row.try_get("id")?,
        status: row.try_get("status")?,
        destination: row.try_get("destination")?,
        attempts: row.try_get("attempts")?,
        max_attempts: row.try_get("max_attempts")?,
        created_at: millis_to_rfc3339(row.try_get("created_at")?),
        updated_at: millis_to_rfc3339(row.try_get("updated_at")?),
        next_attempt_at: row
            .try_get::<Option<i64>, _>("next_attempt_at")?
            .map(millis_to_rfc3339),
        delivered_at: row
            .try_get::<Option<i64>, _>("delivered_at")?
            .map(millis_to_rfc3339),
        last_error: row.try_get("last_error")?,
    })
}
