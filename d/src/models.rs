use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// What callers POST to `/webhook`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRequest {
    /// Arbitrary payload to deliver to the destination.
    pub data: serde_json::Value,
    /// URL the payload is delivered to.
    pub destination: String,
}

/// A job queued for (or being) delivered.
#[derive(Debug, Clone)]
pub struct WebhookJob {
    pub id: Uuid,
    pub payload: serde_json::Value,
    pub destination: String,
    pub attempts: u32,
    pub max_attempts: u32,
    /// When the job is next eligible for a delivery attempt.
    pub next_attempt_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub status: DeliveryStatus,
}

impl WebhookJob {
    pub fn new(req: &WebhookRequest, max_attempts: u32) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            payload: req.data.clone(),
            destination: req.destination.clone(),
            attempts: 0,
            max_attempts,
            next_attempt_at: now,
            created_at: now,
            status: DeliveryStatus::Pending,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Dead,
}

/// A permanently failed delivery parked in the dead letter queue.
#[derive(Debug, Clone)]
pub struct DqlEntry {
    pub id: Uuid,
    pub job_id: Uuid,
    pub payload: serde_json::Value,
    pub destination: String,
    pub attempts: u32,
    pub last_error: String,
    pub moved_at: DateTime<Utc>,
}
