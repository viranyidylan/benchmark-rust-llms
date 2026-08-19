use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Inbound request body for `POST /webhook`.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookRequest {
    pub data: serde_json::Value,
    pub destination: String,
}

/// Response body for an accepted webhook (`202 Accepted`).
#[derive(Debug, Clone, Serialize)]
pub struct WebhookAccepted {
    pub id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    InFlight,
    Delivered,
    Dead,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            JobStatus::Pending => "pending",
            JobStatus::InFlight => "in_flight",
            JobStatus::Delivered => "delivered",
            JobStatus::Dead => "dead",
        }
    }
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JobStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(JobStatus::Pending),
            "in_flight" => Ok(JobStatus::InFlight),
            "delivered" => Ok(JobStatus::Delivered),
            "dead" => Ok(JobStatus::Dead),
            other => Err(anyhow::anyhow!("unknown job status: {other}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Job {
    pub id: Uuid,
    pub destination: String,
    pub payload: serde_json::Value,
    pub status: JobStatus,
    pub attempts: i64,
    pub max_attempts: i64,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Dead-letter-queue view of a job that exhausted its retries.
#[derive(Debug, Clone, Serialize)]
pub struct DlqEntry {
    pub id: Uuid,
    pub destination: String,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub updated_at: DateTime<Utc>,
}

impl From<Job> for DlqEntry {
    fn from(job: Job) -> Self {
        DlqEntry {
            id: job.id,
            destination: job.destination,
            attempts: job.attempts,
            last_error: job.last_error,
            updated_at: job.updated_at,
        }
    }
}
