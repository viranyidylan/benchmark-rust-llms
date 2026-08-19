//! Background delivery workers: claim due jobs, deliver over HTTP, and apply
//! the retry/backoff/DLQ policy.
//!
//! [`spawn_workers`] starts `config.worker_concurrency` independent tasks, each
//! with its own [`reqwest::Client`]. Every loop iteration claims a batch of due
//! jobs (each claim atomically increments `attempts`, so `job.attempts` is the
//! attempt just made), delivers them one by one, and records the outcome:
//!
//! - success → `mark_delivered`
//! - failure with `attempts < max_attempts` → `reschedule_job` at
//!   `now + backoff(attempts, base_delay_ms, max_delay_ms)`
//! - failure on the final attempt → `mark_dead` (the job lands in the DLQ)
//!
//! Payload bodies and the HMAC secret are never logged.

use std::time::Duration;

use chrono::Utc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::models::Job;
use crate::routes::AppState;
use crate::security;

/// Errors a single delivery attempt can produce.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// The destination responded, but with a non-2xx status code.
    #[error("destination returned HTTP status {0}")]
    Http(u16),
    /// The request never completed: connect failure, DNS, timeout, ...
    #[error("transport error: {0}")]
    Transport(String),
}

/// Spawn `config.worker_concurrency` delivery workers that run until the
/// `shutdown` token is cancelled. Returns their join handles so the caller can
/// wait for a graceful stop.
pub fn spawn_workers(state: AppState, shutdown: CancellationToken) -> Vec<JoinHandle<()>> {
    let n = state.config.worker_concurrency;
    (0..n)
        .map(|worker_id| tokio::spawn(worker_loop(worker_id, state.clone(), shutdown.clone())))
        .collect()
}

/// One worker's loop: build a client once, then claim → deliver → sleep.
async fn worker_loop(worker_id: usize, state: AppState, shutdown: CancellationToken) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(state.config.request_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client builder cannot fail with these options");

    loop {
        if shutdown.is_cancelled() {
            break;
        }

        let jobs = match state.db.claim_due_jobs(8).await {
            Ok(jobs) => jobs,
            Err(e) => {
                error!(worker_id, error = %e, "failed to claim due jobs; retrying after poll interval");
                Vec::new()
            }
        };

        if jobs.is_empty() {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(state.config.worker_poll_ms)) => {}
            }
            continue;
        }

        for job in jobs {
            handle_one(&client, &state, &job).await;
        }
    }
}

/// Deliver one claimed job and persist the outcome (delivered / rescheduled / dead).
async fn handle_one(client: &reqwest::Client, state: &AppState, job: &Job) {
    match deliver(client, job, &state.config).await {
        Ok(()) => {
            info!(id = %job.id, destination = %job.destination, attempts = job.attempts, "webhook delivered");
            if let Err(e) = state.db.mark_delivered(job.id).await {
                error!(id = %job.id, error = %e, "failed to mark job delivered");
            }
        }
        Err(e) => {
            if job.attempts >= job.max_attempts {
                error!(id = %job.id, attempts = job.attempts, error = %e, "job exhausted retries; moved to DLQ");
                if let Err(db_err) = state.db.mark_dead(job.id, &e.to_string()).await {
                    error!(id = %job.id, error = %db_err, "failed to mark job dead");
                }
            } else {
                let delay = backoff(
                    job.attempts,
                    state.config.base_delay_ms,
                    state.config.max_delay_ms,
                );
                let next_attempt_at = Utc::now()
                    + chrono::Duration::from_std(delay).unwrap_or_else(|_| {
                        chrono::Duration::milliseconds(state.config.max_delay_ms as i64)
                    });
                warn!(id = %job.id, attempt = job.attempts, error = %e, next_delay_ms = delay.as_millis() as u64, "delivery failed; retrying later");
                if let Err(db_err) = state
                    .db
                    .reschedule_job(job.id, next_attempt_at, &e.to_string())
                    .await
                {
                    error!(id = %job.id, error = %db_err, "failed to reschedule job");
                }
            }
        }
    }
}

/// Exponential backoff: `base_ms * 2^(attempts-1)`, capped at `max_ms`, with
/// ±20% jitter applied to the capped value.
fn backoff(attempts: i64, base_ms: u64, max_ms: u64) -> Duration {
    // Cap the shift so `base << shift` cannot overflow regardless of inputs.
    let shift = (attempts.max(1) as u32 - 1).min(20);
    let exp_ms = base_ms.saturating_mul(1u64 << shift);
    let capped_ms = exp_ms.min(max_ms);
    let jitter = fastrand::f64() * 0.4 - 0.2; // uniform in [-0.2, 0.2)
    let jittered_ms = (capped_ms as f64 * (1.0 + jitter)).max(0.0);
    Duration::from_millis(jittered_ms as u64)
}

/// Attempt one HTTP delivery of a claimed job.
///
/// POSTs the compact-serialized payload with `Content-Type: application/json`
/// plus the `X-Webhook-Id` and `X-Webhook-Signature` headers. Any 2xx status
/// counts as delivered; any other status is [`DeliveryError::Http`] and any
/// request-level failure (DNS, connect, timeout, ...) is
/// [`DeliveryError::Transport`].
async fn deliver(
    client: &reqwest::Client,
    job: &Job,
    config: &crate::config::Config,
) -> Result<(), DeliveryError> {
    let body = serde_json::to_vec(&job.payload)
        .map_err(|e| DeliveryError::Transport(format!("payload serialization failed: {e}")))?;
    let signature = security::sign_body(&config.hmac_secret, &body);

    let response = client
        .post(&job.destination)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("x-webhook-id", job.id.to_string())
        .header("x-webhook-signature", signature)
        .body(body)
        .send()
        .await
        .map_err(|e| DeliveryError::Transport(e.to_string()))?;

    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(DeliveryError::Http(status.as_u16()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With jitter removed the law is min(base * 2^(attempts-1), max); jitter
    /// keeps every sample within ±20% of that value. Sample heavily to make a
    /// flaky failure statistically impossible.
    #[test]
    fn backoff_grows_exponentially_and_respects_cap() {
        let (base, max) = (100u64, 10_000u64);
        for (attempts, expected_center_ms) in [(1, 100u64), (2, 200), (3, 400), (5, 1600)] {
            for _ in 0..500 {
                let d = backoff(attempts, base, max);
                let ms = d.as_millis() as u64;
                let pct_of_center = ((ms as f64 / expected_center_ms as f64) * 100.0) as u64;
                assert!(
                    (80..=120).contains(&pct_of_center),
                    "attempts={attempts}: {ms}ms not within ±20% of {expected_center_ms}ms"
                );
            }
        }
    }

    #[test]
    fn backoff_is_capped_at_max_with_jitter() {
        let (base, max) = (100u64, 300u64);
        for attempts in [4, 10, 63, i64::MAX] {
            for _ in 0..500 {
                let d = backoff(attempts, base, max);
                assert!(
                    d.as_millis() as u64 <= 360, // 300 * 1.2
                    "attempts={attempts}: {}ms exceeded cap+jitter",
                    d.as_millis()
                );
                // Floor: base delay can't shrink below 80% of the capped value.
                assert!(d.as_millis() as u64 >= 240, "attempts={attempts}");
            }
        }
    }

    #[test]
    fn backoff_never_overflows_for_extreme_inputs() {
        // Just must not panic / wrap: saturating math + capped shift.
        let d = backoff(i64::MAX, u64::MAX / 2, 60_000);
        assert!(d.as_millis() as u64 <= 72_000); // 60s cap + 20% jitter
        let d = backoff(0, 1000, 60_000); // attempts=0 treated as first attempt
        assert!(d.as_millis() as u64 <= 1200);
    }

    #[test]
    fn delivery_error_display_is_log_safe() {
        assert_eq!(
            DeliveryError::Http(500).to_string(),
            "destination returned HTTP status 500"
        );
        assert!(DeliveryError::Transport("boom".to_string())
            .to_string()
            .contains("boom"));
    }
}
