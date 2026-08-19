use chrono::Utc;
use sqlx::Row;

use crate::{deliver, models::ClaimedJob, AppState};

/// Background delivery loop. Every tick it:
///
/// 1. reclaims deliveries stuck in `processing` past the visibility timeout
///    (crash recovery, part of the at-least-once guarantee),
/// 2. atomically claims due `pending` deliveries,
/// 3. spawns a bounded task per claimed delivery.
pub async fn run(state: AppState) {
    loop {
        if let Err(e) = tick(&state).await {
            tracing::error!(error = %e, "worker tick failed");
        }
        tokio::time::sleep(std::time::Duration::from_millis(state.cfg.poll_interval_ms)).await;
    }
}

async fn tick(state: &AppState) -> Result<(), sqlx::Error> {
    let now = Utc::now().timestamp_millis();

    let stale_cutoff = now - state.cfg.visibility_timeout_secs * 1000;
    let reclaimed = sqlx::query(
        "UPDATE deliveries SET status = 'pending', updated_at = ?1
         WHERE status = 'processing' AND updated_at < ?2",
    )
    .bind(now)
    .bind(stale_cutoff)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if reclaimed > 0 {
        tracing::warn!(reclaimed, "reclaimed stale in-flight deliveries");
    }

    let rows = sqlx::query(
        r#"
        UPDATE deliveries SET status = 'processing', updated_at = ?1
        WHERE id IN (
            SELECT id FROM deliveries
            WHERE status = 'pending' AND next_attempt_at <= ?2
            ORDER BY next_attempt_at
            LIMIT ?3
        )
        RETURNING id, destination, payload, attempts, max_attempts
        "#,
    )
    .bind(now)
    .bind(now)
    .bind(state.cfg.batch_size)
    .fetch_all(&state.pool)
    .await?;

    for row in rows {
        let job = ClaimedJob {
            id: row.try_get("id")?,
            destination: row.try_get("destination")?,
            payload: row.try_get("payload")?,
            attempts: row.try_get("attempts")?,
            max_attempts: row.try_get("max_attempts")?,
        };
        let task_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = process_job(task_state, job).await {
                tracing::error!(error = %e, "failed to finalize delivery job");
            }
        });
    }

    Ok(())
}

async fn process_job(state: AppState, job: ClaimedJob) -> Result<(), sqlx::Error> {
    let _permit = state
        .sema
        .clone()
        .acquire_owned()
        .await
        .expect("delivery semaphore closed");

    let attempts = job.attempts + 1;
    let now = Utc::now().timestamp_millis();

    match deliver::deliver_once(&state.http, &state.cfg, &job).await {
        Ok(()) => {
            sqlx::query(
                "UPDATE deliveries
                 SET status = 'delivered', attempts = ?1, delivered_at = ?2,
                     updated_at = ?2, last_error = NULL
                 WHERE id = ?3",
            )
            .bind(attempts)
            .bind(now)
            .bind(&job.id)
            .execute(&state.pool)
            .await?;
            tracing::info!(id = %job.id, attempts, destination = %job.destination, "delivered");
        }
        Err(err) if attempts >= job.max_attempts => {
            sqlx::query(
                "UPDATE deliveries
                 SET status = 'dead_lettered', attempts = ?1, last_error = ?2,
                     updated_at = ?3, delivered_at = NULL
                 WHERE id = ?4",
            )
            .bind(attempts)
            .bind(&err)
            .bind(now)
            .bind(&job.id)
            .execute(&state.pool)
            .await?;
            tracing::warn!(id = %job.id, attempts, error = %err, "delivery dead-lettered");
        }
        Err(err) => {
            let delay = deliver::backoff_ms(&state.cfg, attempts);
            sqlx::query(
                "UPDATE deliveries
                 SET status = 'pending', attempts = ?1, last_error = ?2,
                     next_attempt_at = ?3, updated_at = ?4
                 WHERE id = ?5",
            )
            .bind(attempts)
            .bind(&err)
            .bind(now + delay)
            .bind(now)
            .bind(&job.id)
            .execute(&state.pool)
            .await?;
            tracing::info!(
                id = %job.id, attempts, retry_in_ms = delay, error = %err,
                "delivery failed, retry scheduled"
            );
        }
    }

    Ok(())
}
