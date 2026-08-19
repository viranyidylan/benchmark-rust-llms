//! Persistence layer: SQLite pool plus all job-queue queries.
//!
//! All timestamps are stored as RFC 3339 UTC strings (chrono), so lexical
//! ordering in SQLite matches chronological ordering. Payloads are stored as
//! compact JSON text.

use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteRow,
};
use sqlx::Row;
use uuid::Uuid;

use crate::config::Config;
use crate::models::{Job, JobStatus};

/// Column list shared by every query that materializes a [`Job`].
const JOB_COLUMNS: &str = "id, destination, payload, status, attempts, max_attempts, \
                           next_attempt_at, last_error, created_at, updated_at";

/// Shared database handle. Cheap to clone (the pool is reference-counted internally).
#[derive(Clone)]
pub struct Db(SqlitePool);

impl Db {
    /// Connect to the configured database, creating it if missing, and run migrations.
    pub async fn connect(config: &Config) -> anyhow::Result<Db> {
        let options = SqliteConnectOptions::from_str(&config.database_url)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Db(pool))
    }

    /// Connect to a fresh in-memory database (tests / local development).
    ///
    /// Uses a single pooled connection: with SQLite's `:memory:`, every pooled
    /// connection would otherwise see its own independent empty database.
    pub async fn connect_memory() -> anyhow::Result<Db> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Db(pool))
    }

    /// Persist a new job in `pending` state, due immediately.
    pub async fn insert_job(
        &self,
        id: Uuid,
        destination: &str,
        payload: &serde_json::Value,
        max_attempts: i64,
    ) -> anyhow::Result<()> {
        let now = rfc3339_now();
        let payload_text = serde_json::to_string(payload)?; // compact JSON
        sqlx::query(
            "INSERT INTO jobs (id, destination, payload, status, attempts, max_attempts, \
                               next_attempt_at, last_error, created_at, updated_at) \
             VALUES (?, ?, ?, 'pending', 0, ?, ?, NULL, ?, ?)",
        )
        .bind(id.to_string())
        .bind(destination)
        .bind(payload_text)
        .bind(max_attempts)
        .bind(now.as_str())
        .bind(now.as_str())
        .bind(now.as_str())
        .execute(&self.0)
        .await?;
        Ok(())
    }

    /// Atomically claim up to `limit` due pending jobs.
    ///
    /// Runs inside a `BEGIN IMMEDIATE` transaction so concurrent workers cannot
    /// claim the same rows: due rows are selected oldest-due-first, then each is
    /// flipped to `in_flight` with `attempts` incremented before the commit.
    pub async fn claim_due_jobs(&self, limit: i64) -> anyhow::Result<Vec<Job>> {
        let now = rfc3339_now();
        let mut tx = self.0.begin_with("BEGIN IMMEDIATE").await?;

        let rows = sqlx::query(
            "SELECT id FROM jobs \
             WHERE status = 'pending' AND next_attempt_at <= ? \
             ORDER BY next_attempt_at LIMIT ?",
        )
        .bind(now.as_str())
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;

        let update_sql = format!(
            "UPDATE jobs \
             SET status = 'in_flight', attempts = attempts + 1, updated_at = ? \
             WHERE id = ? RETURNING {JOB_COLUMNS}"
        );
        let mut jobs = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: &str = row.try_get("id")?;
            let updated = sqlx::query(&update_sql)
                .bind(now.as_str())
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
            jobs.push(row_to_job(&updated)?);
        }

        tx.commit().await?;
        Ok(jobs)
    }

    /// Mark a job as successfully delivered; clears any stored error.
    pub async fn mark_delivered(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE jobs SET status = 'delivered', last_error = NULL, updated_at = ? \
             WHERE id = ?",
        )
        .bind(rfc3339_now())
        .bind(id.to_string())
        .execute(&self.0)
        .await?;
        Ok(())
    }

    /// Put a job back into `pending` for a later attempt, recording the error.
    pub async fn reschedule_job(
        &self,
        id: Uuid,
        next_attempt_at: DateTime<Utc>,
        error: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE jobs \
             SET status = 'pending', next_attempt_at = ?, last_error = ?, updated_at = ? \
             WHERE id = ?",
        )
        .bind(fmt_ts(next_attempt_at))
        .bind(error)
        .bind(rfc3339_now())
        .bind(id.to_string())
        .execute(&self.0)
        .await?;
        Ok(())
    }

    /// Move a job to the dead-letter queue after its final failed attempt.
    pub async fn mark_dead(&self, id: Uuid, error: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE jobs SET status = 'dead', last_error = ?, updated_at = ? WHERE id = ?")
            .bind(error)
            .bind(rfc3339_now())
            .bind(id.to_string())
            .execute(&self.0)
            .await?;
        Ok(())
    }

    /// List dead-lettered jobs, most recently updated first.
    pub async fn list_dead(&self, limit: i64) -> anyhow::Result<Vec<Job>> {
        let sql = format!(
            "SELECT {JOB_COLUMNS} FROM jobs \
             WHERE status = 'dead' ORDER BY updated_at DESC LIMIT ?"
        );
        let rows = sqlx::query(&sql).bind(limit).fetch_all(&self.0).await?;
        rows.iter().map(row_to_job).collect()
    }

    /// Move a dead job back to `pending` (attempts reset, due immediately).
    /// Returns `false` if no dead job with that id exists.
    pub async fn requeue_dead(&self, id: Uuid) -> anyhow::Result<bool> {
        let now = rfc3339_now();
        let result = sqlx::query(
            "UPDATE jobs \
             SET status = 'pending', attempts = 0, next_attempt_at = ?, last_error = NULL, \
                 updated_at = ? \
             WHERE id = ? AND status = 'dead'",
        )
        .bind(now.as_str())
        .bind(now.as_str())
        .bind(id.to_string())
        .execute(&self.0)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

/// Current UTC time as an RFC 3339 string.
fn rfc3339_now() -> String {
    fmt_ts(Utc::now())
}

/// Format a timestamp as RFC 3339 with millisecond precision and a `Z` suffix,
/// so stored strings compare correctly both lexically and chronologically.
fn fmt_ts(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parse a stored RFC 3339 timestamp back into a UTC `DateTime`.
fn parse_ts(s: &str) -> anyhow::Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
}

/// Map a row containing [`JOB_COLUMNS`] to a [`Job`], parsing the payload JSON,
/// timestamps, and status.
fn row_to_job(row: &SqliteRow) -> anyhow::Result<Job> {
    let id: &str = row.try_get("id")?;
    let payload: &str = row.try_get("payload")?;
    let status: &str = row.try_get("status")?;
    let next_attempt_at: &str = row.try_get("next_attempt_at")?;
    let created_at: &str = row.try_get("created_at")?;
    let updated_at: &str = row.try_get("updated_at")?;
    Ok(Job {
        id: Uuid::parse_str(id)?,
        destination: row.try_get("destination")?,
        payload: serde_json::from_str(payload)?,
        status: JobStatus::from_str(status)?,
        attempts: row.try_get("attempts")?,
        max_attempts: row.try_get("max_attempts")?,
        next_attempt_at: parse_ts(next_attempt_at)?,
        last_error: row.try_get("last_error")?,
        created_at: parse_ts(created_at)?,
        updated_at: parse_ts(updated_at)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn test_db() -> Db {
        Db::connect_memory().await.expect("connect in-memory db")
    }

    #[tokio::test]
    async fn insert_then_claim_marks_in_flight_and_increments_attempts() {
        let db = test_db().await;
        let id = Uuid::new_v4();
        let payload = json!({"hello": "world", "n": 42});
        db.insert_job(id, "https://example.com/hook", &payload, 8)
            .await
            .unwrap();

        let claimed = db.claim_due_jobs(10).await.unwrap();
        assert_eq!(claimed.len(), 1);
        let job = &claimed[0];
        assert_eq!(job.id, id);
        assert_eq!(job.destination, "https://example.com/hook");
        assert_eq!(job.payload, payload);
        assert_eq!(job.status, JobStatus::InFlight);
        assert_eq!(job.attempts, 1);
        assert_eq!(job.max_attempts, 8);
        assert!(job.last_error.is_none());
        assert!(job.created_at <= job.updated_at);
        assert!(job.next_attempt_at <= Utc::now());

        // The payload must be stored as compact JSON text.
        let raw: String = sqlx::query_scalar("SELECT payload FROM jobs WHERE id = ?")
            .bind(id.to_string())
            .fetch_one(&db.0)
            .await
            .unwrap();
        assert_eq!(raw, serde_json::to_string(&payload).unwrap());

        // A second claim must not return the now in-flight job.
        let again = db.claim_due_jobs(10).await.unwrap();
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn claim_respects_limit_and_due_order() {
        let db = test_db().await;
        for _ in 0..3 {
            db.insert_job(
                Uuid::new_v4(),
                "https://example.com/hook",
                &json!({"a": 1}),
                8,
            )
            .await
            .unwrap();
        }
        let first = db.claim_due_jobs(2).await.unwrap();
        assert_eq!(first.len(), 2);
        let second = db.claim_due_jobs(2).await.unwrap();
        assert_eq!(second.len(), 1);
    }

    #[tokio::test]
    async fn delivered_job_is_gone_from_queue_and_dlq() {
        let db = test_db().await;
        let id = Uuid::new_v4();
        db.insert_job(id, "https://example.com/hook", &json!({"a": 1}), 8)
            .await
            .unwrap();
        db.claim_due_jobs(10).await.unwrap();
        db.mark_delivered(id).await.unwrap();

        assert!(db.claim_due_jobs(10).await.unwrap().is_empty());
        assert!(db.list_dead(10).await.unwrap().is_empty());
        assert!(!db.requeue_dead(id).await.unwrap());
    }

    #[tokio::test]
    async fn reschedule_controls_visibility() {
        let db = test_db().await;
        let id = Uuid::new_v4();
        db.insert_job(id, "https://example.com/hook", &json!({"a": 1}), 8)
            .await
            .unwrap();
        assert_eq!(db.claim_due_jobs(10).await.unwrap().len(), 1);

        // Rescheduled into the future: not due yet, must not be claimed.
        let future = Utc::now() + chrono::Duration::hours(1);
        db.reschedule_job(id, future, "boom").await.unwrap();
        assert!(db.claim_due_jobs(10).await.unwrap().is_empty());

        // Rescheduled into the past: due, claimed again with the error kept.
        let past = Utc::now() - chrono::Duration::hours(1);
        db.reschedule_job(id, past, "boom").await.unwrap();
        let claimed = db.claim_due_jobs(10).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id, id);
        assert_eq!(claimed[0].status, JobStatus::InFlight);
        assert_eq!(claimed[0].attempts, 2);
        assert_eq!(claimed[0].last_error.as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn dead_list_and_requeue_roundtrip() {
        let db = test_db().await;
        let id = Uuid::new_v4();
        db.insert_job(id, "https://example.com/hook", &json!({"x": 1}), 8)
            .await
            .unwrap();
        db.claim_due_jobs(10).await.unwrap();
        db.mark_dead(id, "gave up").await.unwrap();

        let dead = db.list_dead(10).await.unwrap();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].id, id);
        assert_eq!(dead[0].status, JobStatus::Dead);
        assert_eq!(dead[0].last_error.as_deref(), Some("gave up"));
        assert_eq!(dead[0].attempts, 1);

        // Requeue: pending again, attempts reset, error cleared.
        assert!(db.requeue_dead(id).await.unwrap());
        assert!(db.list_dead(10).await.unwrap().is_empty());

        // Requeueing a non-dead job reports false.
        assert!(!db.requeue_dead(id).await.unwrap());

        // The requeued job is immediately claimable, counting from zero again.
        let claimed = db.claim_due_jobs(10).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id, id);
        assert_eq!(claimed[0].attempts, 1);
        assert!(claimed[0].last_error.is_none());

        // Still false for a job that is now in flight.
        assert!(!db.requeue_dead(id).await.unwrap());
    }
}
