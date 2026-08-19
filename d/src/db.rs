use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use uuid::Uuid;

use crate::models::{DeliveryStatus, DqlEntry, WebhookJob};

/// Thread-safe handle to the SQLite store. `rusqlite::Connection` is not Sync,
/// so we wrap it in an `Arc<Mutex<...>>`. For a low-throughput queue this is
/// perfectly fine.
#[derive(Debug, Clone)]
pub struct Db {
    conn: std::sync::Arc<std::sync::Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self {
            conn: std::sync::Arc::new(std::sync::Mutex::new(conn)),
        };
        db.init()?;
        Ok(db)
    }

    #[allow(dead_code)]
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: std::sync::Arc::new(std::sync::Mutex::new(conn)),
        };
        db.init()?;
        Ok(db)
    }

    fn init(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                destination TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL,
                next_attempt_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dead_letters (
                id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                destination TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                last_error TEXT NOT NULL,
                moved_at TEXT NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    /// Insert a new job into the queue.
    pub fn enqueue(&self, job: &WebhookJob) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO jobs (id, payload, destination, attempts, max_attempts, next_attempt_at, created_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                job.id.to_string(),
                job.payload.to_string(),
                job.destination,
                job.attempts,
                job.max_attempts,
                job.next_attempt_at.to_rfc3339(),
                job.created_at.to_rfc3339(),
                status_str(job.status),
            ],
        )?;
        Ok(())
    }

    /// Fetch jobs that are due (next_attempt_at <= now) and still pending,
    /// limited to `limit` rows.
    pub fn fetch_due(&self, now: DateTime<Utc>, limit: i64) -> rusqlite::Result<Vec<WebhookJob>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, payload, destination, attempts, max_attempts, next_attempt_at, created_at, status
             FROM jobs WHERE status='Pending' AND next_attempt_at <= ?1 ORDER BY next_attempt_at LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![now.to_rfc3339(), limit], row_to_job)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Mark an attempt as having been made: bump attempts, possibly set status.
    pub fn record_attempt(&self, id: &Uuid, attempts: u32, next_retry_at: Option<DateTime<Utc>>) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let attempts = attempts as i64;
        match next_retry_at {
            Some(t) => conn.execute(
                "UPDATE jobs SET attempts=?2, next_attempt_at=?3 WHERE id=?1",
                params![id.to_string(), attempts, t.to_rfc3339()],
            )?,
            None => conn.execute(
                "UPDATE jobs SET attempts=?2 WHERE id=?1",
                params![id.to_string(), attempts],
            )?,
        };
        Ok(())
    }

    /// Mark a job as delivered (terminal good state).
    pub fn mark_delivered(&self, id: &Uuid) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE jobs SET status='Delivered' WHERE id=?1",
            params![id.to_string()],
        )?;
        Ok(())
    }

    /// Move a job to the dead letter queue and remove it from the active queue.
    pub fn move_to_dlq(&self, job: &WebhookJob, error: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let entry_id = Uuid::new_v4();
        conn.execute(
            "INSERT INTO dead_letters (id, job_id, payload, destination, attempts, last_error, moved_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry_id.to_string(),
                job.id.to_string(),
                job.payload.to_string(),
                job.destination,
                job.attempts as i64,
                error,
                Utc::now().to_rfc3339(),
            ],
        )?;
        conn.execute(
            "DELETE FROM jobs WHERE id=?1",
            params![job.id.to_string()],
        )?;
        Ok(())
    }

    /// List all dead-letter entries, most recent first.
    pub fn list_dlq(&self) -> rusqlite::Result<Vec<DqlEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, job_id, payload, destination, attempts, last_error, moved_at
             FROM dead_letters ORDER BY moved_at DESC",
        )?;
        let rows = stmt
            .query_map([], row_to_dlq)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Get a single dead-letter entry by its entry id.
    pub fn get_dlq(&self, entry_id: &Uuid) -> rusqlite::Result<Option<DqlEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, job_id, payload, destination, attempts, last_error, moved_at
             FROM dead_letters WHERE id=?1",
        )?;
        let row = stmt
            .query_row(params![entry_id.to_string()], row_to_dlq)
            .optional()?;
        Ok(row)
    }

    /// Re-enqueue a dead-letter entry as a brand new job, and delete the DLQ entry.
    /// Preserves the original payload, destination, and max_attempts (fresh attempts).
    pub fn redeliver(&self, entry_id: &Uuid, max_attempts: u32) -> rusqlite::Result<Option<WebhookJob>> {
        let entry = match self.get_dlq(entry_id)? {
            Some(e) => e,
            None => return Ok(None),
        };
        let now = Utc::now();
        let job = WebhookJob {
            id: Uuid::new_v4(),
            payload: entry.payload,
            destination: entry.destination,
            attempts: 0,
            max_attempts,
            next_attempt_at: now,
            created_at: now,
            status: DeliveryStatus::Pending,
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO jobs (id, payload, destination, attempts, max_attempts, next_attempt_at, created_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                job.id.to_string(),
                job.payload.to_string(),
                job.destination,
                job.attempts,
                job.max_attempts,
                job.next_attempt_at.to_rfc3339(),
                job.created_at.to_rfc3339(),
                status_str(job.status),
            ],
        )?;
        conn.execute(
            "DELETE FROM dead_letters WHERE id=?1",
            params![entry_id.to_string()],
        )?;
        Ok(Some(job))
    }

    /// Count active Pending jobs (useful for health checks / tests).
    #[allow(dead_code)]
    pub fn pending_count(&self) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM jobs WHERE status='Pending'",
            [],
            |r| r.get(0),
        )
    }
}

fn row_to_job(row: &rusqlite::Row) -> rusqlite::Result<WebhookJob> {
    let id: String = row.get(0)?;
    let payload: String = row.get(1)?;
    let destination: String = row.get(2)?;
    let attempts: i64 = row.get(3)?;
    let max_attempts: i64 = row.get(4)?;
    let next_attempt_at: String = row.get(5)?;
    let created_at: String = row.get(6)?;
    let status: String = row.get(7)?;
    Ok(WebhookJob {
        id: Uuid::parse_str(&id).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?,
        payload: serde_json::from_str(&payload).map_err(|e| rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e)))?,
        destination,
        attempts: attempts as u32,
        max_attempts: max_attempts as u32,
        next_attempt_at: DateTime::parse_from_rfc3339(&next_attempt_at).map(|d| d.with_timezone(&Utc)).map_err(|e| rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e)))?,
        created_at: DateTime::parse_from_rfc3339(&created_at).map(|d| d.with_timezone(&Utc)).map_err(|e| rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e)))?,
        status: parse_status(&status),
    })
}

fn row_to_dlq(row: &rusqlite::Row) -> rusqlite::Result<DqlEntry> {
    let id: String = row.get(0)?;
    let job_id: String = row.get(1)?;
    let payload: String = row.get(2)?;
    let destination: String = row.get(3)?;
    let attempts: i64 = row.get(4)?;
    let last_error: String = row.get(5)?;
    let moved_at: String = row.get(6)?;
    Ok(DqlEntry {
        id: Uuid::parse_str(&id).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?,
        job_id: Uuid::parse_str(&job_id).map_err(|e| rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e)))?,
        payload: serde_json::from_str(&payload).map_err(|e| rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e)))?,
        destination,
        attempts: attempts as u32,
        last_error,
        moved_at: DateTime::parse_from_rfc3339(&moved_at).map(|d| d.with_timezone(&Utc)).map_err(|e| rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e)))?,
    })
}

fn status_str(s: DeliveryStatus) -> &'static str {
    match s {
        DeliveryStatus::Pending => "Pending",
        DeliveryStatus::Delivered => "Delivered",
        DeliveryStatus::Dead => "Dead",
    }
}

fn parse_status(s: &str) -> DeliveryStatus {
    match s {
        "Delivered" => DeliveryStatus::Delivered,
        "Dead" => DeliveryStatus::Dead,
        _ => DeliveryStatus::Pending,
    }
}
