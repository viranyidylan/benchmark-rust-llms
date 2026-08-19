use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult, Row};
use uuid::Uuid;

use crate::model::{now_ms, Delivery, DeliveryStatus, DlqEntry, NewDelivery, Stats};

/// Schema from PLAN.md §5.
const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS deliveries (
  id              TEXT PRIMARY KEY,
  idempotency_key TEXT UNIQUE,
  destination     TEXT NOT NULL,
  payload         BLOB NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending',
  attempts        INTEGER NOT NULL DEFAULT 0,
  max_attempts    INTEGER NOT NULL DEFAULT 8,
  next_retry_at   INTEGER NOT NULL,
  last_error      TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries_poll ON deliveries (status, next_retry_at);

CREATE TABLE IF NOT EXISTS dead_letters (
  id               TEXT PRIMARY KEY,
  delivery_id      TEXT NOT NULL,
  destination      TEXT NOT NULL,
  payload          BLOB NOT NULL,
  attempts         INTEGER NOT NULL,
  last_error       TEXT,
  dead_lettered_at INTEGER NOT NULL
);
"#;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("idempotency key conflict with existing delivery {0}")]
    IdempotencyConflict(Uuid),
}

pub type DbResult<T> = Result<T, DbError>;

/// SQLite-backed delivery queue.
///
/// A single [`Connection`] behind a [`Mutex`]; all operations are synchronous.
/// Callers in async code should run these via `tokio::task::spawn_blocking`
/// (PLAN.md §5). `Db` is `Send + Sync` so it can be shared by the worker pool.
pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    /// Open (or create) the database at `path` (`:memory:` supported) and run migrations.
    pub fn new(path: &str) -> DbResult<Self> {
        if path != ":memory:" {
            if let Some(parent) = std::path::Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(DDL)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Insert a new pending delivery (`next_retry_at` = now).
    /// Returns [`DbError::IdempotencyConflict`] with the existing id on a
    /// unique `idempotency_key` hit.
    pub fn insert(&self, d: &NewDelivery) -> DbResult<()> {
        let now = now_ms();
        let conn = self.lock();
        match conn.execute(
            "INSERT INTO deliveries
               (id, idempotency_key, destination, payload, status, attempts, max_attempts,
                next_retry_at, last_error, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'pending', 0, ?5, ?6, NULL, ?6, ?6)",
            params![
                d.id.to_string(),
                d.idempotency_key,
                d.destination,
                d.payload,
                d.max_attempts,
                now
            ],
        ) {
            Ok(_) => Ok(()),
            Err(e) if is_constraint_error(&e) => {
                // SQLite UNIQUE allows multiple NULLs, so a constraint hit here
                // means a non-NULL idempotency_key collision (or a PK collision).
                let existing: Option<String> = conn
                    .query_row(
                        "SELECT id FROM deliveries WHERE idempotency_key = ?1",
                        params![d.idempotency_key],
                        |r| r.get::<_, String>(0),
                    )
                    .optional()?;
                match existing {
                    Some(id) => Err(DbError::IdempotencyConflict(parse_uuid(&id)?)),
                    None => Err(DbError::Sqlite(e)),
                }
            }
            Err(e) => Err(DbError::Sqlite(e)),
        }
    }

    /// Fetch one delivery by id.
    pub fn find(&self, id: &Uuid) -> DbResult<Option<Delivery>> {
        let conn = self.lock();
        let row: Option<Delivery> = conn
            .query_row(
                "SELECT id, idempotency_key, destination, payload, status, attempts,
                        max_attempts, next_retry_at, last_error, created_at, updated_at
                 FROM deliveries WHERE id = ?1",
                params![id.to_string()],
                map_delivery,
            )
            .optional()?;
        Ok(row)
    }

    /// Pending deliveries due for delivery at or before `now_ms`, oldest first.
    pub fn list_due(&self, now_ms: i64, limit: usize) -> DbResult<Vec<Delivery>> {
        let conn = self.lock();
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = conn.prepare(
            "SELECT id, idempotency_key, destination, payload, status, attempts,
                    max_attempts, next_retry_at, last_error, created_at, updated_at
             FROM deliveries
             WHERE status = 'pending' AND next_retry_at <= ?1
             ORDER BY next_retry_at ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now_ms, limit], map_delivery)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Atomically claim a pending delivery (pending → in_flight).
    /// Returns `true` iff this caller won the claim.
    pub fn claim(&self, id: &Uuid) -> DbResult<bool> {
        let now = now_ms();
        let n = self.lock().execute(
            "UPDATE deliveries SET status = 'in_flight', updated_at = ?2
             WHERE id = ?1 AND status = 'pending'",
            params![id.to_string(), now],
        )?;
        Ok(n == 1)
    }

    /// Mark a delivery as delivered after a 2xx response.
    ///
    /// `attempts` counts sends actually made (PLAN.md, T7 verification:
    /// `200` ⇒ delivered with `attempts = 1`), so the final successful send
    /// is counted here; failed sends are counted by [`Db::schedule_retry`].
    pub fn mark_delivered(&self, id: &Uuid) -> DbResult<()> {
        let now = now_ms();
        self.lock().execute(
            "UPDATE deliveries
             SET status = 'delivered', attempts = attempts + 1, last_error = NULL, updated_at = ?2
             WHERE id = ?1",
            params![id.to_string(), now],
        )?;
        Ok(())
    }

    /// Bump `attempts` by one and reschedule the delivery as pending at `next_ms`.
    pub fn schedule_retry(&self, id: &Uuid, next_ms: i64, err: &str) -> DbResult<()> {
        let now = now_ms();
        self.lock().execute(
            "UPDATE deliveries
             SET status = 'pending', attempts = attempts + 1, next_retry_at = ?2,
                 last_error = ?3, updated_at = ?4
             WHERE id = ?1",
            params![id.to_string(), next_ms, err, now],
        )?;
        Ok(())
    }

    /// Move a delivery to the dead-letter queue.
    /// Returns the new DLQ entry, or `None` if the delivery does not exist.
    pub fn dead_letter(&self, id: &Uuid, err: &str) -> DbResult<Option<DlqEntry>> {
        let now = now_ms();
        let conn = self.lock();
        let (destination, payload, attempts): (String, Vec<u8>, i32) = match conn
            .query_row(
                "SELECT destination, payload, attempts FROM deliveries WHERE id = ?1",
                params![id.to_string()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i32>(2)?,
                    ))
                },
            )
            .optional()?
        {
            Some(row) => row,
            None => return Ok(None),
        };
        let entry_id = Uuid::new_v4();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE deliveries SET status = 'dead_letter', last_error = ?2, updated_at = ?3
             WHERE id = ?1",
            params![id.to_string(), err, now],
        )?;
        tx.execute(
            "INSERT INTO dead_letters
               (id, delivery_id, destination, payload, attempts, last_error, dead_lettered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry_id.to_string(),
                id.to_string(),
                destination,
                payload,
                attempts,
                err,
                now
            ],
        )?;
        tx.commit()?;
        Ok(Some(DlqEntry {
            id: entry_id,
            delivery_id: id.to_string(),
            destination,
            payload,
            attempts: u32::try_from(attempts).unwrap_or(u32::MAX),
            last_error: Some(err.to_string()),
            dead_lettered_at: now,
        }))
    }

    /// List dead-letter entries, oldest first.
    pub fn list_dead_letters(&self, limit: usize, offset: usize) -> DbResult<Vec<DlqEntry>> {
        let conn = self.lock();
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let offset = i64::try_from(offset).unwrap_or(0);
        let mut stmt = conn.prepare(
            "SELECT id, delivery_id, destination, payload, attempts, last_error, dead_lettered_at
             FROM dead_letters
             ORDER BY dead_lettered_at ASC, id ASC
             LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit, offset], |r| {
            Ok(DlqEntry {
                id: parse_uuid(&r.get::<_, String>(0)?)?,
                delivery_id: r.get::<_, String>(1)?,
                destination: r.get::<_, String>(2)?,
                payload: r.get::<_, Vec<u8>>(3)?,
                attempts: u32::try_from(r.get::<_, i32>(4)?).unwrap_or(u32::MAX),
                last_error: r.get::<_, Option<String>>(5)?,
                dead_lettered_at: r.get::<_, i64>(6)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Look up a dead-letter entry by its DLQ entry id.
    pub fn find_dlq_entry(&self, id: &Uuid) -> DbResult<Option<DlqEntry>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT id, delivery_id, destination, payload, attempts, last_error, dead_lettered_at
             FROM dead_letters WHERE id = ?1",
            params![id.to_string()],
            |r| {
                Ok(DlqEntry {
                    id: parse_uuid(&r.get::<_, String>(0)?)?,
                    delivery_id: r.get::<_, String>(1)?,
                    destination: r.get::<_, String>(2)?,
                    payload: r.get::<_, Vec<u8>>(3)?,
                    attempts: u32::try_from(r.get::<_, i32>(4)?).unwrap_or(u32::MAX),
                    last_error: r.get::<_, Option<String>>(5)?,
                    dead_lettered_at: r.get::<_, i64>(6)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    /// Requeue a dead-lettered delivery (pending, attempts = 0, due now).
    /// The DLQ row is kept for audit. Returns `true` iff the row was dead-lettered.
    pub fn replay_dead_letter(&self, delivery_id: &Uuid) -> DbResult<bool> {
        let now = now_ms();
        let n = self.lock().execute(
            "UPDATE deliveries
             SET status = 'pending', attempts = 0, next_retry_at = ?2,
                 last_error = NULL, updated_at = ?2
             WHERE id = ?1 AND status = 'dead_letter'",
            params![delivery_id.to_string(), now],
        )?;
        Ok(n == 1)
    }

    /// Crash recovery: reset in-flight rows whose `updated_at` is older than
    /// `stale_ms` back to pending (due immediately). Returns rows touched.
    pub fn reset_stale_in_flight(&self, now_ms: i64, stale_ms: i64) -> DbResult<usize> {
        Ok(self.lock().execute(
            "UPDATE deliveries
             SET status = 'pending', next_retry_at = ?1, updated_at = ?1
             WHERE status = 'in_flight' AND updated_at <= ?1 - ?2",
            params![now_ms, stale_ms],
        )?)
    }

    /// Test helper: force a row to a stale in_flight state (simulates a crash
    /// mid-delivery). Exposed (not `#[cfg(test)]`) so the integration tests
    /// in `tests/` can stage crash-recovery scenarios.
    pub fn set_in_flight_stale_for_test(&self, id: &Uuid, updated_at: i64) -> DbResult<()> {
        self.lock().execute(
            "UPDATE deliveries SET status = 'in_flight', updated_at = ?2, attempts = 1
             WHERE id = ?1",
            params![id.to_string(), updated_at],
        )?;
        Ok(())
    }

    /// Queue counters (PLAN.md §5).
    pub fn stats(&self) -> DbResult<Stats> {
        let conn = self.lock();
        let submitted: i64 =
            conn.query_row("SELECT COUNT(*) FROM deliveries", params![], |r| r.get(0))?;
        let delivered: i64 = conn.query_row(
            "SELECT COUNT(*) FROM deliveries WHERE status = 'delivered'",
            params![],
            |r| r.get(0),
        )?;
        let dead_lettered: i64 = conn.query_row(
            "SELECT COUNT(*) FROM deliveries WHERE status = 'dead_letter'",
            params![],
            |r| r.get(0),
        )?;
        let pending: i64 = conn.query_row(
            "SELECT COUNT(*) FROM deliveries WHERE status = 'pending'",
            params![],
            |r| r.get(0),
        )?;
        let in_flight: i64 = conn.query_row(
            "SELECT COUNT(*) FROM deliveries WHERE status = 'in_flight'",
            params![],
            |r| r.get(0),
        )?;
        let dead_letters: i64 =
            conn.query_row("SELECT COUNT(*) FROM dead_letters", params![], |r| r.get(0))?;
        Ok(Stats {
            submitted: u64::try_from(submitted).unwrap_or(u64::MAX),
            delivered: u64::try_from(delivered).unwrap_or(u64::MAX),
            dead_lettered: u64::try_from(dead_lettered).unwrap_or(u64::MAX),
            pending: u64::try_from(pending).unwrap_or(u64::MAX),
            in_flight: u64::try_from(in_flight).unwrap_or(u64::MAX),
            dead_letters: u64::try_from(dead_letters).unwrap_or(u64::MAX),
        })
    }

    /// Cheap liveness check for `/readyz`.
    pub fn ping(&self) -> bool {
        self.lock().execute_batch("SELECT 1").is_ok()
    }
}

/// Marker error for column values that fail to convert to the expected Rust type.
#[derive(Debug)]
struct BadRowValue(String);

impl std::fmt::Display for BadRowValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BadRowValue {}

fn conversion_error(idx: usize, msg: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        idx,
        rusqlite::types::Type::Text,
        Box::new(BadRowValue(msg)),
    )
}

/// rusqlite 0.32 has no `Error::is_constraint_error`; check the failure code.
fn is_constraint_error(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(code, _)
            if code.code == rusqlite::ffi::ErrorCode::ConstraintViolation
    )
}

fn parse_uuid(s: &str) -> SqliteResult<Uuid> {
    Uuid::parse_str(s).map_err(|e| conversion_error(0, format!("invalid uuid in db: {e}")))
}

fn map_delivery(r: &Row<'_>) -> SqliteResult<Delivery> {
    let status = r.get::<_, String>(4)?;
    let status = DeliveryStatus::parse(&status)
        .ok_or_else(|| conversion_error(4, format!("unknown status '{status}'")))?;
    Ok(Delivery {
        id: parse_uuid(&r.get::<_, String>(0)?)?,
        idempotency_key: r.get::<_, Option<String>>(1)?,
        destination: r.get::<_, String>(2)?,
        payload: r.get::<_, Vec<u8>>(3)?,
        status,
        attempts: u32::try_from(r.get::<_, i32>(5)?).unwrap_or(u32::MAX),
        max_attempts: u32::try_from(r.get::<_, i32>(6)?).unwrap_or(u32::MAX),
        next_retry_at: r.get::<_, i64>(7)?,
        last_error: r.get::<_, Option<String>>(8)?,
        created_at: r.get::<_, i64>(9)?,
        updated_at: r.get::<_, i64>(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Db {
        Db::new(":memory:").unwrap()
    }

    fn new_delivery(key: Option<&str>) -> NewDelivery {
        NewDelivery {
            id: Uuid::new_v4(),
            idempotency_key: key.map(str::to_string),
            destination: "http://example.com/hook".to_string(),
            payload: br#"{"hello":"world"}"#.to_vec(),
            max_attempts: 8,
        }
    }

    #[test]
    fn insert_list_due_claim() {
        let db = test_db();
        let d = new_delivery(None);
        let id = d.id;
        db.insert(&d).unwrap();

        let now = now_ms();
        let due = db.list_due(now, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert_eq!(due[0].status, DeliveryStatus::Pending);
        assert_eq!(due[0].payload, br#"{"hello":"world"}"#);

        assert!(db.claim(&id).unwrap());
        // Second claim loses: row is no longer pending.
        assert!(!db.claim(&id).unwrap());

        // Claimed rows are no longer due.
        assert!(db.list_due(now, 10).unwrap().is_empty());

        let d2 = db.find(&id).unwrap().unwrap();
        assert_eq!(d2.status, DeliveryStatus::InFlight);
        assert_eq!(d2.attempts, 0);
    }

    #[test]
    fn schedule_retry_moves_out_of_due_until_time_passes() {
        let db = test_db();
        let d = new_delivery(None);
        let id = d.id;
        db.insert(&d).unwrap();

        let now = now_ms();
        db.schedule_retry(&id, now + 1001, "boom").unwrap();

        let d2 = db.find(&id).unwrap().unwrap();
        assert_eq!(d2.attempts, 1);
        assert_eq!(d2.status, DeliveryStatus::Pending);
        assert_eq!(d2.last_error.as_deref(), Some("boom"));
        assert_eq!(d2.next_retry_at, now + 1001);

        // Not due before the retry time.
        assert!(db.list_due(now + 500, 10).unwrap().is_empty());
        // Due once the retry time arrives.
        let due = db.list_due(now + 1001, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
    }

    #[test]
    fn mark_delivered() {
        let db = test_db();
        let d = new_delivery(None);
        let id = d.id;
        db.insert(&d).unwrap();
        db.claim(&id).unwrap();
        db.mark_delivered(&id).unwrap();

        let d2 = db.find(&id).unwrap().unwrap();
        assert_eq!(d2.status, DeliveryStatus::Delivered);
        assert_eq!(d2.last_error, None);
    }

    #[test]
    fn dead_letter_list_replay() {
        let db = test_db();
        let d = new_delivery(None);
        let id = d.id;
        db.insert(&d).unwrap();

        let entry = db.dead_letter(&id, "gave up").unwrap().unwrap();
        assert_eq!(entry.delivery_id, id.to_string());
        assert_eq!(entry.attempts, 0);
        assert_eq!(entry.last_error.as_deref(), Some("gave up"));

        let d2 = db.find(&id).unwrap().unwrap();
        assert_eq!(d2.status, DeliveryStatus::DeadLetter);
        assert_eq!(d2.last_error.as_deref(), Some("gave up"));

        let list = db.list_dead_letters(10, 0).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, entry.id);
        assert_eq!(list[0].delivery_id, id.to_string());
        assert_eq!(list[0].payload, br#"{"hello":"world"}"#);

        // Replay works once (row becomes pending); a second replay is a no-op.
        assert!(db.replay_dead_letter(&id).unwrap());
        assert!(!db.replay_dead_letter(&id).unwrap());
        let d3 = db.find(&id).unwrap().unwrap();
        assert_eq!(d3.status, DeliveryStatus::Pending);
        assert_eq!(d3.attempts, 0);
        assert_eq!(d3.last_error, None);
        // DLQ row kept for audit.
        assert_eq!(db.list_dead_letters(10, 0).unwrap().len(), 1);

        // Dead-lettering a missing row yields None.
        let missing = Uuid::new_v4();
        assert!(db.dead_letter(&missing, "x").unwrap().is_none());
    }

    #[test]
    fn idempotency_conflict_returns_existing_id() {
        let db = test_db();
        let d1 = new_delivery(Some("key-1"));
        let id1 = d1.id;
        db.insert(&d1).unwrap();

        let d2 = new_delivery(Some("key-1"));
        match db.insert(&d2).unwrap_err() {
            DbError::IdempotencyConflict(existing) => assert_eq!(existing, id1),
            other => panic!("expected IdempotencyConflict, got {other:?}"),
        }

        // NULL idempotency keys never conflict.
        let n1 = new_delivery(None);
        let n2 = new_delivery(None);
        db.insert(&n1).unwrap();
        db.insert(&n2).unwrap();
    }

    #[test]
    fn reset_stale_in_flight_only_touches_old_rows() {
        let db = test_db();
        let d_old = new_delivery(None);
        let d_fresh = new_delivery(None);
        db.insert(&d_old).unwrap();
        db.insert(&d_fresh).unwrap();
        db.claim(&d_old.id).unwrap();
        db.claim(&d_fresh.id).unwrap();

        let now = now_ms();
        // Age the first row 10 minutes back (same-module test may use the
        // private lock helper).
        db.lock()
            .execute(
                "UPDATE deliveries SET updated_at = ?2 WHERE id = ?1",
                params![d_old.id.to_string(), now - 10 * 60 * 1000],
            )
            .unwrap();

        let n = db.reset_stale_in_flight(now, 5 * 60 * 1000).unwrap();
        assert_eq!(n, 1);

        let old = db.find(&d_old.id).unwrap().unwrap();
        assert_eq!(old.status, DeliveryStatus::Pending);
        assert_eq!(old.next_retry_at, now);
        let fresh = db.find(&d_fresh.id).unwrap().unwrap();
        assert_eq!(fresh.status, DeliveryStatus::InFlight);
    }

    #[test]
    fn stats_counts() {
        let db = test_db();
        assert!(db.ping());

        let a = new_delivery(None);
        let b = new_delivery(None);
        let c = new_delivery(None);
        db.insert(&a).unwrap();
        db.insert(&b).unwrap();
        db.insert(&c).unwrap();

        db.claim(&a.id).unwrap();
        db.mark_delivered(&a.id).unwrap();
        db.claim(&b.id).unwrap();
        db.dead_letter(&b.id, "nope").unwrap();

        let s = db.stats().unwrap();
        assert_eq!(s.submitted, 3);
        assert_eq!(s.delivered, 1);
        assert_eq!(s.dead_lettered, 1);
        assert_eq!(s.pending, 1);
        assert_eq!(s.in_flight, 0);
        assert_eq!(s.dead_letters, 1);
    }
}
