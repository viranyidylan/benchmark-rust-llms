use std::{str::FromStr, time::Duration};

use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};

const CREATE_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS deliveries (
    id              TEXT PRIMARY KEY,
    destination     TEXT NOT NULL,
    payload         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL,
    next_attempt_at INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    delivered_at    INTEGER,
    last_error      TEXT
)
"#;

const CREATE_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_deliveries_status_next ON deliveries (status, next_attempt_at)";

pub async fn init_pool(url: &str, max_connections: u32) -> Result<SqlitePool, sqlx::Error> {
    let opts = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(opts)
        .await?;

    sqlx::query(CREATE_TABLE).execute(&pool).await?;
    sqlx::query(CREATE_INDEX).execute(&pool).await?;

    Ok(pool)
}

/// On startup, return any deliveries left in `processing` by a previous crash
/// back to the queue. This is part of the at-least-once guarantee: a job that
/// may or may not have been delivered is retried rather than dropped.
pub async fn reset_processing(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let now = chrono::Utc::now().timestamp_millis();
    let res = sqlx::query(
        "UPDATE deliveries SET status = 'pending', updated_at = ?1 WHERE status = 'processing'",
    )
    .bind(now)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
