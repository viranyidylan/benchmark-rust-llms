use std::{net::SocketAddr, path::PathBuf, time::Duration};

/// Runtime configuration for the webhook delivery service.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    /// Shared secret required in the `X-Api-Key` header for all endpoints.
    pub api_key: String,
    /// SQLite database file path. ":memory:" for tests.
    pub db_path: PathBuf,
    /// Maximum delivery attempts before a job moves to the DLQ.
    pub max_attempts: u32,
    /// Base delay for the first retry (exponential backoff grows from here).
    pub retry_base: Duration,
    /// Cap on how large the backoff can grow.
    pub retry_max: Duration,
    /// Polling interval of the delivery worker.
    pub poll_interval: Duration,
    /// Permit delivery to private/reserved hosts (useful for local testing).
    /// Defaults to false (SSRF protection on). Set ALLOW_PRIVATE=true to disable.
    #[allow(dead_code)]
    pub allow_private: bool,
}

impl Config {
    #[allow(dead_code)]
    /// Defaults chosen for a typical local/dev run.
    pub fn from_env() -> Self {
        let bind_addr: SocketAddr = std::env::var("BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
            .parse()
            .expect("invalid BIND_ADDR");
        let api_key = std::env::var("API_KEY").unwrap_or_else(|_| "dev-secret".to_string());
        let db_path = PathBuf::from(std::env::var("DB_PATH").unwrap_or_else(|_| "webhook.db".to_string()));
        let max_attempts: u32 = std::env::var("MAX_ATTEMPTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);
        let retry_base = Duration::from_secs(
            std::env::var("RETRY_BASE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
        );
        let retry_max = Duration::from_secs(
            std::env::var("RETRY_MAX_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
        );
        let poll_interval = Duration::from_millis(
            std::env::var("POLL_INTERVAL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(500),
        );
        let allow_private = std::env::var("ALLOW_PRIVATE")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        Self {
            bind_addr,
            api_key,
            db_path,
            max_attempts,
            retry_base,
            retry_max,
            poll_interval,
            allow_private,
        }
    }
}

impl Config {
    /// Build a minimal config for in-memory tests.
    #[allow(dead_code)]
    pub fn default_test(max_attempts: u32) -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            api_key: "testkey".into(),
            db_path: ":memory:".into(),
            max_attempts,
            retry_base: std::time::Duration::from_millis(50),
            retry_max: std::time::Duration::from_secs(1),
            poll_interval: std::time::Duration::from_millis(50),
            allow_private: true,
        }
    }
}
