use std::net::SocketAddr;

use rand::RngCore;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: SocketAddr,
    /// HMAC-SHA256 key used to sign delivered payloads so receivers can
    /// verify authenticity and reject replays.
    pub signing_secret: String,
    /// When set, all API routes (except /healthz) require an
    /// `X-API-Token` header matching this value.
    pub api_token: Option<String>,
    /// Maximum accepted request body size (and serialized `data` size).
    pub max_payload_bytes: usize,
    /// Delivery attempts before a job is moved to the dead letter queue.
    pub max_attempts: i64,
    /// Base delay for exponential backoff after the first failed attempt.
    pub retry_base_ms: i64,
    /// Upper bound for any single retry delay.
    pub retry_max_ms: i64,
    /// How often the worker polls the database for due deliveries.
    pub poll_interval_ms: u64,
    /// Maximum number of due deliveries claimed per poll.
    pub batch_size: i64,
    /// A job stuck in `processing` longer than this is assumed orphaned by a
    /// crash and is reclaimed for redelivery (at-least-once semantics).
    pub visibility_timeout_secs: i64,
    /// Timeout for a single outbound delivery attempt.
    pub delivery_timeout_secs: u64,
    /// Maximum concurrently executing outbound deliveries.
    pub max_concurrent_deliveries: usize,
    pub db_max_connections: u32,
    /// When true, destinations resolving to private/loopback/link-local
    /// addresses are allowed. Intended for local development and tests only.
    pub allow_private_destinations: bool,
}

fn env_str(key: &str, default: impl Into<String>) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    match std::env::var(key) {
        Ok(v) => match v.parse() {
            Ok(parsed) => parsed,
            Err(_) => {
                tracing::warn!(key, value = %v, "invalid value, using default");
                default
            }
        },
        Err(_) => default,
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            database_url: "sqlite://webhooks.db?mode=rwc".to_string(),
            bind_addr: "0.0.0.0:8080".parse().expect("valid default bind address"),
            signing_secret: String::new(),
            api_token: None,
            max_payload_bytes: 262_144,
            max_attempts: 10,
            retry_base_ms: 1_000,
            retry_max_ms: 300_000,
            poll_interval_ms: 200,
            batch_size: 50,
            visibility_timeout_secs: 60,
            delivery_timeout_secs: 10,
            max_concurrent_deliveries: 64,
            db_max_connections: 8,
            allow_private_destinations: false,
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        let signing_secret = std::env::var("WEBHOOK_SIGNING_SECRET").unwrap_or_else(|_| {
            tracing::warn!(
                "WEBHOOK_SIGNING_SECRET not set; generated an ephemeral secret. \
                 Receivers will not be able to verify signatures across restarts."
            );
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            hex::encode(bytes)
        });

        Config {
            database_url: env_str("DATABASE_URL", Config::default().database_url),
            bind_addr: env_parse("BIND_ADDR", Config::default().bind_addr),
            signing_secret,
            api_token: std::env::var("API_TOKEN").ok().filter(|s| !s.is_empty()),
            max_payload_bytes: env_parse("MAX_PAYLOAD_BYTES", Config::default().max_payload_bytes),
            max_attempts: env_parse("MAX_ATTEMPTS", Config::default().max_attempts),
            retry_base_ms: env_parse("RETRY_BASE_MS", Config::default().retry_base_ms),
            retry_max_ms: env_parse("RETRY_MAX_MS", Config::default().retry_max_ms),
            poll_interval_ms: env_parse("POLL_INTERVAL_MS", Config::default().poll_interval_ms),
            batch_size: env_parse("BATCH_SIZE", Config::default().batch_size),
            visibility_timeout_secs: env_parse(
                "VISIBILITY_TIMEOUT_SECS",
                Config::default().visibility_timeout_secs,
            ),
            delivery_timeout_secs: env_parse(
                "DELIVERY_TIMEOUT_SECS",
                Config::default().delivery_timeout_secs,
            ),
            max_concurrent_deliveries: env_parse(
                "MAX_CONCURRENT_DELIVERIES",
                Config::default().max_concurrent_deliveries,
            ),
            db_max_connections: env_parse("DB_MAX_CONNECTIONS", Config::default().db_max_connections),
            allow_private_destinations: env_bool("ALLOW_PRIVATE_DESTINATIONS", false),
        }
    }
}
