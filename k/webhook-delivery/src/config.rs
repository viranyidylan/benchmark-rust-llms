use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    pub max_attempts: i64,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub request_timeout_secs: u64,
    pub max_payload_bytes: usize,
    pub hmac_secret: String,
    pub allow_private_destinations: bool,
    pub worker_poll_ms: u64,
    pub worker_concurrency: usize,
}

const DEFAULT_HMAC_SECRET: &str = "dev-insecure-secret";

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        let database_url = env_or("DATABASE_URL", "sqlite://webhook.db?mode=rwc");
        let bind_addr = env_or("BIND_ADDR", "0.0.0.0:3000");
        let max_attempts = env_parse("MAX_ATTEMPTS", 8i64)?;
        let base_delay_ms = env_parse("BASE_DELAY_MS", 1000u64)?;
        let max_delay_ms = env_parse("MAX_DELAY_MS", 300_000u64)?;
        let request_timeout_secs = env_parse("REQUEST_TIMEOUT_SECS", 10u64)?;
        let max_payload_bytes = env_parse("MAX_PAYLOAD_BYTES", 262_144usize)?;
        let hmac_secret = env_or("HMAC_SECRET", DEFAULT_HMAC_SECRET);
        if hmac_secret == DEFAULT_HMAC_SECRET {
            tracing::warn!(
                "HMAC_SECRET is not set; using the built-in development default. \
                 Set HMAC_SECRET in production."
            );
        }
        let allow_private_destinations = env_bool("ALLOW_PRIVATE_DESTINATIONS", false);
        let worker_poll_ms = env_parse("WORKER_POLL_MS", 500u64)?;
        let worker_concurrency = env_parse("WORKER_CONCURRENCY", 4usize)?;

        Ok(Config {
            database_url,
            bind_addr,
            max_attempts,
            base_delay_ms,
            max_delay_ms,
            request_timeout_secs,
            max_payload_bytes,
            hmac_secret,
            allow_private_destinations,
            worker_poll_ms,
            worker_concurrency,
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_parse<T>(key: &str, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    match env::var(key) {
        Ok(raw) => raw
            .parse::<T>()
            .map_err(|e| anyhow::anyhow!("invalid value for {key}: {e}")),
        Err(_) => Ok(default),
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(raw) => matches!(raw.as_str(), "true" | "1"),
        Err(_) => default,
    }
}
