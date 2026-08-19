use std::env;
use std::net::SocketAddr;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    Missing(&'static str),
    #[error("environment variable {0} must not be empty")]
    Empty(&'static str),
    #[error("invalid value for {var} = \'{value}\': {reason}")]
    Invalid {
        var: &'static str,
        value: String,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub api_keys: Vec<String>,
    pub admin_key: String,
    pub hmac_secret: Option<String>,
    pub database_path: String,
    pub worker_count: usize,
    pub poll_interval_ms: u64,
    pub max_attempts: u32,
    pub base_retry_delay_ms: u64,
    pub max_retry_delay_ms: u64,
    pub request_timeout_ms: u64,
    pub max_payload_bytes: u64,
    pub allow_private_destinations: bool,
    pub rate_limit_per_min: u32,
    pub stale_in_flight_ms: u64,
}

impl Config {
    /// Build a [`Config`] from the process environment.
    ///
    /// Required vars: `WEBHOOK_API_KEYS`, `WEBHOOK_ADMIN_KEY`.
    /// Every other var falls back to the default in PLAN.md §6.
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            listen_addr: parse_listen_addr("LISTEN_ADDR")?,
            api_keys: parse_api_keys("WEBHOOK_API_KEYS")?,
            admin_key: required("WEBHOOK_ADMIN_KEY")?,
            hmac_secret: optional("HMAC_SECRET"),
            database_path: env::var("DATABASE_PATH")
                .unwrap_or_else(|_| "./data/webhook.db".to_string()),
            worker_count: parse_u64("WORKER_COUNT", 4)? as usize,
            poll_interval_ms: parse_u64("POLL_INTERVAL_MS", 500)?,
            max_attempts: parse_u64("MAX_ATTEMPTS", 8)? as u32,
            base_retry_delay_ms: parse_u64("BASE_RETRY_DELAY_MS", 5000)?,
            max_retry_delay_ms: parse_u64("MAX_RETRY_DELAY_MS", 3600000)?,
            request_timeout_ms: parse_u64("REQUEST_TIMEOUT_MS", 10000)?,
            max_payload_bytes: parse_u64("MAX_PAYLOAD_BYTES", 1048576)?,
            allow_private_destinations: parse_bool("ALLOW_PRIVATE_DESTINATIONS", false)?,
            rate_limit_per_min: parse_u64("RATE_LIMIT_PER_MIN", 120)? as u32,
            stale_in_flight_ms: parse_u64("STALE_IN_FLIGHT_MS", 300000)?,
        })
    }

    /// A [`Config`] suitable for in-process tests: in-memory DB, tiny delays,
    /// private destinations allowed, fixed credentials. Exposed (not
    /// `#[cfg(test)]`) so the integration tests in `tests/` can use it.
    pub fn test_defaults() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            api_keys: vec!["test-key".to_string()],
            admin_key: "test-admin".to_string(),
            hmac_secret: None,
            database_path: ":memory:".to_string(),
            worker_count: 1,
            poll_interval_ms: 10,
            max_attempts: 8,
            base_retry_delay_ms: 10,
            max_retry_delay_ms: 100,
            request_timeout_ms: 1000,
            max_payload_bytes: 1024 * 1024,
            allow_private_destinations: true,
            rate_limit_per_min: 1_000_000,
            stale_in_flight_ms: 1000,
        }
    }
}

fn required(var: &'static str) -> Result<String, ConfigError> {
    match env::var(var) {
        Ok(v) if !v.trim().is_empty() => Ok(v),
        Ok(_) => Err(ConfigError::Empty(var)),
        Err(_) => Err(ConfigError::Missing(var)),
    }
}

fn optional(var: &'static str) -> Option<String> {
    env::var(var).ok().filter(|v| !v.is_empty())
}

fn parse_listen_addr(var: &'static str) -> Result<SocketAddr, ConfigError> {
    let raw = env::var(var).unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    raw.parse::<SocketAddr>().map_err(|e| ConfigError::Invalid {
        var,
        value: raw,
        reason: format!("not a valid socket address ({e})"),
    })
}

fn parse_api_keys(var: &'static str) -> Result<Vec<String>, ConfigError> {
    let raw = env::var(var).map_err(|_| ConfigError::Missing(var))?;
    let keys: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if keys.is_empty() {
        return Err(ConfigError::Empty(var));
    }
    Ok(keys)
}

fn parse_u64(var: &'static str, default: u64) -> Result<u64, ConfigError> {
    match env::var(var) {
        Ok(v) if !v.trim().is_empty() => {
            let trimmed = v.trim().to_string();
            let n: u64 = trimmed.parse().map_err(|e| ConfigError::Invalid {
                var,
                value: v.clone(),
                reason: format!("not a valid unsigned integer ({e})"),
            })?;
            if n == 0 {
                return Err(ConfigError::Invalid {
                    var,
                    value: v,
                    reason: "must be greater than 0".to_string(),
                });
            }
            Ok(n)
        }
        Ok(_) => Ok(default),
        Err(_) => Ok(default),
    }
}

fn parse_bool(var: &'static str, default: bool) -> Result<bool, ConfigError> {
    match env::var(var) {
        Ok(v) if !v.trim().is_empty() => match v.trim().to_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(ConfigError::Invalid {
                var,
                value: v,
                reason: format!("expected 'true' or 'false', got \'{other}\'"),
            }),
        },
        Ok(_) => Ok(default),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const ALL_VARS: &[&str] = &[
        "LISTEN_ADDR",
        "WEBHOOK_API_KEYS",
        "WEBHOOK_ADMIN_KEY",
        "HMAC_SECRET",
        "DATABASE_PATH",
        "WORKER_COUNT",
        "POLL_INTERVAL_MS",
        "MAX_ATTEMPTS",
        "BASE_RETRY_DELAY_MS",
        "MAX_RETRY_DELAY_MS",
        "REQUEST_TIMEOUT_MS",
        "MAX_PAYLOAD_BYTES",
        "ALLOW_PRIVATE_DESTINATIONS",
        "RATE_LIMIT_PER_MIN",
        "STALE_IN_FLIGHT_MS",
    ];

    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn set(pairs: &[(&str, &str)]) -> Self {
            let mut saved = Vec::new();
            for v in ALL_VARS.iter().copied() {
                saved.push((v, env::var(v).ok()));
            }
            for v in ALL_VARS.iter().copied() {
                env::remove_var(v);
            }
            for (k, val) in pairs {
                env::set_var(k, val);
            }
            EnvGuard { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (v, val) in self.saved.drain(..) {
                match val {
                    Some(val) => env::set_var(v, val),
                    None => env::remove_var(v),
                }
            }
        }
    }

    fn lock() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn invalid_var(e: &ConfigError) -> Option<&'static str> {
        match e {
            ConfigError::Invalid { var, .. } => Some(*var),
            _ => None,
        }
    }

    #[test]
    fn defaults() {
        let _lock = lock();
        let _guard = EnvGuard::set(&[("WEBHOOK_API_KEYS", "k1"), ("WEBHOOK_ADMIN_KEY", "admin")]);
        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(cfg.api_keys, vec!["k1".to_string()]);
        assert_eq!(cfg.admin_key, "admin");
        assert_eq!(cfg.hmac_secret, None);
        assert_eq!(cfg.database_path, "./data/webhook.db");
        assert_eq!(cfg.worker_count, 4);
        assert_eq!(cfg.poll_interval_ms, 500);
        assert_eq!(cfg.max_attempts, 8);
        assert_eq!(cfg.base_retry_delay_ms, 5000);
        assert_eq!(cfg.max_retry_delay_ms, 3600000);
        assert_eq!(cfg.request_timeout_ms, 10000);
        assert_eq!(cfg.max_payload_bytes, 1048576);
        assert!(!cfg.allow_private_destinations);
        assert_eq!(cfg.rate_limit_per_min, 120);
        assert_eq!(cfg.stale_in_flight_ms, 300000);
    }

    #[test]
    fn env_overrides() {
        let _lock = lock();
        let _guard = EnvGuard::set(&[
            ("LISTEN_ADDR", "0.0.0.0:9000"),
            ("WEBHOOK_API_KEYS", "a, b ,c"),
            ("WEBHOOK_ADMIN_KEY", "admin2"),
            ("HMAC_SECRET", "secret"),
            ("DATABASE_PATH", "/tmp/x.db"),
            ("WORKER_COUNT", "2"),
            ("POLL_INTERVAL_MS", "250"),
            ("MAX_ATTEMPTS", "5"),
            ("BASE_RETRY_DELAY_MS", "100"),
            ("MAX_RETRY_DELAY_MS", "5000"),
            ("REQUEST_TIMEOUT_MS", "5000"),
            ("MAX_PAYLOAD_BYTES", "2048"),
            ("ALLOW_PRIVATE_DESTINATIONS", "true"),
            ("RATE_LIMIT_PER_MIN", "60"),
            ("STALE_IN_FLIGHT_MS", "60000"),
        ]);
        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.listen_addr, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(
            cfg.api_keys,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert_eq!(cfg.admin_key, "admin2");
        assert_eq!(cfg.hmac_secret, Some("secret".to_string()));
        assert_eq!(cfg.database_path, "/tmp/x.db");
        assert_eq!(cfg.worker_count, 2);
        assert_eq!(cfg.poll_interval_ms, 250);
        assert_eq!(cfg.max_attempts, 5);
        assert_eq!(cfg.base_retry_delay_ms, 100);
        assert_eq!(cfg.max_retry_delay_ms, 5000);
        assert_eq!(cfg.request_timeout_ms, 5000);
        assert_eq!(cfg.max_payload_bytes, 2048);
        assert!(cfg.allow_private_destinations);
        assert_eq!(cfg.rate_limit_per_min, 60);
        assert_eq!(cfg.stale_in_flight_ms, 60000);
    }

    #[test]
    fn missing_api_keys() {
        let _lock = lock();
        let _guard = EnvGuard::set(&[("WEBHOOK_ADMIN_KEY", "admin")]);
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::Missing("WEBHOOK_API_KEYS"))
        ));
    }

    #[test]
    fn missing_admin_key() {
        let _lock = lock();
        let _guard = EnvGuard::set(&[("WEBHOOK_API_KEYS", "k1")]);
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::Missing("WEBHOOK_ADMIN_KEY"))
        ));
    }

    #[test]
    fn empty_api_keys() {
        let _lock = lock();
        let _guard = EnvGuard::set(&[
            ("WEBHOOK_API_KEYS", "  ,  "),
            ("WEBHOOK_ADMIN_KEY", "admin"),
        ]);
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::Empty("WEBHOOK_API_KEYS"))
        ));
    }

    #[test]
    fn empty_admin_key() {
        let _lock = lock();
        let _guard = EnvGuard::set(&[("WEBHOOK_API_KEYS", "k1"), ("WEBHOOK_ADMIN_KEY", "  ")]);
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::Empty("WEBHOOK_ADMIN_KEY"))
        ));
    }

    #[test]
    fn bad_listen_addr() {
        let _lock = lock();
        let _guard = EnvGuard::set(&[
            ("LISTEN_ADDR", "not-an-addr"),
            ("WEBHOOK_API_KEYS", "k1"),
            ("WEBHOOK_ADMIN_KEY", "admin"),
        ]);
        let err = Config::from_env().unwrap_err();
        assert_eq!(invalid_var(&err), Some("LISTEN_ADDR"));
    }

    #[test]
    fn bad_bool() {
        let _lock = lock();
        let _guard = EnvGuard::set(&[
            ("ALLOW_PRIVATE_DESTINATIONS", "maybe"),
            ("WEBHOOK_API_KEYS", "k1"),
            ("WEBHOOK_ADMIN_KEY", "admin"),
        ]);
        let err = Config::from_env().unwrap_err();
        assert_eq!(invalid_var(&err), Some("ALLOW_PRIVATE_DESTINATIONS"));
    }

    #[test]
    fn zero_worker_count() {
        let _lock = lock();
        let _guard = EnvGuard::set(&[
            ("WORKER_COUNT", "0"),
            ("WEBHOOK_API_KEYS", "k1"),
            ("WEBHOOK_ADMIN_KEY", "admin"),
        ]);
        let err = Config::from_env().unwrap_err();
        assert_eq!(invalid_var(&err), Some("WORKER_COUNT"));
    }

    #[test]
    fn non_numeric() {
        let _lock = lock();
        let _guard = EnvGuard::set(&[
            ("MAX_ATTEMPTS", "abc"),
            ("WEBHOOK_API_KEYS", "k1"),
            ("WEBHOOK_ADMIN_KEY", "admin"),
        ]);
        let err = Config::from_env().unwrap_err();
        assert_eq!(invalid_var(&err), Some("MAX_ATTEMPTS"));
    }
}
