//! Per-key sliding-window rate limiter (PLAN.md, T6).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Sliding-window limiter: each key may make at most `limit` checks per
/// rolling `window`. `Arc`-shareable.
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    hits: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Record a use for `key`; return `true` if it is within the limit.
    /// Expired timestamps (and fully-expired keys) are pruned on access.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = self.hits.lock().unwrap_or_else(|p| p.into_inner());
        let hits = map.entry(key.to_string()).or_default();
        while let Some(oldest) = hits.front() {
            if now.duration_since(*oldest) >= self.window {
                hits.pop_front();
            } else {
                break;
            }
        }
        if hits.len() as u32 >= self.limit {
            return false;
        }
        hits.push_back(now);
        map.retain(|_, v| !v.is_empty());
        true
    }

    /// Drop keys whose last hit is older than the window.
    pub fn prune(&self) {
        let now = Instant::now();
        let mut map = self.hits.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, v| {
            if let Some(last) = v.back() {
                now.duration_since(*last) < self.window
            } else {
                false
            }
        });
    }

    /// Number of keys with a live window (for tests/observability).
    pub fn active_keys(&self) -> usize {
        self.hits.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_at_n_plus_1() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        assert!(rl.check("k"));
        assert!(rl.check("k"));
        assert!(rl.check("k"));
        assert!(!rl.check("k"));
    }

    #[test]
    fn recovers_after_window() {
        let rl = RateLimiter::new(1, Duration::from_millis(50));
        assert!(rl.check("k"));
        assert!(!rl.check("k"));
        std::thread::sleep(Duration::from_millis(70));
        assert!(rl.check("k"));
    }

    #[test]
    fn per_key_isolation() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        assert!(rl.check("a"));
        assert!(!rl.check("a"));
        assert!(rl.check("b"));
        assert!(!rl.check("b"));
    }

    #[test]
    fn prune_drops_expired_keys() {
        let rl = RateLimiter::new(5, Duration::from_millis(20));
        rl.check("k");
        assert_eq!(rl.active_keys(), 1);
        std::thread::sleep(Duration::from_millis(30));
        rl.prune();
        assert_eq!(rl.active_keys(), 0);
    }
}
