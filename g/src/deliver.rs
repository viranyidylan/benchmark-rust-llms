use crate::{config::Config, models::ClaimedJob, security};

use reqwest::Client;

/// Outbound HTTP client. Redirects are disabled so a destination cannot bounce
/// a request to a host that was not validated (SSRF via redirect).
pub fn build_http_client(timeout_secs: u64) -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("webhook-delivery/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("failed to build delivery http client")
}

/// Exponential backoff with full jitter for the retry after the given
/// (1-based) attempt number: delay in [min(base * 2^(n-1), cap) / 2, cap].
pub fn backoff_ms(cfg: &Config, attempt: i64) -> i64 {
    use rand::Rng;

    let exp = (attempt.max(1) - 1).clamp(0, 16) as f64;
    let base = (cfg.retry_base_ms.max(1) as f64) * 2f64.powf(exp);
    let capped = base.min(cfg.retry_max_ms.max(1) as f64);
    let mut rng = rand::thread_rng();
    rng.gen_range((capped / 2.0)..=capped) as i64
}

/// Perform one delivery attempt. Any outcome other than a 2xx response is an
/// error, including connect failures and timeouts.
pub async fn deliver_once(http: &Client, cfg: &Config, job: &ClaimedJob) -> Result<(), String> {
    security::validate_destination(&job.destination, cfg.allow_private_destinations)
        .await
        .map_err(|reason| format!("destination rejected: {reason}"))?;

    let timestamp = chrono::Utc::now().timestamp().to_string();
    let signature = security::sign_payload(&cfg.signing_secret, &timestamp, &job.payload);

    let result = http
        .post(&job.destination)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-Webhook-Id", &job.id)
        .header("X-Webhook-Timestamp", &timestamp)
        .header("X-Webhook-Signature", &signature)
        .body(job.payload.clone())
        .send()
        .await;

    match result {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(format!(
                "destination responded with HTTP {status}: {}",
                truncate(&body, 200)
            ))
        }
        Err(e) => Err(format!("request failed: {e}")),
    }
}

/// Truncate a string at a character boundary.
pub fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_jittered_and_capped() {
        let cfg = Config {
            retry_base_ms: 100,
            retry_max_ms: 1000,
            ..Config::default()
        };
        for attempt in 1..=25i64 {
            let d = backoff_ms(&cfg, attempt);
            assert!(d >= 50 && d <= 1000, "attempt {attempt} gave {d}");
        }
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("hello world", 5), "hello");
        assert_eq!(truncate("héllo wörld", 5), "héllo");
        assert_eq!(truncate("short", 50), "short");
    }
}
