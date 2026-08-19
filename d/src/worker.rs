use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use rand::Rng;
use tokio::time::sleep;

use crate::config::Config;
use crate::db::Db;
use crate::models::WebhookJob;

pub async fn run_worker(db: Db, config: Arc<Config>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client");

    loop {
        let now = Utc::now();
        match db.fetch_due(now, 10) {
            Ok(jobs) => {
                for job in jobs {
                    process_job(&db, &config, &client, &job).await;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to fetch due jobs");
            }
        }
        sleep(config.poll_interval).await;
    }
}

async fn process_job(db: &Db, config: &Config, client: &reqwest::Client, job: &WebhookJob) {
    if let Err(err) = check_destination_blocked(&job.destination).await {
        tracing::warn!(job_id = %job.id, error = %err, "blocking job due to SSRF policy");
        let _ = db.move_to_dlq(job, &format!("blocked: {err}"));
        return;
    }

    let result = client
        .post(&job.destination)
        .json(&job.payload)
        .send()
        .await;

    match result {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!(job_id = %job.id, "delivered");
            let _ = db.mark_delivered(&job.id);
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            tracing::warn!(job_id = %job.id, status, "delivery returned non-success");
            handle_failure(db, config, job, &format!("HTTP status {status}")).await;
        }
        Err(e) => {
            tracing::warn!(job_id = %job.id, error = %e, "delivery failed");
            handle_failure(db, config, job, &e.to_string()).await;
        }
    }
}

async fn handle_failure(db: &Db, config: &Config, job: &WebhookJob, error: &str) {
    let attempts = job.attempts + 1;
    if attempts >= job.max_attempts {
        let failed = WebhookJob { attempts, ..job.clone() };
        tracing::error!(job_id = %job.id, "moved to dead letter queue after max attempts");
        let _ = db.move_to_dlq(&failed, error);
    } else {
        let delay = backoff(attempts, config);
        let next = Utc::now() + chrono::Duration::from_std(delay).unwrap_or_else(|_| chrono::Duration::seconds(5));
        tracing::info!(job_id = %job.id, attempts, delay_ms = delay.as_millis(), "scheduling retry");
        let _ = db.record_attempt(&job.id, attempts, Some(next));
    }
}

fn backoff(attempt: u32, config: &Config) -> Duration {
    let base_ms = config.retry_base.as_millis() as u64;
    let shift = attempt.saturating_sub(1).min(10);
    let exp = base_ms
        .saturating_mul(1u64 << shift)
        .min(config.retry_max.as_millis() as u64);
    let jitter = rand::thread_rng().gen_range(0.8_f64..1.2_f64);
    Duration::from_millis((exp as f64 * jitter) as u64)
}

async fn check_destination_blocked(destination: &str) -> Result<(), String> {
    let parsed = crate::security::validate_destination(destination).map_err(|e| e)?;
    let host = host_from_url(&parsed.host);
    // skip SSRF resolution when private delivery is explicitly allowed (tests/local)
    if std::env::var("ALLOW_PRIVATE").map(|v| v == "true" || v == "1").unwrap_or(false) {
        return Ok(());
    }
    if host.is_empty() {
        return Err("no host in URL".to_string());
    }
    if crate::security::is_blocked_literal_ip(&host) {
        return Err(format!("host {host} is a private/reserved address"));
    }
    let ips = tokio::net::lookup_host((host.as_str(), 0))
        .await
        .map_err(|e| e.to_string())?;
    for addr in ips {
        if crate::security::is_private_ip(&addr.ip()) {
            return Err(format!("host {host} resolves to private address {}", addr.ip()));
        }
    }
    Ok(())
}

fn host_from_url(authority: &str) -> String {
    let without_path = authority.split('/').next().unwrap_or("");
    let idx = without_path.rfind(':').and_then(|i| {
        let port = &without_path[i + 1..];
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            Some(i)
        } else {
            None
        }
    });
    match idx {
        Some(i) => without_path[..i].to_string(),
        None => without_path.to_string(),
    }
}
