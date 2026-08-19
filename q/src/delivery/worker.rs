//! Delivery worker (PLAN.md, T7).

use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::watch;

use crate::api::Metrics;
use crate::config::Config;
use crate::db::Db;
use crate::model::{now_ms, Delivery};
use crate::security::ssrf::{SsrfPolicy, SystemResolver};

use super::backoff::next_delay_ms;
use super::classify::{classify, Outcome};

/// Outbound HTTP client (PLAN.md, T7): per-request timeout, **no redirects**,
/// fixed User-Agent, rustls TLS.
pub fn build_client(cfg: &Config) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        "webhook-delivery/0.1".parse().unwrap(),
    );
    reqwest::Client::builder()
        .timeout(Duration::from_millis(cfg.request_timeout_ms))
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(headers)
        .build()
        .expect("reqwest client")
}

/// POST `d.payload` to `d.destination` with the §4 delivery headers and
/// classify the response (or transport error).
pub async fn send(
    client: &reqwest::Client,
    d: &Delivery,
    attempt: u32,
    hmac_secret: &Option<String>,
) -> Outcome {
    let mut req = client
        .post(&d.destination)
        .header("Content-Type", "application/json")
        .header("X-Webhook-Id", d.id.to_string())
        .header("X-Webhook-Attempt", attempt.to_string())
        .header("X-Webhook-Timestamp", (now_ms() / 1000).to_string())
        .body(d.payload.clone());
    if let Some(secret) = hmac_secret {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(&d.payload);
        let hex: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        req = req.header("X-Webhook-Signature", format!("sha256={hex}"));
    }
    match req.send().await {
        Ok(res) => classify(res.status().as_u16(), None),
        Err(e) => classify(0, Some(&e)),
    }
}

/// One delivery worker: polls due rows and drives them to a terminal or
/// retryable state (PLAN.md, T7).
pub struct Worker {
    db: Arc<Db>,
    cfg: Config,
    client: reqwest::Client,
    ssrf: SsrfPolicy,
    metrics: Metrics,
}

impl Worker {
    pub fn new(
        db: Arc<Db>,
        cfg: Config,
        client: reqwest::Client,
        ssrf: SsrfPolicy,
        metrics: Metrics,
    ) -> Self {
        Self {
            db,
            cfg,
            client,
            ssrf,
            metrics,
        }
    }

    /// Run until `shutdown` is set to `true`.
    pub async fn run(&self, shutdown: &mut watch::Receiver<bool>) {
        // Re-queue in-flight rows that died with a previous process.
        let now = now_ms();
        let n = self
            .db
            .reset_stale_in_flight(now, self.cfg.stale_in_flight_ms as i64)
            .unwrap_or(0);
        if n > 0 {
            tracing::info!(reset = n, "reset stale in-flight deliveries");
        }

        loop {
            if *shutdown.borrow() {
                break;
            }
            let now = now_ms();
            for d in self.db.list_due(now, 20).unwrap_or_default() {
                self.process(&d).await;
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_millis(self.cfg.poll_interval_ms)) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }

    async fn process(&self, d: &Delivery) {
        // Re-validate SSRF on every attempt (PLAN.md, T7).
        let url = match url::Url::parse(&d.destination) {
            Ok(u) => u,
            Err(_) => {
                self.dead_letter(d, "ssrf: invalid destination url");
                return;
            }
        };
        let resolver = SystemResolver;
        if let Err(e) = self.ssrf.validate(&url, &resolver) {
            self.dead_letter(d, &format!("ssrf: {e}"));
            return;
        }

        if !self.db.claim(&d.id).unwrap_or(false) {
            return; // lost the claim race
        }

        let attempt = d.attempts + 1;
        let outcome = send(&self.client, d, attempt, &self.cfg.hmac_secret).await;
        match outcome {
            Outcome::Delivered => {
                let _ = self.db.mark_delivered(&d.id);
                self.metrics.inc_delivered();
            }
            Outcome::Retryable(err) => {
                if attempt >= d.max_attempts {
                    self.dead_letter(d, &err);
                } else {
                    let mut rng = rand::thread_rng();
                    let delay = next_delay_ms(
                        attempt,
                        self.cfg.base_retry_delay_ms,
                        self.cfg.max_retry_delay_ms,
                        &mut rng,
                    );
                    let _ = self.db.schedule_retry(&d.id, now_ms() + delay as i64, &err);
                    self.metrics.inc_retryable_failures();
                }
            }
            Outcome::Permanent(err) => {
                self.metrics.inc_permanent_failures();
                self.dead_letter(d, &err);
            }
        }
    }

    fn dead_letter(&self, d: &Delivery, err: &str) {
        let _ = self.db.dead_letter(&d.id, err);
        self.metrics.inc_dead_lettered();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Instant;

    use std::future::IntoFuture;

    use axum::http::StatusCode;
    use axum::serve;
    use axum::Router;
    use uuid::Uuid;

    use crate::api::Metrics;
    use crate::config::Config;
    use crate::db::Db;
    use crate::model::{DeliveryStatus, NewDelivery};

    type Script = Arc<Mutex<VecDeque<u16>>>;

    /// Mock destination: answers every request with the next status code from
    /// the script (default 200 when exhausted).
    async fn start_mock(script: Vec<u16>) -> (String, u16, Script) {
        let script: Script = Arc::new(Mutex::new(VecDeque::from(script)));
        let app = Router::new()
            .fallback(
                move |axum::extract::State(script): axum::extract::State<Script>| async move {
                    let status = script.lock().unwrap().pop_front().unwrap_or(200);
                    StatusCode::from_u16(status).unwrap()
                },
            )
            .with_state(script.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, app).into_future());
        (
            format!("http://{}:{}", addr.ip(), addr.port()),
            addr.port(),
            script,
        )
    }

    fn worker_for(db: Arc<Db>, cfg: Config, port: u16) -> Worker {
        Worker::new(
            db,
            cfg.clone(),
            build_client(&cfg),
            SsrfPolicy::new(cfg.allow_private_destinations, vec![80, 443, port]),
            Metrics::new(),
        )
    }

    fn insert_pending(db: &Db, destination: &str) -> Uuid {
        let id = Uuid::new_v4();
        db.insert(&NewDelivery {
            id,
            idempotency_key: None,
            destination: destination.to_string(),
            payload: br#"{"hello": "worker"}"#.to_vec(),
            max_attempts: 8,
        })
        .unwrap();
        id
    }

    async fn wait_for_status(
        db: &Db,
        id: &Uuid,
        status: DeliveryStatus,
        timeout: Duration,
    ) -> Option<Delivery> {
        let deadline = Instant::now() + timeout;
        loop {
            let done = match db.find(id).unwrap() {
                Some(d) if d.status == status => Some(d),
                _ => None,
            };
            if let Some(d) = done {
                return Some(d);
            }
            if Instant::now() > deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn run_worker_until_done(
        db: Arc<Db>,
        cfg: Config,
        port: u16,
        id: &Uuid,
        status: DeliveryStatus,
        timeout: Duration,
    ) -> Delivery {
        let worker = worker_for(db.clone(), cfg, port);
        let (tx, mut rx) = watch::channel(false);
        let handle = tokio::spawn(async move { worker.run(&mut rx).await });
        let row = wait_for_status(&db, id, status, timeout)
            .await
            .unwrap_or_else(|| panic!("timed out waiting for {status:?}"));
        let _ = tx.send_replace(true);
        handle.await.unwrap();
        row
    }

    #[tokio::test]
    async fn delivered_on_200() {
        let (dest, port, _) = start_mock(vec![200]).await;
        let cfg = Config::test_defaults();
        let db = Arc::new(Db::new(":memory:").unwrap());
        let id = insert_pending(&db, &dest);
        let row = run_worker_until_done(
            db,
            cfg,
            port,
            &id,
            DeliveryStatus::Delivered,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(row.attempts, 1);
        assert!(row.last_error.is_none());
    }

    #[tokio::test]
    async fn retried_then_delivered() {
        let (dest, port, _) = start_mock(vec![500, 500, 200]).await;
        let cfg = Config::test_defaults();
        let db = Arc::new(Db::new(":memory:").unwrap());
        let id = insert_pending(&db, &dest);
        let row = run_worker_until_done(
            db,
            cfg,
            port,
            &id,
            DeliveryStatus::Delivered,
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(row.attempts, 3);
    }

    #[tokio::test]
    async fn permanent_404_dead_letters() {
        let (dest, port, _) = start_mock(vec![404]).await;
        let cfg = Config::test_defaults();
        let db = Arc::new(Db::new(":memory:").unwrap());
        let id = insert_pending(&db, &dest);
        let row = run_worker_until_done(
            db,
            cfg,
            port,
            &id,
            DeliveryStatus::DeadLetter,
            Duration::from_secs(5),
        )
        .await;
        assert!(row.last_error.unwrap().contains("404"));
    }

    #[tokio::test]
    async fn stale_in_flight_reset_and_redelivered() {
        let (dest, port, _) = start_mock(vec![200]).await;
        let cfg = Config::test_defaults();
        let db = Arc::new(Db::new(":memory:").unwrap());
        let id = insert_pending(&db, &dest);
        db.set_in_flight_stale_for_test(&id, now_ms() - 5000)
            .unwrap();
        let row = run_worker_until_done(
            db,
            cfg,
            port,
            &id,
            DeliveryStatus::Delivered,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(row.attempts, 2);
    }
}
