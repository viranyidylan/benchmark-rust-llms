//! End-to-end test (PLAN.md, T10): real router + real worker + in-memory
//! SQLite + mock destination server, all driven over HTTP.
//!
//! Scenarios:
//! 1. happy path: `202` -> delivered, `attempts = 1`
//! 2. `500, 500, 200` -> delivered with `attempts = 3`
//! 3. always-500 with `max_attempts = 2` -> dead-lettered -> listed -> replayed -> delivered
//! 4. security: 401 (no key), 403 (loopback dest, `allow_private = false`),
//!    400 (`ftp://`), 429 (tiny rate limit), 413 (oversized payload)
//! 5. idempotency dedupe via `Idempotency-Key`
//! 6. crash recovery: stale `in_flight` row is reset and redelivered

use std::collections::VecDeque;
use std::future::IntoFuture;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::serve;
use axum::Router;
use serde_json::json;
use tokio::sync::watch;
use uuid::Uuid;

use webhook_delivery::api::{router, AppState, Metrics};
use webhook_delivery::config::Config;
use webhook_delivery::db::Db;
use webhook_delivery::delivery::worker::{build_client, Worker};
use webhook_delivery::model::{now_ms, Delivery, DeliveryStatus};
use webhook_delivery::security::ratelimit::RateLimiter;
use webhook_delivery::security::ssrf::SsrfPolicy;

const API_KEY: &str = "test-key";
const ADMIN_KEY: &str = "test-admin";

type Script = Arc<Mutex<VecDeque<u16>>>;

/// Mock destination: answers every request with the next status code from
/// the script (default 200 once exhausted).
async fn start_mock(script: Vec<u16>) -> (String, u16, Script) {
    let script: Script = Arc::new(Mutex::new(VecDeque::from(script)));
    let app = Router::new()
        .fallback(move |State(script): State<Script>| async move {
            let status = script.lock().unwrap().pop_front().unwrap_or(200);
            StatusCode::from_u16(status).unwrap()
        })
        .with_state(script.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve(listener, app).into_future());
    (format!("http://127.0.0.1:{port}"), port, script)
}

/// One in-process deployment: mock destination + in-memory DB + API server.
/// The worker is created here but only started via [`TestApp::start_worker`],
/// so the crash-recovery scenario can stage the DB before the worker runs.
struct TestApp {
    base_url: String,
    mock_url: String,
    db: Arc<Db>,
    worker: Option<Worker>,
    shutdown_tx: Option<watch::Sender<bool>>,
    _worker_handle: Option<tokio::task::JoinHandle<()>>,
}

async fn start_app(mut cfg: Config, script: Vec<u16>) -> TestApp {
    let (mock_url, mock_port, _mock) = start_mock(script).await;
    cfg.listen_addr = "127.0.0.1:0".parse().unwrap();
    cfg.database_path = ":memory:".to_string();

    let db = Arc::new(Db::new(&cfg.database_path).unwrap());
    let metrics = Metrics::new();
    let ssrf = SsrfPolicy::new(cfg.allow_private_destinations, vec![80, 443, mock_port]);
    let limiter = Arc::new(RateLimiter::new(
        cfg.rate_limit_per_min,
        Duration::from_secs(60),
    ));
    let state = AppState {
        db: db.clone(),
        cfg: cfg.clone(),
        metrics: metrics.clone(),
        ssrf: ssrf.clone(),
        limiter,
    };
    let client = build_client(&cfg);
    let worker = Worker::new(db.clone(), cfg, client, ssrf, metrics);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve(listener, router(state)).into_future());

    TestApp {
        base_url: format!("http://127.0.0.1:{port}"),
        mock_url,
        db,
        worker: Some(worker),
        shutdown_tx: None,
        _worker_handle: None,
    }
}

impl TestApp {
    fn start_worker(&mut self) {
        let worker = self.worker.take().unwrap();
        let (tx, rx) = watch::channel(false);
        self.shutdown_tx = Some(tx);
        self._worker_handle = Some(tokio::spawn(async move {
            let mut rx = rx;
            worker.run(&mut rx).await;
        }));
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send_replace(true);
        }
        if let Some(handle) = self._worker_handle.take() {
            let _ = handle.await;
        }
    }
}

/// Poll the DB until the delivery reaches `want` (panics on timeout).
async fn wait_status(db: &Db, id: &Uuid, want: DeliveryStatus, timeout: Duration) -> Delivery {
    let start = Instant::now();
    loop {
        match db.find(id).unwrap() {
            Some(d) if d.status == want => return d,
            Some(d) => {
                if start.elapsed() > timeout {
                    panic!(
                        "timed out waiting for {id}: status={:?} attempts={} last_error={:?}",
                        d.status, d.attempts, d.last_error
                    );
                }
            }
            None => panic!("delivery {id} missing"),
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn webhook_body(destination: &str, data: &serde_json::Value) -> String {
    json!({ "data": data, "destination": destination }).to_string()
}

#[tokio::test]
async fn e2e() {
    let client = reqwest::Client::new();

    // --- App A: happy path (1), retries (2), idempotency (5) ----------------
    {
        let mut app = start_app(Config::test_defaults(), vec![200, 500, 500, 200, 200]).await;
        app.start_worker();

        // 1. Happy path: 202 -> delivered, attempts = 1.
        let resp = client
            .post(format!("{}/webhook", app.base_url))
            .header("Authorization", format!("Bearer {API_KEY}"))
            .body(webhook_body(
                &format!("{}/s1", app.mock_url),
                &json!({ "hello": "world" }),
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let v: serde_json::Value = resp.json().await.unwrap();
        let id1: Uuid = v["id"].as_str().unwrap().parse().unwrap();
        let row = wait_status(
            &app.db,
            &id1,
            DeliveryStatus::Delivered,
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(row.attempts, 1);
        assert!(row.last_error.is_none());

        // The same delivery, as seen through the admin API.
        let resp = client
            .get(format!("{}/deliveries/{id1}", app.base_url))
            .header("Authorization", format!("Bearer {ADMIN_KEY}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v["status"].as_str(), Some("delivered"));
        assert_eq!(v["attempts"].as_u64(), Some(1));

        // 2. 500, 500, 200 -> delivered with attempts = 3.
        let resp = client
            .post(format!("{}/webhook", app.base_url))
            .header("Authorization", format!("Bearer {API_KEY}"))
            .body(webhook_body(
                &format!("{}/s2", app.mock_url),
                &json!({ "n": 2 }),
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let v: serde_json::Value = resp.json().await.unwrap();
        let id2: Uuid = v["id"].as_str().unwrap().parse().unwrap();
        let row = wait_status(
            &app.db,
            &id2,
            DeliveryStatus::Delivered,
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(row.attempts, 3);

        // 5. Idempotency: same key twice -> duplicate with the original id.
        let body = webhook_body(&format!("{}/s5", app.mock_url), &json!({ "n": 5 }));
        let resp = client
            .post(format!("{}/webhook", app.base_url))
            .header("Authorization", format!("Bearer {API_KEY}"))
            .header("Idempotency-Key", "e2e-key-1")
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let v: serde_json::Value = resp.json().await.unwrap();
        let id5: Uuid = v["id"].as_str().unwrap().parse().unwrap();
        wait_status(
            &app.db,
            &id5,
            DeliveryStatus::Delivered,
            Duration::from_secs(10),
        )
        .await;

        let resp = client
            .post(format!("{}/webhook", app.base_url))
            .header("Authorization", format!("Bearer {API_KEY}"))
            .header("Idempotency-Key", "e2e-key-1")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v["duplicate"].as_bool(), Some(true));
        assert_eq!(v["id"].as_str(), Some(id5.to_string().as_str()));

        app.shutdown().await;
    }

    // --- App B: retries exhausted -> DLQ -> replay (3) ----------------------
    {
        let mut cfg = Config::test_defaults();
        cfg.max_attempts = 2;
        // 500, 500 -> dead-lettered (max_attempts = 2); 200 -> the replay
        // is delivered.
        let mut app = start_app(cfg, vec![500, 500, 200]).await;
        app.start_worker();

        let resp = client
            .post(format!("{}/webhook", app.base_url))
            .header("Authorization", format!("Bearer {API_KEY}"))
            .body(webhook_body(
                &format!("{}/s3", app.mock_url),
                &json!({ "n": 3 }),
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let v: serde_json::Value = resp.json().await.unwrap();
        let id3: Uuid = v["id"].as_str().unwrap().parse().unwrap();
        let row = wait_status(
            &app.db,
            &id3,
            DeliveryStatus::DeadLetter,
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(row.attempts, 1); // dead_letter does not increment attempts
        assert!(row.last_error.as_deref().unwrap().contains("500"));

        // List the DLQ (admin) and find our entry.
        let resp = client
            .get(format!("{}/admin/dead-letters", app.base_url))
            .header("Authorization", format!("Bearer {ADMIN_KEY}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let entries: Vec<serde_json::Value> = resp.json().await.unwrap();
        let entry = entries
            .iter()
            .find(|e| e["delivery_id"].as_str() == Some(id3.to_string().as_str()))
            .expect("dead-lettered delivery listed")
            .clone();
        assert_eq!(entry["attempts"].as_u64(), Some(1));

        // Replay (mock exhausted -> default 200) -> delivered, attempts reset.
        let resp = client
            .post(format!(
                "{}/admin/dead-letters/{}/replay",
                app.base_url,
                entry["id"].as_str().unwrap()
            ))
            .header("Authorization", format!("Bearer {ADMIN_KEY}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let row = wait_status(
            &app.db,
            &id3,
            DeliveryStatus::Delivered,
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(row.attempts, 1);

        app.shutdown().await;
    }

    // --- App C: security battery (4) ----------------------------------------
    {
        let mut cfg = Config::test_defaults();
        cfg.allow_private_destinations = false;
        cfg.rate_limit_per_min = 2;
        cfg.max_payload_bytes = 256;
        let mut app = start_app(cfg, Vec::new()).await;
        app.start_worker(); // nothing will ever be queued

        // 401: no credentials at all.
        let resp = client
            .post(format!("{}/webhook", app.base_url))
            .body(webhook_body("http://127.0.0.1:1/x", &json!({})))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 403: loopback destination with allow_private = false (rate slot 1).
        let resp = client
            .post(format!("{}/webhook", app.base_url))
            .header("Authorization", format!("Bearer {API_KEY}"))
            .body(webhook_body(&app.mock_url, &json!({})))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // 400: non-http(s) scheme (rate slot 2).
        let resp = client
            .post(format!("{}/webhook", app.base_url))
            .header("Authorization", format!("Bearer {API_KEY}"))
            .body(webhook_body("ftp://example.invalid/x", &json!({})))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // 429: third authenticated request exceeds the limit of 2/min.
        let resp = client
            .post(format!("{}/webhook", app.base_url))
            .header("Authorization", format!("Bearer {API_KEY}"))
            .body(webhook_body(&app.mock_url, &json!({})))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // 413: body over MAX_PAYLOAD_BYTES (enforced before auth).
        let big = "x".repeat(300);
        let resp = client
            .post(format!("{}/webhook", app.base_url))
            .header("Authorization", format!("Bearer {API_KEY}"))
            .body(webhook_body(&app.mock_url, &json!({ "blob": big })))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        app.shutdown().await;
    }

    // --- App D: crash recovery (6) -------------------------------------------
    {
        let mut app = start_app(Config::test_defaults(), vec![200]).await;
        // No worker yet: post, then stage a crashed in-flight row.
        let resp = client
            .post(format!("{}/webhook", app.base_url))
            .header("Authorization", format!("Bearer {API_KEY}"))
            .body(webhook_body(
                &format!("{}/s6", app.mock_url),
                &json!({ "n": 6 }),
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let v: serde_json::Value = resp.json().await.unwrap();
        let id6: Uuid = v["id"].as_str().unwrap().parse().unwrap();

        // Simulate a crash: row stuck in_flight with an old updated_at.
        app.db
            .set_in_flight_stale_for_test(&id6, now_ms() - 10_000)
            .unwrap();

        // (Re)start: the worker resets the stale row and redelivers.
        app.start_worker();
        let row = wait_status(
            &app.db,
            &id6,
            DeliveryStatus::Delivered,
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(row.attempts, 2); // stale helper set attempts = 1; redelivery makes 2

        app.shutdown().await;
    }
}
