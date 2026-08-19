//! Integration tests for the delivery worker (Step 5): end-to-end delivery,
//! retry sequencing, and the DLQ flow.
//!
//! Every test runs the FULL app (HTTP router + delivery workers) against a
//! throwaway SQLite file, with either a wiremock server or a tiny
//! stateful axum sink as the destination. All synchronization is done through
//! bounded polling loops ([`wait_until`]) — never fixed sleeps.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use webhook_delivery::config::Config;
use webhook_delivery::db::Db;
use webhook_delivery::routes::{build_router, AppState};
use webhook_delivery::security;
use webhook_delivery::worker::spawn_workers;
use wiremock::matchers::{body_string, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Config with fast, test-friendly delivery timing.
fn test_config(database_url: String) -> Config {
    Config {
        database_url,
        bind_addr: "127.0.0.1:0".to_string(),
        max_attempts: 3,
        base_delay_ms: 50,
        max_delay_ms: 200,
        request_timeout_secs: 2,
        max_payload_bytes: 262_144,
        hmac_secret: "test-secret".to_string(),
        allow_private_destinations: true,
        worker_poll_ms: 50,
        worker_concurrency: 1,
    }
}

/// sqlite:// URL for a fresh database file inside `dir`.
fn db_url(dir: &std::path::Path) -> String {
    format!("sqlite://{}?mode=rwc", dir.join("test.db").display())
}

/// Running app under test: HTTP base URL, worker handles, and the shutdown
/// token (cancelled on drop so workers stop promptly at end of test).
struct TestApp {
    base_url: String,
    workers: Vec<JoinHandle<()>>,
    shutdown: CancellationToken,
}

impl TestApp {
    /// Cancel the workers and wait for them to stop.
    async fn shutdown(mut self) {
        self.shutdown.cancel();
        for handle in std::mem::take(&mut self.workers) {
            let _ = handle.await;
        }
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Connect the DB, build the router, spawn the delivery workers, and serve
/// on an ephemeral loopback port.
async fn spawn_app(config: Config) -> TestApp {
    let db = Db::connect(&config).await.expect("connect test db");
    let state = AppState {
        db,
        config: Arc::new(config),
    };

    let shutdown = CancellationToken::new();
    let workers = spawn_workers(state.clone(), shutdown.clone());

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });

    TestApp {
        base_url: format!("http://{addr}"),
        workers,
        shutdown,
    }
}

/// Poll `cond` every 50 ms until it returns true or `timeout` elapses.
/// Panics (failing the test) on timeout. Never use fixed sleeps instead.
async fn wait_until<F, Fut>(what: &str, timeout: Duration, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    loop {
        if cond().await {
            return;
        }
        assert!(
            start.elapsed() <= timeout,
            "timed out after {timeout:?} waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// POST a webhook delivering `data` to `destination`; returns the job id.
async fn post_webhook(base_url: &str, destination: &str, data: serde_json::Value) -> Uuid {
    let resp = reqwest::Client::new()
        .post(format!("{base_url}/webhook"))
        .json(&serde_json::json!({ "data": data, "destination": destination }))
        .send()
        .await
        .expect("POST /webhook");
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let body: serde_json::Value = resp.json().await.unwrap();
    Uuid::parse_str(body["id"].as_str().expect("string id")).unwrap()
}

/// A stateful sink: returns `fail_until` - how many of the first requests get
/// a 500 before it starts answering 200. Every request body is recorded.
#[derive(Clone)]
struct Sink {
    hits: Arc<AtomicUsize>,
    fail_until: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<String>>>,
}

impl Sink {
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn bodies(&self) -> Vec<String> {
        self.bodies.lock().unwrap().clone()
    }

    fn set_fail_until(&self, n: usize) {
        self.fail_until.store(n, Ordering::SeqCst);
    }
}

async fn sink_handler(State(sink): State<Sink>, body: axum::body::Bytes) -> StatusCode {
    let n = sink.hits.fetch_add(1, Ordering::SeqCst) + 1;
    sink.bodies
        .lock()
        .unwrap()
        .push(String::from_utf8_lossy(&body).into_owned());
    if n <= sink.fail_until.load(Ordering::SeqCst) {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    }
}

/// Spawn the sink on an ephemeral port; returns (base_url, sink handle).
async fn spawn_sink(fail_until: usize) -> (String, Sink) {
    let sink = Sink {
        hits: Arc::new(AtomicUsize::new(0)),
        fail_until: Arc::new(AtomicUsize::new(fail_until)),
        bodies: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route("/hook", post(sink_handler))
        .with_state(sink.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind sink");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve sink");
    });
    (format!("http://{addr}"), sink)
}

/// (a) Happy path: 200 sink → delivered with exact body, id, and signature.
#[tokio::test]
async fn delivered_webhook_reaches_sink_with_signature_headers() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(db_url(dir.path()));
    let app = spawn_app(config.clone()).await;

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string(r#"{"hello":"world"}"#))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let id = post_webhook(
        &app.base_url,
        &format!("{}/hook", mock_server.uri()),
        serde_json::json!({ "hello": "world" }),
    )
    .await;

    wait_until("sink to receive 1 request", Duration::from_secs(10), || {
        let server = &mock_server;
        async move { server.received_requests().await.unwrap_or_default().len() == 1 }
    })
    .await;

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];

    // Body is exactly the compact-serialized payload.
    let body_bytes = &request.body;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(body_bytes).unwrap(),
        serde_json::json!({ "hello": "world" })
    );

    // X-Webhook-Id is the job uuid returned by POST /webhook.
    let webhook_id = request
        .headers
        .get("x-webhook-id")
        .and_then(|v| v.to_str().ok())
        .expect("x-webhook-id header present");
    assert_eq!(webhook_id, id.to_string());

    // X-Webhook-Signature starts with sha256= and matches sign_body(secret, body).
    let signature = request
        .headers
        .get("x-webhook-signature")
        .and_then(|v| v.to_str().ok())
        .expect("x-webhook-signature header present");
    assert!(signature.starts_with("sha256="), "signature: {signature}");
    assert_eq!(
        signature,
        security::sign_body(&config.hmac_secret, body_bytes),
        "signature must verify against the raw body and the app secret"
    );

    // wiremock's .expect(1) verifies the exact request count on drop.
    app.shutdown().await;
}

/// (b) Retry sequencing: 500, 500, then 200 → delivered after exactly 3 requests.
#[tokio::test]
async fn failed_attempts_are_retried_until_success() {
    let dir = tempfile::tempdir().unwrap();
    let app = spawn_app(test_config(db_url(dir.path()))).await;
    let (sink_url, sink) = spawn_sink(2).await; // first 2 requests get 500

    post_webhook(
        &app.base_url,
        &format!("{sink_url}/hook"),
        serde_json::json!({ "retry": "me" }),
    )
    .await;

    wait_until(
        "sink to receive 3 requests",
        Duration::from_secs(10),
        || {
            let sink = sink.clone();
            async move { sink.hits() == 3 }
        },
    )
    .await;
    assert_eq!(sink.hits(), 3, "delivered after exactly 3 attempts");

    // Same payload body on every attempt.
    for body in sink.bodies() {
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({ "retry": "me" })
        );
    }

    app.shutdown().await;
}

/// (c) Always-500 sink → job lands in the DLQ after max_attempts; manual
/// DLQ retry requeues it and delivery succeeds once the sink recovers.
#[tokio::test]
async fn exhausted_retries_land_in_dlq_and_manual_retry_redelivers() {
    let dir = tempfile::tempdir().unwrap();
    let app = spawn_app(test_config(db_url(dir.path()))).await;
    let (sink_url, sink) = spawn_sink(usize::MAX).await; // always 500 for now

    let id = post_webhook(
        &app.base_url,
        &format!("{sink_url}/hook"),
        serde_json::json!({ "doomed": true }),
    )
    .await;

    // After 3 attempts (max_attempts) the job must be dead and visible via GET /dlq.
    let client = reqwest::Client::new();
    wait_until("job to appear in GET /dlq", Duration::from_secs(10), || {
        let client = client.clone();
        let base = app.base_url.clone();
        async move {
            let resp = client.get(format!("{base}/dlq")).send().await.unwrap();
            let entries: Vec<serde_json::Value> = resp.json().await.unwrap();
            entries
                .iter()
                .any(|e| e["id"].as_str() == Some(&id.to_string()))
        }
    })
    .await;

    let resp = client
        .get(format!("{}/dlq", app.base_url))
        .send()
        .await
        .unwrap();
    let entries: Vec<serde_json::Value> = resp.json().await.unwrap();
    let entry = entries
        .iter()
        .find(|e| e["id"].as_str() == Some(&id.to_string()))
        .expect("job present in DLQ");
    assert_eq!(entry["attempts"].as_i64().unwrap(), 3);
    assert!(
        entry["last_error"].as_str().unwrap().contains("500"),
        "last_error records the final HTTP failure: {}",
        entry["last_error"]
    );
    assert_eq!(sink.hits(), 3, "exactly max_attempts delivery attempts");

    // The sink recovers; manual retry requeues the job (attempts reset to 0).
    sink.set_fail_until(0);
    let resp = client
        .post(format!("{}/dlq/{id}/retry", app.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body, serde_json::json!({ "requeued": true }));

    // The worker picks it up again and delivers → 4th request to the sink.
    wait_until(
        "sink to receive a 4th request",
        Duration::from_secs(10),
        || {
            let sink = sink.clone();
            async move { sink.hits() >= 4 }
        },
    )
    .await;
    assert_eq!(sink.hits(), 4);

    // And the DLQ is empty again.
    let resp = client
        .get(format!("{}/dlq", app.base_url))
        .send()
        .await
        .unwrap();
    let entries: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(
        entries
            .iter()
            .all(|e| e["id"].as_str() != Some(&id.to_string())),
        "redelivered job must leave the DLQ"
    );

    app.shutdown().await;
}
