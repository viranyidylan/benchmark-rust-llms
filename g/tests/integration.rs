use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use axum::{extract::State, http::{HeaderMap, StatusCode}, routing::post, Router};
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::Semaphore};
use webhook_delivery::{config::Config, db, deliver, routes, security, worker, AppState};

fn test_config(db_path: &PathBuf, allow_private: bool, max_attempts: i64) -> Arc<Config> {
    Arc::new(Config {
        database_url: format!("sqlite://{}", db_path.display()),
        allow_private_destinations: allow_private,
        max_attempts,
        retry_base_ms: 20,
        retry_max_ms: 100,
        poll_interval_ms: 10,
        visibility_timeout_secs: 5,
        delivery_timeout_secs: 2,
        max_concurrent_deliveries: 16,
        db_max_connections: 4,
        ..Config::default()
    })
}

async fn start_service(cfg: Arc<Config>) -> (reqwest::Client, String) {
    let pool = db::init_pool(&cfg.database_url, cfg.db_max_connections)
        .await
        .expect("db init");
    let state = AppState {
        cfg: cfg.clone(),
        pool,
        http: deliver::build_http_client(cfg.delivery_timeout_secs),
        sema: Arc::new(Semaphore::new(cfg.max_concurrent_deliveries)),
    };
    tokio::spawn(worker::run(state.clone()));

    let app = routes::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (reqwest::Client::new(), format!("http://{addr}"))
}

#[derive(Clone)]
struct CapturedRequest {
    id: String,
    timestamp: String,
    signature: String,
    body: String,
}

struct ReceiverState {
    attempts: AtomicUsize,
    /// 1-based attempts numbered <= fail_until receive a 500.
    fail_until: AtomicUsize,
    captured: Mutex<Vec<CapturedRequest>>,
}

fn header_str(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

async fn spawn_receiver(state: Arc<ReceiverState>) -> SocketAddr {
    let app = Router::new().route(
        "/hook",
        post(
            |State(s): State<Arc<ReceiverState>>, headers: HeaderMap, body: String| async move {
                let n = s.attempts.fetch_add(1, Ordering::SeqCst) + 1;
                s.captured.lock().unwrap().push(CapturedRequest {
                    id: header_str(&headers, "x-webhook-id"),
                    timestamp: header_str(&headers, "x-webhook-timestamp"),
                    signature: header_str(&headers, "x-webhook-signature"),
                    body,
                });
                if n <= s.fail_until.load(Ordering::SeqCst) {
                    StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    StatusCode::OK
                }
            },
        ),
    )
    .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

async fn wait_for_status(
    client: &reqwest::Client,
    base: &str,
    id: &str,
    want: &str,
    timeout: Duration,
) -> Value {
    let start = Instant::now();
    loop {
        let resp = client.get(format!("{base}/webhook/{id}")).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        if body["status"] == want {
            return body;
        }
        assert!(
            start.elapsed() < timeout,
            "timed out waiting for status '{want}', last state: {body}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delivers_with_retries_and_valid_signature() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(&dir.path().join("t1.db"), true, 5);
    let (client, base) = start_service(cfg.clone()).await;

    let receiver = Arc::new(ReceiverState {
        attempts: AtomicUsize::new(0),
        fail_until: AtomicUsize::new(2), // first two attempts fail, third succeeds
        captured: Mutex::new(Vec::new()),
    });
    let receiver_addr = spawn_receiver(receiver.clone()).await;

    let data = json!({ "event": "order.created", "count": 42, "nested": { "ok": true } });
    let resp = client
        .post(format!("{base}/webhook"))
        .json(&json!({
            "data": data,
            "destination": format!("http://{receiver_addr}/hook"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let body: Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["status"], "pending");

    let status = wait_for_status(&client, &base, &id, "delivered", Duration::from_secs(15)).await;
    assert_eq!(status["attempts"], 3, "two failures then one success");

    let captured = receiver.captured.lock().unwrap();
    assert_eq!(captured.len(), 3);
    let cap = captured.last().unwrap();

    let delivered: Value = serde_json::from_str(&cap.body).unwrap();
    assert_eq!(delivered, data, "exact payload is delivered");
    assert_eq!(cap.id, id, "X-Webhook-Id carries the delivery id for dedupe");

    let expected = security::sign_payload(&cfg.signing_secret, &cap.timestamp, &cap.body);
    assert_eq!(cap.signature, expected, "HMAC signature is valid");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dead_letters_after_max_attempts_and_requeues() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(&dir.path().join("t2.db"), true, 3);
    let (client, base) = start_service(cfg).await;

    let receiver = Arc::new(ReceiverState {
        attempts: AtomicUsize::new(0),
        fail_until: AtomicUsize::new(usize::MAX), // always fail
        captured: Mutex::new(Vec::new()),
    });
    let receiver_addr = spawn_receiver(receiver.clone()).await;

    let resp = client
        .post(format!("{base}/webhook"))
        .json(&json!({
            "data": { "event": "will.fail" },
            "destination": format!("http://{receiver_addr}/hook"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let body: Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();

    let status =
        wait_for_status(&client, &base, &id, "dead_lettered", Duration::from_secs(15)).await;
    assert_eq!(status["attempts"], 3);
    assert!(status["last_error"].as_str().is_some_and(|e| !e.is_empty()));

    let dlq: Value = client.get(format!("{base}/dlq")).send().await.unwrap().json().await.unwrap();
    assert_eq!(dlq["count"], 1);
    assert_eq!(dlq["deliveries"][0]["id"], *id.as_str());

    // Requeue: destination recovers, delivery must succeed.
    receiver.fail_until.store(0, Ordering::SeqCst);
    let resp = client
        .post(format!("{base}/dlq/{id}/requeue"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let status = wait_for_status(&client, &base, &id, "delivered", Duration::from_secs(15)).await;
    assert!(status["attempts"].as_i64().unwrap() >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_private_destinations_unless_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(&dir.path().join("t3.db"), false, 3);
    let (client, base) = start_service(cfg).await;

    for destination in [
        "http://127.0.0.1:8080/hook",
        "http://localhost/hook",
        "http://10.0.0.5/hook",
        "http://169.254.169.254/latest/meta-data",
    ] {
        let resp = client
            .post(format!("{base}/webhook"))
            .json(&json!({ "data": { "a": 1 }, "destination": destination }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 422, "expected {destination} to be blocked");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validates_request_shape() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(&dir.path().join("t4.db"), true, 3);
    let (client, base) = start_service(cfg).await;

    let missing_destination = client
        .post(format!("{base}/webhook"))
        .json(&json!({ "data": { "a": 1 } }))
        .send()
        .await
        .unwrap();
    assert_eq!(missing_destination.status(), 400);

    let bad_url = client
        .post(format!("{base}/webhook"))
        .json(&json!({ "data": { "a": 1 }, "destination": "not a url" }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_url.status(), 422);

    let bad_scheme = client
        .post(format!("{base}/webhook"))
        .json(&json!({ "data": { "a": 1 }, "destination": "file:///etc/passwd" }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_scheme.status(), 422);

    let unknown = client.get(format!("{base}/webhook/does-not-exist")).send().await.unwrap();
    assert_eq!(unknown.status(), 404);

    let health: Value = client.get(format!("{base}/healthz")).send().await.unwrap().json().await.unwrap();
    assert_eq!(health["status"], "ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforces_payload_size_limit() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(&dir.path().join("t5.db"), true, 3);
    let small_limit = 128usize;
    Arc::get_mut(&mut cfg).unwrap().max_payload_bytes = small_limit;
    let (client, base) = start_service(cfg).await;

    let big = "x".repeat(small_limit * 2);
    let resp = client
        .post(format!("{base}/webhook"))
        .json(&json!({ "data": { "blob": big }, "destination": "http://example.com/hook" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
}
