//! Integration tests for the HTTP API (Step 4): POST /webhook, GET /health,
//! and the DLQ endpoints.
//!
//! Each test runs the real router against a throwaway SQLite database in a
//! temp file. (A shared in-memory database would require a max_connections=1
//! pool, which serializes the concurrent connections a running server makes;
//! a temp file per test is simpler and just as isolated.)

use std::net::SocketAddr;
use std::sync::Arc;

use uuid::Uuid;
use webhook_delivery::config::Config;
use webhook_delivery::db::Db;
use webhook_delivery::routes::{build_router, AppState};

/// A config with fast, test-friendly values; the caller overrides the fields
/// relevant to its scenario (database_url, allow_private_destinations, ...).
fn test_config(database_url: String) -> Config {
    Config {
        database_url,
        bind_addr: "127.0.0.1:0".to_string(),
        max_attempts: 8,
        base_delay_ms: 50,
        max_delay_ms: 200,
        request_timeout_secs: 5,
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

/// Connect the DB, build the router, and serve it on an ephemeral loopback
/// port in a background task. Returns the base URL (e.g. http://127.0.0.1:PORT).
async fn spawn_app(config: Config) -> String {
    let db = Db::connect(&config).await.expect("connect test db");
    let state = AppState {
        db,
        config: Arc::new(config),
    };
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });

    format!("http://{addr}")
}

fn webhook_body() -> serde_json::Value {
    serde_json::json!({
        "data": { "hello": "world" },
        "destination": "http://127.0.0.1:1/hook"
    })
}

/// (a) Valid request with allow_private_destinations=true → 202 + uuid id.
#[tokio::test]
async fn post_webhook_accepts_and_returns_uuid() {
    let dir = tempfile::tempdir().unwrap();
    let base = spawn_app(test_config(db_url(dir.path()))).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/webhook"))
        .json(&webhook_body())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);

    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().expect("response has string id");
    Uuid::parse_str(id).expect("id parses as uuid");
}

/// (b) Private/loopback destination with allow_private_destinations=false → 400.
#[tokio::test]
async fn post_webhook_rejects_private_destination_when_not_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(db_url(dir.path()));
    config.allow_private_destinations = false;
    let base = spawn_app(config).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/webhook"))
        .json(&webhook_body())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("blocked"));
}

/// (c1) Malformed JSON → 400.
#[tokio::test]
async fn post_webhook_rejects_invalid_json() {
    let dir = tempfile::tempdir().unwrap();
    let base = spawn_app(test_config(db_url(dir.path()))).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/webhook"))
        .header("content-type", "application/json")
        .body("{not valid json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// (c2) Valid JSON but missing `destination` field → 400.
#[tokio::test]
async fn post_webhook_rejects_missing_destination() {
    let dir = tempfile::tempdir().unwrap();
    let base = spawn_app(test_config(db_url(dir.path()))).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/webhook"))
        .json(&serde_json::json!({ "data": { "hello": "world" } }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status == reqwest::StatusCode::BAD_REQUEST
            || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400/422, got {status}"
    );
}

/// (d) Body larger than max_payload_bytes → 413.
#[tokio::test]
async fn post_webhook_rejects_oversize_payload() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(db_url(dir.path()));
    config.max_payload_bytes = 64;
    let base = spawn_app(config).await;

    let big_body = "x".repeat(10 * 1024); // 10 KiB > 64 B
    let resp = reqwest::Client::new()
        .post(format!("{base}/webhook"))
        .header("content-type", "application/json")
        .body(big_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
}

/// (e) health + DLQ endpoints on an empty database.
#[tokio::test]
async fn health_and_empty_dlq_endpoints() {
    let dir = tempfile::tempdir().unwrap();
    let base = spawn_app(test_config(db_url(dir.path()))).await;
    let client = reqwest::Client::new();

    // GET /health → 200 {"status":"ok"}
    let resp = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body, serde_json::json!({ "status": "ok" }));

    // GET /dlq → 200 []
    let resp = client.get(format!("{base}/dlq")).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body, serde_json::json!([]));

    // POST /dlq/<random-uuid>/retry → 404
    let resp = client
        .post(format!("{base}/dlq/{}/retry", Uuid::new_v4()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].is_string());
}

/// A webhook accepted via the API is actually persisted as a pending job
/// (durability-before-ack guarantee).
#[tokio::test]
async fn accepted_webhook_is_persisted_as_pending() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(db_url(dir.path()));
    let base = spawn_app(config.clone()).await;
    let db = Db::connect(&config).await.unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{base}/webhook"))
        .json(&webhook_body())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    let claimed = db.claim_due_jobs(10).await.unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id, id);
    assert_eq!(claimed[0].destination, "http://127.0.0.1:1/hook");
    assert_eq!(claimed[0].payload, serde_json::json!({ "hello": "world" }));
    assert_eq!(claimed[0].attempts, 1); // claim increments
    assert_eq!(claimed[0].max_attempts, config.max_attempts);
}
