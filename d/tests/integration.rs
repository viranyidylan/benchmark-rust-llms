use axum::{
    body::Body,
    http::{header, HeaderValue, Request, StatusCode},
};
use http_body_util::BodyExt;
use tower::ServiceExt;

use webhook_delivery::{build_router, AppState, Config, Db};

/// In-memory app with fixed API key and private delivery allowed.
fn app_with(max_attempts: u32) -> (axum::Router, Db) {
    let db = Db::open_in_memory().unwrap();
    let cfg = std::sync::Arc::new(Config::default_test(max_attempts));
    webhook_delivery::set_api_key("testkey".into());
    let state = AppState { db: db.clone(), config: cfg };
    (build_router(state), db)
}

fn body(s: &str) -> Body {
    Body::from(s.to_string())
}

#[tokio::test]
async fn accepts_valid_webhook_and_returns_202() {
    let (app, _db) = app_with(5);
    let key = HeaderValue::from_static("testkey");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-api-key", &key)
                .body(body(r#"{"data":{"a":1},"destination":"https://example.com/hook"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["status"], "queued");
}

#[tokio::test]
async fn rejects_missing_api_key_with_401() {
    let (app, _db) = app_with(5);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook")
                .header(header::CONTENT_TYPE, "application/json")
                .body(body(r#"{"data":{},"destination":"https://example.com/hook"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_non_http_destination_with_400() {
    let (app, _db) = app_with(5);
    let key = HeaderValue::from_static("testkey");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-api-key", &key)
                .body(body(r#"{"data":{},"destination":"ftp://example.com"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejects_malformed_json_body_with_422() {
    let (app, _db) = app_with(5);
    let key = HeaderValue::from_static("testkey");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-api-key", &key)
                .body(body("not json {{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_client_error());
}
