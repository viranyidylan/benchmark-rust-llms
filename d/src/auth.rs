use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::OnceLock;

static API_KEY: OnceLock<String> = OnceLock::new();

pub fn set_api_key(key: String) {
    let _ = API_KEY.set(key);
}

/// Middleware that requires a valid `X-Api-Key` header.
pub async fn require_api_key(req: Request, next: Next) -> Result<Response, Response> {
    let expected = API_KEY.get().cloned().unwrap_or_default();
    let provided = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok());

    match provided {
        Some(k) if k == expected => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED.into_response()),
    }
}
