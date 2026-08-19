//! Authentication (PLAN.md, T6).

use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Constant-time byte comparison (timing-safe).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Extract the token from an `Authorization: Bearer <token>` header.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("Authorization")?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
}

/// Accept if any of `keys` matches the bearer token (constant-time).
/// An empty `keys` list never authenticates.
pub fn check_bearer(headers: &HeaderMap, keys: &[String]) -> bool {
    match bearer_token(headers) {
        Some(token) => keys
            .iter()
            .any(|k| constant_time_eq(token.as_bytes(), k.as_bytes())),
        None => false,
    }
}

/// Accept if `X-Webhook-Signature: sha256=<hex>` matches the HMAC-SHA256 of
/// the raw request body under `secret` (constant-time hex compare).
pub fn check_hmac(headers: &HeaderMap, raw_body: &[u8], secret: &str) -> bool {
    let header = match headers.get("X-Webhook-Signature") {
        Some(v) => v.to_str().ok(),
        None => return false,
    };
    let header = match header {
        Some(h) => h,
        None => return false,
    };
    let provided = match header.strip_prefix("sha256=") {
        Some(h) => h,
        None => return false,
    };
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(raw_body);
    let expected = mac.finalize().into_bytes();
    let provided = hex_decode(provided).unwrap_or_default();
    constant_time_eq(&provided, expected.as_slice())
}

/// Full request authorization for `/webhook` (PLAN.md §4):
/// - if `hmac_secret` is configured and the request carries an
///   `X-Webhook-Signature` header: the signature must be valid;
/// - otherwise (no secret, or header absent): fall back to bearer auth.
pub fn authorized(
    headers: &HeaderMap,
    raw_body: &[u8],
    hmac_secret: &Option<String>,
    api_keys: &[String],
) -> bool {
    match hmac_secret {
        Some(secret) if headers.contains_key("X-Webhook-Signature") => {
            check_hmac(headers, raw_body, secret)
        }
        _ => check_bearer(headers, api_keys),
    }
}

/// Admin authorization (PLAN.md, T8): bearer token must equal `admin_key`.
pub fn admin_authorized(headers: &HeaderMap, admin_key: &str) -> bool {
    match bearer_token(headers) {
        Some(token) => constant_time_eq(token.as_bytes(), admin_key.as_bytes()),
        None => false,
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks(2) {
        out.push(hex_nib(pair[0])? << 4 | hex_nib(pair[1])?);
    }
    Some(out)
}

fn hex_nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            name.parse::<axum::http::header::HeaderName>().unwrap(),
            value.parse().unwrap(),
        );
        h
    }

    #[test]
    fn constant_time_eq_matches() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn bearer_accepts_valid_key() {
        let h = headers_with("Authorization", "Bearer key-1");
        assert!(check_bearer(
            &h,
            &["key-1".to_string(), "key-2".to_string()]
        ));
        let h2 = headers_with("Authorization", "Bearer key-2");
        assert!(check_bearer(
            &h2,
            &["key-1".to_string(), "key-2".to_string()]
        ));
    }

    #[test]
    fn bearer_rejects_wrong_key_missing_header_empty_keys() {
        let keys = ["key-1".to_string()];
        let wrong = headers_with("Authorization", "Bearer nope");
        assert!(!check_bearer(&wrong, &keys));
        assert!(!check_bearer(&HeaderMap::new(), &keys));
        let good = headers_with("Authorization", "Bearer key-1");
        assert!(!check_bearer(&good, &[]));
        // Non-bearer scheme must not authenticate.
        let basic = headers_with("Authorization", "Basic key-1");
        assert!(!check_bearer(&basic, &keys));
    }

    fn sign(body: &[u8], secret: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let hex: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("sha256={hex}")
    }

    #[test]
    fn hmac_accepts_valid_signature() {
        let body = br#"{"data": 1}"#;
        let h = headers_with("X-Webhook-Signature", &sign(body, "s3cret"));
        assert!(check_hmac(&h, body, "s3cret"));
    }

    #[test]
    fn hmac_rejects_tampered_body_and_bad_signature() {
        let body = br#"{"data": 1}"#;
        let h = headers_with("X-Webhook-Signature", &sign(body, "s3cret"));
        assert!(!check_hmac(&h, br#"{"data": 2}"#, "s3cret"));
        let other = headers_with("X-Webhook-Signature", &sign(body, "other"));
        assert!(!check_hmac(&other, body, "s3cret"));
        // Missing header.
        assert!(!check_hmac(&HeaderMap::new(), body, "s3cret"));
        // Garbage hex.
        let bad = headers_with("X-Webhook-Signature", "sha256=zz");
        assert!(!check_hmac(&bad, body, "s3cret"));
        // Wrong prefix.
        let prefix = headers_with(
            "X-Webhook-Signature",
            &sign(body, "s3cret").replace("sha256=", "hmac="),
        );
        assert!(!check_hmac(&prefix, body, "s3cret"));
    }

    #[test]
    fn authorized_falls_back_to_bearer_when_signature_header_missing() {
        let body = b"{}";
        let secret = Some("s3cret".to_string());
        let keys = ["key-1".to_string()];
        // No signature header -> bearer path.
        let bearer = headers_with("Authorization", "Bearer key-1");
        assert!(authorized(&bearer, body, &secret, &keys));
        // Signature header present but invalid -> NO fallback, rejected.
        let bad_sig = headers_with("X-Webhook-Signature", "sha256=00");
        assert!(!authorized(&bad_sig, body, &secret, &keys));
        // Signature header valid -> accepted without bearer.
        let good_sig = headers_with("X-Webhook-Signature", &sign(body, "s3cret"));
        assert!(authorized(&good_sig, body, &secret, &keys));
        // No secret configured -> bearer only.
        let no_secret: Option<String> = None;
        assert!(authorized(&bearer, body, &no_secret, &keys));
        assert!(!authorized(&good_sig, body, &no_secret, &keys));
    }

    #[test]
    fn admin_authorized_requires_exact_admin_key() {
        let ok = headers_with("Authorization", "Bearer admin-1");
        assert!(admin_authorized(&ok, "admin-1"));
        let wrong = headers_with("Authorization", "Bearer nope");
        assert!(!admin_authorized(&wrong, "admin-1"));
        assert!(!admin_authorized(&HeaderMap::new(), "admin-1"));
    }
}
