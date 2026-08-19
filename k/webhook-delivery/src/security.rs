//! Security primitives for the webhook delivery service.
//!
//! - [`validate_destination`]: SSRF guard for user-supplied delivery URLs.
//! - [`sign_body`]: HMAC-SHA256 request signing so receivers can verify authenticity.
//! - [`enforce_size`]: payload size limit check.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

/// Errors produced by the security layer (SSRF guard, size limits, signing).
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    /// The destination string is not a valid absolute URL (or has no host).
    #[error("destination URL is invalid: {0}")]
    InvalidUrl(String),
    /// The URL scheme is not `http` or `https`.
    #[error("URL scheme '{0}' is not allowed; only http and https are permitted")]
    SchemeNotAllowed(String),
    /// The URL contains userinfo credentials (`user:pass@host`), which is not allowed.
    #[error("destination URL must not contain credentials (userinfo)")]
    CredentialsNotAllowed,
    /// The destination hostname could not be resolved to any IP address.
    #[error("destination host could not be resolved: {0}")]
    UnresolvableHost(String),
    /// The destination resolves to a blocked IP (loopback, private, link-local,
    /// CGNAT, multicast, unspecified, ...). Classic SSRF target.
    #[error("destination resolves to blocked address {0} (private/loopback/link-local/reserved)")]
    PrivateAddressBlocked(IpAddr),
    /// The request body exceeds the configured maximum payload size.
    #[error("payload size {len} bytes exceeds the maximum of {max} bytes")]
    PayloadTooLarge { len: usize, max: usize },
}

/// Validate a user-supplied destination URL for safe outbound delivery.
///
/// Structural checks (always applied):
/// 1. Must parse as an absolute URL.
/// 2. Scheme must be `http` or `https`.
/// 3. A host must be present, and the URL must not carry credentials
///    (username must be empty, password must be absent).
///
/// Network checks (skipped when `allow_private` is true, e.g. dev/tests):
/// 4. The host is resolved to candidate IPs (IP literals are used directly;
///    domains go through DNS on port 443 for https, 80 for http, unless the
///    URL carries an explicit port).
/// 5. If ANY candidate IP is blocked (loopback, private, link-local, CGNAT,
///    multicast, unspecified, IPv4-mapped IPv6 wrapping such an address),
///    the URL is rejected with [`SecurityError::PrivateAddressBlocked`].
pub async fn validate_destination(
    url_str: &str,
    allow_private: bool,
) -> Result<Url, SecurityError> {
    // 1. Parse; require an absolute URL.
    let url = Url::parse(url_str).map_err(|e| SecurityError::InvalidUrl(e.to_string()))?;

    // 2. Scheme allow-list.
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(SecurityError::SchemeNotAllowed(other.to_string())),
    }

    // 3a. Host must be present.
    let host = url
        .host()
        .ok_or_else(|| SecurityError::InvalidUrl("missing host".to_string()))?;

    // 3b. No credentials in the URL.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(SecurityError::CredentialsNotAllowed);
    }

    // 4. Structural checks done: nothing more to do when private destinations
    //    are explicitly allowed (dev/test mode).
    if allow_private {
        return Ok(url);
    }

    // 5. Collect candidate IPs for the host.
    let candidates: Vec<IpAddr> = match host {
        url::Host::Ipv4(v4) => vec![IpAddr::V4(v4)],
        url::Host::Ipv6(v6) => vec![IpAddr::V6(v6)],
        url::Host::Domain(domain) => {
            let port = match url.port() {
                Some(p) => p,
                None => {
                    if url.scheme() == "https" {
                        443
                    } else {
                        80
                    }
                }
            };
            tokio::net::lookup_host((domain, port))
                .await
                .map_err(|e| SecurityError::UnresolvableHost(format!("{domain}: {e}")))?
                .map(|sock_addr| sock_addr.ip())
                .collect()
        }
    };

    // 6. Reject if ANY candidate IP is blocked.
    for ip in candidates {
        if ip_is_blocked(&ip) {
            return Err(SecurityError::PrivateAddressBlocked(ip));
        }
    }

    Ok(url)
}

/// Sign a request body with HMAC-SHA256, returning the
/// `sha256=<hex>` value for the `X-Webhook-Signature` header.
pub fn sign_body(secret: &str, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Enforce the configured maximum payload size.
pub fn enforce_size(len: usize, max: usize) -> Result<(), SecurityError> {
    if len > max {
        Err(SecurityError::PayloadTooLarge { len, max })
    } else {
        Ok(())
    }
}

/// Returns true if the IP address must not be used as a delivery destination.
fn ip_is_blocked(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_blocked(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) — apply the v4 rules.
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return ipv4_is_blocked(&mapped_v4);
            }
            ipv6_is_blocked(v6)
        }
    }
}

fn ipv4_is_blocked(v4: &Ipv4Addr) -> bool {
    v4.is_private() // RFC1918: 10/8, 172.16/12, 192.168/16
        || v4.is_loopback() // 127.0.0.0/8
        || v4.is_link_local() // 169.254.0.0/16 — includes cloud metadata endpoints
        || v4.is_multicast() // 224.0.0.0/4
        || v4.is_unspecified() // 0.0.0.0
        || v4.is_broadcast() // 255.255.255.255
        || is_cgnat(v4) // 100.64.0.0/10 — std has no helper for this
}

/// RFC 6598 shared address space (Carrier-Grade NAT): 100.64.0.0/10.
fn is_cgnat(v4: &Ipv4Addr) -> bool {
    let octets = v4.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

fn ipv6_is_blocked(v6: &Ipv6Addr) -> bool {
    v6.is_loopback() // ::1
        || v6.is_unspecified() // ::
        || v6.is_multicast() // ff00::/8
        || is_v6_link_local(v6) // fe80::/10
        || is_v6_unique_local(v6) // fc00::/7
}

/// Link-local unicast fe80::/10 (std's is_unicast_link_local is unstable).
fn is_v6_link_local(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// Unique-local fc00::/7 (std's is_unique_local is unstable).
fn is_v6_unique_local(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assert the URL is rejected specifically because of a blocked IP.
    /// (All inputs are IP literals, so no DNS lookup happens.)
    async fn assert_blocked_ip(url: &str) {
        match validate_destination(url, false).await {
            Err(SecurityError::PrivateAddressBlocked(_)) => {}
            other => panic!("expected PrivateAddressBlocked for {url}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_loopback_v4() {
        assert_blocked_ip("http://127.0.0.1/x").await;
    }

    #[tokio::test]
    async fn rejects_loopback_v6() {
        assert_blocked_ip("http://[::1]/").await;
    }

    #[tokio::test]
    async fn rejects_private_v4_ranges() {
        assert_blocked_ip("http://10.0.0.5/").await;
        assert_blocked_ip("http://172.16.0.1/").await;
        assert_blocked_ip("http://192.168.1.1/").await;
    }

    #[tokio::test]
    async fn rejects_link_local_cloud_metadata() {
        assert_blocked_ip("http://169.254.169.254/latest/meta-data").await;
    }

    #[tokio::test]
    async fn rejects_v6_link_local_and_unique_local() {
        assert_blocked_ip("http://[fe80::1]/").await;
        assert_blocked_ip("http://[fc00::1]/").await;
    }

    #[tokio::test]
    async fn rejects_ipv4_mapped_ipv6() {
        assert_blocked_ip("http://[::ffff:127.0.0.1]/").await;
    }

    #[tokio::test]
    async fn rejects_cgnat_range() {
        assert_blocked_ip("http://100.64.1.1/").await;
    }

    #[tokio::test]
    async fn rejects_unspecified_v4() {
        assert_blocked_ip("http://0.0.0.0/").await;
    }

    #[tokio::test]
    async fn rejects_credentials_in_url() {
        let err = validate_destination("http://user:pass@example.com/", false)
            .await
            .expect_err("userinfo must be rejected");
        assert!(
            matches!(err, SecurityError::CredentialsNotAllowed),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_non_http_schemes() {
        let err = validate_destination("ftp://example.com/", false)
            .await
            .expect_err("ftp scheme must be rejected");
        assert!(
            matches!(err, SecurityError::SchemeNotAllowed(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_non_absolute_url() {
        let err = validate_destination("not-a-url", false)
            .await
            .expect_err("relative URL must be rejected");
        assert!(matches!(err, SecurityError::InvalidUrl(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn accepts_private_when_allowed() {
        let url = validate_destination("http://127.0.0.1:9000/hook", true)
            .await
            .expect("loopback should be accepted with allow_private=true");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(9000));

        validate_destination("http://[::1]:8080/", true)
            .await
            .expect("v6 loopback should be accepted with allow_private=true");
    }

    #[tokio::test]
    async fn accepts_domain_with_allow_private_without_dns() {
        // Structural checks only; no DNS resolution is performed.
        let url = validate_destination("https://example.com/path", true)
            .await
            .expect("domain should pass structural checks with allow_private=true");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.path(), "/path");
    }

    #[test]
    fn sign_body_matches_known_vector() {
        let sig = sign_body("key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            sig,
            "sha256=f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn sign_body_has_sha256_prefix() {
        let sig = sign_body("secret", b"{}");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64);
    }

    #[test]
    fn enforce_size_rejects_over_max() {
        let err = enforce_size(101, 100).expect_err("len > max must fail");
        assert!(
            matches!(err, SecurityError::PayloadTooLarge { len: 101, max: 100 }),
            "got {err:?}"
        );
    }

    #[test]
    fn enforce_size_accepts_exactly_max_and_below() {
        assert!(enforce_size(100, 100).is_ok());
        assert!(enforce_size(0, 100).is_ok());
    }
}
