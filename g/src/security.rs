use std::net::{IpAddr, SocketAddr};

use url::{Host, Url};

/// Compute the signature header value for an outbound delivery.
///
/// The signed material is `"{timestamp}.{body}"` with an HMAC-SHA256 over the
/// shared secret. Receivers should verify the signature AND reject timestamps
/// outside a small window (e.g. 5 minutes) to prevent replay attacks.
pub fn sign_payload(secret: &str, timestamp: &str, body: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    format!("v1={}", hex::encode(mac.finalize().into_bytes()))
}

/// True if the address is globally routable, i.e. not loopback, private,
/// link-local, unspecified, multicast, broadcast, documentation or CGNAT.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000; // 100.64.0.0/10
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || cgnat)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local())
        }
    }
}

/// Validate an outbound destination URL (SSRF guard).
///
/// - must parse, be absolute, and use http or https
/// - must not carry credentials
/// - unless `allow_private` is set, the host must resolve (or literally be) to
///   public IP addresses only
///
/// The check is performed again immediately before every delivery attempt, so
/// a hostname that flips to a private address between enqueue and delivery is
/// still blocked at delivery time.
pub async fn validate_destination(raw: &str, allow_private: bool) -> Result<(), String> {
    if raw.len() > 2048 {
        return Err("destination URL is too long".to_string());
    }

    let url = Url::parse(raw).map_err(|e| format!("invalid destination URL: {e}"))?;

    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "unsupported destination scheme '{other}': only http and https are allowed"
            ))
        }
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err("destination URL must not contain credentials".to_string());
    }

    if allow_private {
        return Ok(());
    }

    let host = url.host().ok_or_else(|| "destination URL has no host".to_string())?;
    let port = url.port_or_known_default().unwrap_or(80);

    let addrs: Vec<SocketAddr> = match host {
        Host::Ipv4(ip) => vec![SocketAddr::from((ip, port))],
        Host::Ipv6(ip) => vec![SocketAddr::from((ip, port))],
        Host::Domain(domain) => tokio::net::lookup_host((domain, port))
            .await
            .map_err(|e| format!("DNS resolution failed for '{domain}': {e}"))?
            .collect(),
    };

    if addrs.is_empty() {
        return Err(format!("no addresses resolved for '{host}'"));
    }

    for addr in &addrs {
        if !is_public_ip(addr.ip()) {
            return Err(format!(
                "destination host resolves to a blocked (non-public) address: {}",
                addr.ip()
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn public_and_private_ips() {
        for public in ["8.8.8.8", "1.1.1.1", "93.184.216.34"] {
            assert!(is_public_ip(public.parse::<Ipv4Addr>().unwrap().into()));
        }
        for blocked in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "100.64.0.1",
            "192.0.2.1",
        ] {
            assert!(!is_public_ip(blocked.parse::<Ipv4Addr>().unwrap().into()));
        }

        assert!(is_public_ip("2606:4700::1111".parse::<Ipv6Addr>().unwrap().into()));
        for blocked in [
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public_ip(blocked.parse::<Ipv6Addr>().unwrap().into()));
        }
    }

    #[test]
    fn signature_is_deterministic_and_keyed() {
        let a = sign_payload("secret", "1700000000", r#"{"a":1}"#);
        let b = sign_payload("secret", "1700000000", r#"{"a":1}"#);
        let c = sign_payload("other", "1700000000", r#"{"a":1}"#);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("v1="));
        assert_eq!(a.len(), 3 + 64);
    }
}
