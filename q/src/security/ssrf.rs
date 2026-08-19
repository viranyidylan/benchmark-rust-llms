//! SSRF protection for outbound webhook destinations (PLAN.md, T4).
//!
//! All checks are synchronous; async callers should run [`SsrfPolicy::validate`]
//! inside `tokio::task::spawn_blocking`.

use std::net::{IpAddr, ToSocketAddrs};

use thiserror::Error;
use url::Url;

/// Errors from SSRF validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SsrfError {
    #[error("unsupported scheme: expected http or https")]
    BadScheme,
    #[error("url has no host")]
    MissingHost,
    #[error("url must not contain userinfo")]
    Userinfo,
    #[error("port {0} not allowed")]
    BadPort(u16),
    #[error("resolved address is a blocked private/reserved IP: {0}")]
    PrivateIp(IpAddr),
    #[error("dns resolution failed for {0}")]
    ResolutionFailed(String),
}

/// SSRF policy for outbound delivery.
#[derive(Debug, Clone)]
pub struct SsrfPolicy {
    /// When `true`, private/reserved destination IPs are allowed (e.g. for
    /// local development against a LAN hook).
    pub allow_private: bool,
    /// Explicit ports accepted on the URL. Default: `[80, 443]`.
    pub allowed_ports: Vec<u16>,
}

impl Default for SsrfPolicy {
    fn default() -> Self {
        Self {
            allow_private: false,
            allowed_ports: vec![80, 443],
        }
    }
}

impl SsrfPolicy {
    pub fn new(allow_private: bool, allowed_ports: Vec<u16>) -> Self {
        Self {
            allow_private,
            allowed_ports,
        }
    }

    /// Static checks on the URL (no DNS involved):
    /// scheme must be http/https, host must be present, no userinfo, and an
    /// explicit port (if any) must be in `allowed_ports`.
    pub fn validate_url(&self, url: &Url) -> Result<(), SsrfError> {
        match url.scheme() {
            "http" | "https" => {}
            _ => return Err(SsrfError::BadScheme),
        }
        match url.host_str() {
            Some(h) if !h.is_empty() => {}
            _ => return Err(SsrfError::MissingHost),
        }
        if url.username() != "" || url.password().is_some() {
            return Err(SsrfError::Userinfo);
        }
        if let Some(port) = url.port() {
            if !self.allowed_ports.contains(&port) {
                return Err(SsrfError::BadPort(port));
            }
        }
        Ok(())
    }

    /// Full validation: static URL checks, then DNS resolution; when
    /// `allow_private` is `false`, every resolved IP must pass
    /// [`is_blocked_ip`]. Returns the resolved addresses.
    pub fn validate(&self, url: &Url, resolver: &dyn IpResolver) -> Result<Vec<IpAddr>, SsrfError> {
        self.validate_url(url)?;
        let host = url.host_str().unwrap_or_default().to_string();
        let ips = resolver
            .lookup(&host)
            .map_err(SsrfError::ResolutionFailed)?;
        if !self.allow_private {
            for ip in &ips {
                if is_blocked_ip(*ip) {
                    return Err(SsrfError::PrivateIp(*ip));
                }
            }
        }
        Ok(ips)
    }
}

/// Synchronous DNS resolver abstraction so tests can inject fixed addresses.
pub trait IpResolver {
    fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, String>;
}

/// System resolver via `std::net::ToSocketAddrs`.
#[derive(Debug)]
pub struct SystemResolver;

impl IpResolver for SystemResolver {
    fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        // Port is irrelevant for resolution; use 443.
        let addrs: Vec<IpAddr> = (host, 443u16)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .map(|sa| sa.ip())
            .collect();
        if addrs.is_empty() {
            return Err(format!("no addresses for {host}"));
        }
        Ok(addrs)
    }
}

/// Returns `true` for IPs that must never be a webhook destination when
/// `allow_private` is off:
/// 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10 (CGNAT), 127.0.0.0/8, 169.254.0.0/16,
/// 172.16.0.0/12, 192.168.0.0/16, 255.0.0.0/8, `::`, `::1`, fc00::/7 (ULA),
/// fe80::/10 (link-local), and IPv4-mapped IPv6 (`::ffff:a.b.c.d` — the
/// embedded IPv4 is checked).
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 0 // 0.0.0.0/8
                || o[0] == 10 // 10.0.0.0/8
                || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64.0.0/10 (CGNAT)
                || o[0] == 127 // 127.0.0.0/8
                || (o[0] == 169 && o[1] == 254) // 169.254.0.0/16
                || (o[0] == 172 && (16..=31).contains(&o[1])) // 172.16.0.0/12
                || (o[0] == 192 && o[1] == 168) // 192.168.0.0/16
                || o[0] == 255 // 255.0.0.0/8
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // IPv4-mapped (::ffff:a.b.c.d): check the embedded IPv4.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(mapped));
            }
            s.iter().all(|&x| x == 0) // ::
                || (s[0..7].iter().all(|&x| x == 0) && s[7] == 1) // ::1
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 (unique local)
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 (link-local)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedResolver(Vec<IpAddr>);
    impl IpResolver for FixedResolver {
        fn lookup(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
            Ok(self.0.clone())
        }
    }

    struct ErrResolver;
    impl IpResolver for ErrResolver {
        fn lookup(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
            Err("boom".to_string())
        }
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn policy() -> SsrfPolicy {
        SsrfPolicy::default()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_ip_allowed() {
        for s in [
            "93.184.216.34",
            "8.8.8.8",
            "100.128.0.1", // just outside CGNAT
            "172.32.0.1",  // just outside 172.16/12
            "fec0::1",     // just outside fe80::/10
            "::ffff:8.8.8.8",
        ] {
            let resolver = FixedResolver(vec![ip(s)]);
            assert_eq!(
                policy().validate(&url("https://example.com/hook"), &resolver),
                Ok(vec![ip(s)]),
                "{s} should be allowed"
            );
        }
    }

    #[test]
    fn each_blocked_range_rejected() {
        let blocked = [
            "0.0.0.1",
            "0.255.255.255",
            "10.0.0.1",
            "10.255.255.255",
            "100.64.0.1",
            "100.127.255.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.1",
            "192.168.1.1",
            "255.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456:789a::1",
            "fe80::1",
            "febf::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.1.1",
        ];
        for s in blocked {
            let resolver = FixedResolver(vec![ip(s)]);
            assert!(
                matches!(
                    policy().validate(&url("https://example.com/hook"), &resolver),
                    Err(SsrfError::PrivateIp(_))
                ),
                "{s} should be blocked"
            );
        }
    }

    #[test]
    fn allow_private_bypass() {
        let p = SsrfPolicy::new(true, vec![80, 443]);
        let resolver = FixedResolver(vec![ip("10.0.0.1"), ip("192.168.1.5")]);
        assert!(p
            .validate(&url("https://example.com/hook"), &resolver)
            .is_ok());
    }

    #[test]
    fn scheme_userinfo_port_cases() {
        assert!(matches!(
            policy().validate_url(&url("ftp://example.com/")),
            Err(SsrfError::BadScheme)
        ));
        assert!(matches!(
            policy().validate_url(&url("file:///etc/passwd")),
            Err(SsrfError::BadScheme)
        ));
        assert!(matches!(
            policy().validate_url(&url("http://user:pass@example.com/")),
            Err(SsrfError::Userinfo)
        ));
        assert!(matches!(
            policy().validate_url(&url("http://user@example.com/")),
            Err(SsrfError::Userinfo)
        ));
        assert!(matches!(
            policy().validate_url(&url("http://example.com:8080/")),
            Err(SsrfError::BadPort(8080))
        ));
        assert!(policy()
            .validate_url(&url("http://example.com:80/"))
            .is_ok());
        assert!(policy()
            .validate_url(&url("https://example.com:443/"))
            .is_ok());
        assert!(policy().validate_url(&url("https://example.com/")).is_ok());
    }

    #[test]
    fn resolution_failure_propagates() {
        let resolver = ErrResolver;
        assert!(matches!(
            policy().validate(&url("https://example.com/"), &resolver),
            Err(SsrfError::ResolutionFailed(e)) if e == "boom"
        ));
    }
}
