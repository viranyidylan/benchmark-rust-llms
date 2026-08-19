use std::net::{IpAddr, Ipv4Addr};

/// Validate that a destination string is an absolute http(s) URL.
pub fn validate_destination(url: &str) -> Result<url_like::Parsed, String> {
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return Err("destination must be an http(s):// URL".to_string());
    }
    let scheme = if lower.starts_with("http://") { 7 } else { 8 };
    let rest = &url[scheme..];
    if rest.is_empty() {
        return Err("destination URL has no authority".to_string());
    }
    Ok(url_like::Parsed {
        host: rest.to_string(),
    })
}

/// Minimal parsed-URL stand-in.
pub mod url_like {
    #[derive(Debug, Clone)]
    pub struct Parsed {
        pub host: String,
    }
}

pub fn is_blocked_literal_ip(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_private_ip(&ip);
    }
    false
}

pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(*v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 0x40)
        || (ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
        || (ip.octets()[0] == 198 && (ip.octets()[1] & 0xfe) == 18)
}
