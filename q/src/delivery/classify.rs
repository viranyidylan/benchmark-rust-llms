//! Outcome classification for delivery attempts (PLAN.md, T3).

/// What happened after a single delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The destination accepted the payload (2xx).
    Delivered,
    /// Transient failure — retry with backoff.
    Retryable(String),
    /// Permanent failure — dead-letter.
    Permanent(String),
}

/// Classify a response.
///
/// A transport error takes precedence: if the request failed before a
/// response arrived (timeout, DNS, TLS, connection refused, ...), the outcome
/// is [`Outcome::Retryable`]. Otherwise status codes map as:
/// 2xx ⇒ [`Outcome::Delivered`]; 429/5xx ⇒ [`Outcome::Retryable`];
/// anything else ⇒ [`Outcome::Permanent`].
pub fn classify(status: u16, transport_err: Option<&reqwest::Error>) -> Outcome {
    if let Some(e) = transport_err {
        return Outcome::Retryable(e.to_string());
    }
    match status {
        200..=299 => Outcome::Delivered,
        429 | 500..=599 => Outcome::Retryable(format!("HTTP {status}")),
        _ => Outcome::Permanent(format!("HTTP {status}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_table() {
        assert_eq!(classify(200, None), Outcome::Delivered);
        assert_eq!(classify(204, None), Outcome::Delivered);
        assert!(matches!(
            classify(404, None),
            Outcome::Permanent(msg) if msg.contains("404")
        ));
        assert!(matches!(
            classify(429, None),
            Outcome::Retryable(msg) if msg.contains("429")
        ));
        assert!(matches!(
            classify(500, None),
            Outcome::Retryable(msg) if msg.contains("500")
        ));
        assert!(matches!(
            classify(503, None),
            Outcome::Retryable(msg) if msg.contains("503")
        ));
    }

    #[tokio::test]
    async fn transport_error_is_retryable() {
        let client = reqwest::Client::new();
        // Connection refused on loopback: fast, deterministic transport error.
        let err = client
            .get("http://127.0.0.1:1/")
            .send()
            .await
            .expect_err("connection to 127.0.0.1:1 must fail");
        assert!(matches!(classify(0, Some(&err)), Outcome::Retryable(_)));
    }
}
