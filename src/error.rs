//! Typed errors for the guard-agent-rs telemetry agent.

use std::fmt;

/// Root error type for every fallible operation in the agent.
///
/// The public API is deliberately narrow about what can fail:
/// [`GuardAgent::new`](crate::GuardAgent::new) surfaces
/// [`GuardAgentError::Config`], and
/// [`GuardAgent::try_send_event`](crate::GuardAgent::try_send_event) can
/// surface [`GuardAgentError::BufferFull`] when the overflow policy is
/// [`BufferOverflowPolicy::Raise`](crate::BufferOverflowPolicy::Raise). Every
/// transport, flush, and persistence failure is absorbed by the agent and
/// reported through stats, logs, and the optional `on_error` hook instead,
/// mirroring the failure-isolation policy of the Python and TypeScript agents.
#[derive(Debug, thiserror::Error)]
pub enum GuardAgentError {
    /// The agent configuration failed validation.
    #[error("Invalid agent configuration: {0}")]
    Config(#[from] ConfigError),

    /// The buffer is full and the configured overflow policy is `raise`.
    #[error("Buffer full at capacity {capacity} and buffer_overflow_policy='raise'")]
    BufferFull {
        /// Configured per-kind buffer capacity that was exceeded.
        capacity: usize,
    },

    /// The ingestion API responded with 429 Too Many Requests.
    #[error("Rate limited (429); retry after {retry_after_seconds:.0}s")]
    RateLimited {
        /// Server-provided or defaulted delay in seconds.
        retry_after_seconds: f64,
    },

    /// The request was permanently rejected (400, 404, 422) and will never be
    /// retried. The affected batch is dropped by the flush layer.
    #[error("Permanent client error {status_code}: {detail}")]
    Permanent {
        /// HTTP status code that triggered the rejection.
        status_code: u16,
        /// Truncated response body describing the rejection.
        detail: String,
    },

    /// The request body exceeded the server payload cap (413).
    #[error("Payload too large (413): {detail}")]
    PayloadTooLarge {
        /// Truncated response body describing the limit.
        detail: String,
    },

    /// A non-permanent transport-level failure (network, timeout, 5xx,
    /// authentication, circuit breaker open, unparseable response, ...).
    #[error("{0}")]
    Transport(String),

    /// A payload could not be serialized.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// A Redis persistence operation failed.
    #[error("Redis error: {0}")]
    Redis(String),
}

/// Validation failure report for [`AgentConfig`](crate::AgentConfig).
///
/// Collects every problem found instead of stopping at the first one, so a
/// caller can fix the whole configuration in one pass.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Invalid agent configuration: {}", problems.join("; "))]
pub struct ConfigError {
    /// Individual problems found, in field order.
    pub problems: Vec<String>,
}

/// Stage identifiers passed to the optional `on_error` hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorStage {
    /// A transport send failed after exhausting retries, or a batch was
    /// permanently dropped, or a payload could not be serialized.
    TransportSend,
    /// An events flush failed and the batch was requeued.
    FlushEvents,
    /// A metrics flush failed and the batch was requeued.
    FlushMetrics,
}

impl fmt::Display for ErrorStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::TransportSend => "transport_send",
            Self::FlushEvents => "flush_events",
            Self::FlushMetrics => "flush_metrics",
        };
        f.write_str(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_joins_problems() {
        let err = ConfigError {
            problems: vec![
                "api_key must be at least 10 characters long".into(),
                "buffer_size must be greater than 0".into(),
            ],
        };
        assert_eq!(
            err.to_string(),
            "Invalid agent configuration: api_key must be at least 10 characters long; \
             buffer_size must be greater than 0"
        );
    }

    #[test]
    fn error_stage_labels_match_python_stages() {
        assert_eq!(ErrorStage::TransportSend.to_string(), "transport_send");
        assert_eq!(ErrorStage::FlushEvents.to_string(), "flush_events");
        assert_eq!(ErrorStage::FlushMetrics.to_string(), "flush_metrics");
    }

    #[test]
    fn error_messages_are_stable() {
        let rate = GuardAgentError::RateLimited {
            retry_after_seconds: 42.0,
        };
        assert_eq!(rate.to_string(), "Rate limited (429); retry after 42s");

        let perm = GuardAgentError::Permanent {
            status_code: 400,
            detail: "bad request".into(),
        };
        assert_eq!(perm.to_string(), "Permanent client error 400: bad request");

        let full = GuardAgentError::BufferFull { capacity: 10 };
        assert_eq!(
            full.to_string(),
            "Buffer full at capacity 10 and buffer_overflow_policy='raise'"
        );
    }
}
