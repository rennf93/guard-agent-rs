//! Agent configuration and validation.

use std::sync::Arc;

use crate::error::{ConfigError, GuardAgentError};

/// Default ingestion endpoint of the Guard platform.
pub const DEFAULT_ENDPOINT: &str = "https://api.guard-core.com";

/// Default per-kind buffer capacity.
pub const DEFAULT_BUFFER_SIZE: usize = 100;

/// Default flush interval in seconds.
pub const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 30;

/// Default status push interval in seconds.
pub const DEFAULT_STATUS_INTERVAL_SECS: u64 = 300;

/// Minimum accepted status push interval in seconds.
pub const MIN_STATUS_INTERVAL_SECS: u64 = 60;

/// Default high watermark ratio that triggers an early flush.
pub const DEFAULT_HIGH_WATERMARK_RATIO: f64 = 0.8;

/// Default number of retries after the initial send attempt.
pub const DEFAULT_RETRY_ATTEMPTS: u32 = 3;

/// Default per-request timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default exponential backoff base for transport retries.
pub const DEFAULT_BACKOFF_FACTOR: f64 = 1.0;

/// Default gzip threshold in bytes.
pub const DEFAULT_COMPRESSION_THRESHOLD: usize = 1024;

/// Minimum length of an API key accepted by validation.
pub const MIN_API_KEY_LEN: usize = 10;

/// Default payload size hint in bytes.
pub const DEFAULT_MAX_PAYLOAD_SIZE: usize = 1024;

/// How the buffer behaves when a push would exceed its capacity.
///
/// The names mirror the Python and TypeScript agents:
///
/// - `Drop` evicts the oldest buffered item (default).
/// - `Block` waits for space, applying backpressure to the caller.
/// - `Raise` rejects the incoming item by returning
///   [`GuardAgentError::BufferFull`] from `try_send_*` (the fire-and-forget
///   `send_*` helpers log and swallow it, exactly like the Python agent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BufferOverflowPolicy {
    /// Evict the oldest buffered item to make room.
    #[default]
    Drop,
    /// Wait until space is available.
    Block,
    /// Reject the new item.
    Raise,
}

impl BufferOverflowPolicy {
    /// Returns the wire-compatible snake case name of the policy.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Drop => "drop",
            Self::Block => "block",
            Self::Raise => "raise",
        }
    }
}

impl std::fmt::Display for BufferOverflowPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Redis connection settings for the built-in persistence backend.
///
/// Credentials, database index, and TLS settings are expressed through the
/// URL, for example `redis://:password@127.0.0.1:6379/2` or
/// `rediss://cache.internal:6380`.
#[cfg(feature = "persistence")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisConfig {
    /// Redis connection URL.
    pub url: String,
    /// Prefix applied to every key written by the agent.
    pub key_prefix: String,
    /// Per-command timeout in milliseconds.
    pub command_timeout_ms: u64,
}

#[cfg(feature = "persistence")]
impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".to_owned(),
            key_prefix: DEFAULT_REDIS_KEY_PREFIX.to_owned(),
            command_timeout_ms: 5_000,
        }
    }
}

#[cfg(feature = "persistence")]
impl RedisConfig {
    /// Creates a Redis configuration for `url` with default prefix and timeout.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Self::default()
        }
    }
}

/// Default key prefix used by the built-in Redis backend.
pub const DEFAULT_REDIS_KEY_PREFIX: &str = "guard:agent";

/// Callback invoked when a telemetry failure is observed.
///
/// The hook receives the pipeline stage and the underlying error. It is called
/// on a best-effort basis: a panicking hook is caught and logged, and never
/// propagates into the caller's request path.
pub type ErrorHook = Arc<dyn Fn(crate::error::ErrorStage, &GuardAgentError) + Send + Sync>;

/// Configuration for [`GuardAgent`](crate::GuardAgent).
///
/// Every field has a documented default applied by [`AgentConfig::new`]. Call
/// [`AgentConfig::validate`] (or let `GuardAgent::new` do it) before use.
/// Validation normalizes `endpoint` in place: trailing slashes are removed and
/// a legacy `/api/v1` suffix is stripped, matching the Python agent.
#[derive(Clone)]
pub struct AgentConfig {
    /// API key used for the `X-API-Key` header. Must be at least 10 characters.
    pub api_key: String,
    /// Base URL of the ingestion API. Defaults to [`DEFAULT_ENDPOINT`].
    pub endpoint: String,
    /// Project identifier sent as `X-Project-Id`. When unset, the payload
    /// `project_id` falls back to `"default"`.
    pub project_id: Option<String>,
    /// Per-kind buffer capacity. Defaults to [`DEFAULT_BUFFER_SIZE`].
    pub buffer_size: usize,
    /// Time trigger for automatic flushes, in seconds.
    pub flush_interval: u64,
    /// Interval between status pushes, in seconds. Minimum
    /// [`MIN_STATUS_INTERVAL_SECS`].
    pub status_interval: u64,
    /// Occupancy ratio that triggers an early flush. Must be in `(0, 1]`.
    pub high_watermark_ratio: f64,
    /// Maximum number of concurrent flushes. Must be at least 1.
    pub max_concurrent_flushes: usize,
    /// Behavior when the buffer is full.
    pub buffer_overflow_policy: BufferOverflowPolicy,
    /// Enables event ingestion.
    pub enable_events: bool,
    /// Enables metric ingestion.
    pub enable_metrics: bool,
    /// Retries after the initial attempt. Total attempts are this value plus one.
    pub retry_attempts: u32,
    /// Per-request timeout in seconds.
    pub timeout: u64,
    /// Exponential backoff base, in seconds, for transport retries.
    pub backoff_factor: f64,
    /// Metadata and tag keys that are redacted before buffering.
    pub sensitive_headers: Vec<String>,
    /// Advisory payload size hint in bytes.
    ///
    /// Kept for parity with the Python and TypeScript agents, which expose it
    /// to their adapters. The core transport does not truncate payloads.
    pub max_payload_size: usize,
    /// Higher level wrapper version reported in batch payloads.
    pub guard_version: Option<String>,
    /// Guard Core version reported in batch payloads.
    pub guard_core_version: Option<String>,
    /// Enables gzip compression of request bodies at or above the threshold.
    pub compression_enabled: bool,
    /// Minimum body size, in bytes, before gzip is applied.
    pub compression_threshold: usize,
    /// Explicit install identifier. When unset, a UUID is persisted under
    /// `~/.guard-agent/install-id`.
    pub install_id: Option<String>,
    /// Secret for `X-Payload-Signature` (HMAC-SHA256, `v1=<hex>`). When unset,
    /// no signature header is sent.
    pub payload_signing_secret: Option<String>,
    /// Redis persistence settings for the built-in backend.
    #[cfg(feature = "persistence")]
    pub redis: Option<RedisConfig>,
    /// Optional failure hook.
    pub on_error: Option<ErrorHook>,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_struct("AgentConfig");
        dbg.field("endpoint", &self.endpoint)
            .field("project_id", &self.project_id)
            .field("api_key", &"<redacted>")
            .field("buffer_size", &self.buffer_size)
            .field("flush_interval", &self.flush_interval)
            .field("status_interval", &self.status_interval)
            .field("high_watermark_ratio", &self.high_watermark_ratio)
            .field("max_concurrent_flushes", &self.max_concurrent_flushes)
            .field("buffer_overflow_policy", &self.buffer_overflow_policy)
            .field("enable_events", &self.enable_events)
            .field("enable_metrics", &self.enable_metrics)
            .field("retry_attempts", &self.retry_attempts)
            .field("timeout", &self.timeout)
            .field("backoff_factor", &self.backoff_factor)
            .field("sensitive_headers", &self.sensitive_headers)
            .field("max_payload_size", &self.max_payload_size)
            .field("guard_version", &self.guard_version)
            .field("guard_core_version", &self.guard_core_version)
            .field("compression_enabled", &self.compression_enabled)
            .field("compression_threshold", &self.compression_threshold)
            .field("install_id", &self.install_id)
            .field(
                "payload_signing_secret",
                &self.payload_signing_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("on_error", &self.on_error.as_ref().map(|_| "<hook>"));
        #[cfg(feature = "persistence")]
        dbg.field("redis", &self.redis);
        dbg.finish()
    }
}

impl AgentConfig {
    /// Creates a configuration with default values and the given API key.
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            endpoint: DEFAULT_ENDPOINT.to_owned(),
            project_id: None,
            buffer_size: DEFAULT_BUFFER_SIZE,
            flush_interval: DEFAULT_FLUSH_INTERVAL_SECS,
            status_interval: DEFAULT_STATUS_INTERVAL_SECS,
            high_watermark_ratio: DEFAULT_HIGH_WATERMARK_RATIO,
            max_concurrent_flushes: 1,
            buffer_overflow_policy: BufferOverflowPolicy::Drop,
            enable_events: true,
            enable_metrics: true,
            retry_attempts: DEFAULT_RETRY_ATTEMPTS,
            timeout: DEFAULT_TIMEOUT_SECS,
            backoff_factor: DEFAULT_BACKOFF_FACTOR,
            sensitive_headers: DEFAULT_SENSITIVE_HEADERS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            max_payload_size: DEFAULT_MAX_PAYLOAD_SIZE,
            guard_version: None,
            guard_core_version: None,
            compression_enabled: true,
            compression_threshold: DEFAULT_COMPRESSION_THRESHOLD,
            install_id: None,
            payload_signing_secret: None,
            #[cfg(feature = "persistence")]
            redis: None,
            on_error: None,
        }
    }

    /// Normalizes and validates the configuration in place.
    ///
    /// Returns every problem found, so a caller can fix them all at once. The
    /// only mutation is endpoint normalization (trailing slashes removed, a
    /// legacy `/api/v1` suffix stripped with a warning).
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        let mut problems = Vec::new();

        if self.api_key.len() < MIN_API_KEY_LEN {
            problems.push(format!(
                "api_key must be at least {MIN_API_KEY_LEN} characters long"
            ));
        }

        self.normalize_endpoint(&mut problems);
        self.validate_numeric(&mut problems);
        #[cfg(feature = "persistence")]
        self.validate_optional(&mut problems);

        if problems.is_empty() {
            Ok(())
        } else {
            Err(ConfigError { problems })
        }
    }

    /// Trims the endpoint, strips trailing slashes, and drops a legacy
    /// `/api/v1` suffix.
    fn normalize_endpoint(&mut self, problems: &mut Vec<String>) {
        let trimmed = self.endpoint.trim().to_owned();
        if trimmed.is_empty() {
            problems.push("endpoint must not be empty".to_owned());
            self.endpoint = trimmed;
            return;
        }
        let without_slash = trimmed.trim_end_matches('/').to_owned();
        let without_slash = without_slash.strip_suffix("/api/v1").map_or_else(
            || without_slash.clone(),
            |stripped| {
                log::warn!(
                    "Endpoint '{trimmed}' includes the legacy '/api/v1' suffix; stripping it. \
                         The agent appends versioned paths itself."
                );
                stripped.trim_end_matches('/').to_owned()
            },
        );
        if !without_slash.starts_with("http://") && !without_slash.starts_with("https://") {
            problems.push("endpoint must start with http:// or https://".to_owned());
        } else {
            let host = without_slash
                .split_once("://")
                .map_or("", |(_scheme, rest)| rest);
            if host.is_empty() || host.starts_with('/') {
                problems.push("endpoint must include a host".to_owned());
            }
        }
        self.endpoint = without_slash;
    }

    /// Validates the numeric ranges.
    fn validate_numeric(&self, problems: &mut Vec<String>) {
        if self.buffer_size == 0 {
            problems.push("buffer_size must be greater than 0".to_owned());
        }
        if self.flush_interval == 0 {
            problems.push("flush_interval must be greater than 0".to_owned());
        }
        if self.status_interval < MIN_STATUS_INTERVAL_SECS {
            problems.push(format!(
                "status_interval must be at least {MIN_STATUS_INTERVAL_SECS} seconds"
            ));
        }
        if self.timeout == 0 {
            problems.push("timeout must be greater than 0".to_owned());
        }
        if self.backoff_factor <= 0.0 {
            problems.push("backoff_factor must be greater than 0".to_owned());
        }
        if self.high_watermark_ratio <= 0.0 || self.high_watermark_ratio > 1.0 {
            problems.push("high_watermark_ratio must be within (0, 1]".to_owned());
        }
        if self.max_concurrent_flushes == 0 {
            problems.push("max_concurrent_flushes must be at least 1".to_owned());
        }
    }

    /// Validates optional subsections. Only compiled with persistence.
    #[cfg(feature = "persistence")]
    fn validate_optional(&self, problems: &mut Vec<String>) {
        if let Some(redis) = &self.redis
            && redis.url.trim().is_empty()
        {
            problems.push("redis.url must not be empty".to_owned());
        }
    }

    /// Returns the payload `project_id`, defaulting to `"default"` like the
    /// Python and TypeScript agents.
    #[must_use]
    pub fn payload_project_id(&self) -> String {
        self.project_id
            .clone()
            .unwrap_or_else(|| "default".to_owned())
    }
}

/// Default sensitive metadata and tag keys redacted before buffering.
pub const DEFAULT_SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> AgentConfig {
        AgentConfig::new("test-api-key-1234")
    }

    #[test]
    fn defaults_match_the_python_agent() {
        let config = valid_config();
        assert_eq!(config.endpoint, DEFAULT_ENDPOINT);
        assert_eq!(config.buffer_size, 100);
        assert_eq!(config.flush_interval, 30);
        assert_eq!(config.status_interval, 300);
        assert!((config.high_watermark_ratio - 0.8).abs() < f64::EPSILON);
        assert_eq!(config.max_concurrent_flushes, 1);
        assert_eq!(config.buffer_overflow_policy, BufferOverflowPolicy::Drop);
        assert_eq!(config.retry_attempts, 3);
        assert_eq!(config.timeout, 30);
        assert!((config.backoff_factor - 1.0).abs() < f64::EPSILON);
        assert_eq!(config.compression_threshold, 1024);
        assert_eq!(config.max_payload_size, 1024);
        assert!(config.enable_events && config.enable_metrics);
        assert!(config.compression_enabled);
        assert_eq!(config.sensitive_headers.len(), 4);
        assert!(config.project_id.is_none());
        assert!(config.install_id.is_none());
        assert!(config.payload_signing_secret.is_none());
        assert!(config.on_error.is_none());
    }

    #[test]
    fn valid_config_passes() {
        let mut config = valid_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn short_api_key_is_rejected() {
        let mut config = AgentConfig::new("short");
        let err = config.validate().unwrap_err();
        assert!(
            err.problems
                .iter()
                .any(|p| p.contains("api_key must be at least 10 characters")),
            "{:?}",
            err.problems
        );
    }

    #[test]
    fn all_problems_are_collected() {
        let mut config = AgentConfig::new("x");
        config.endpoint = "ftp://example.com".to_owned();
        config.buffer_size = 0;
        config.flush_interval = 0;
        config.status_interval = 5;
        config.timeout = 0;
        config.backoff_factor = 0.0;
        config.high_watermark_ratio = 1.5;
        config.max_concurrent_flushes = 0;
        let err = config.validate().unwrap_err();
        assert_eq!(err.problems.len(), 9, "{:?}", err.problems);
    }

    #[test]
    fn endpoint_trailing_slashes_are_stripped() {
        let mut config = valid_config();
        config.endpoint = "https://api.example.com///".to_owned();
        config.validate().unwrap();
        assert_eq!(config.endpoint, "https://api.example.com");
    }

    #[test]
    fn legacy_api_v1_suffix_is_stripped() {
        let mut config = valid_config();
        config.endpoint = "https://api.example.com/api/v1/".to_owned();
        config.validate().unwrap();
        assert_eq!(config.endpoint, "https://api.example.com");
    }

    #[test]
    fn endpoint_requires_http_scheme() {
        let mut config = valid_config();
        config.endpoint = "example.com".to_owned();
        let err = config.validate().unwrap_err();
        assert!(err.problems[0].contains("must start with http:// or https://"));
    }

    #[test]
    fn endpoint_requires_host() {
        let mut config = valid_config();
        // Trailing slashes are trimmed first, so "https://" degrades to the
        // scheme error; a path-only authority hits the host check.
        config.endpoint = "http:///api".to_owned();
        let err = config.validate().unwrap_err();
        assert!(
            err.problems
                .iter()
                .any(|p| p.contains("must include a host")),
            "{:?}",
            err.problems
        );
        config.endpoint = "https://".to_owned();
        let err = config.validate().unwrap_err();
        assert!(
            err.problems
                .iter()
                .any(|p| p.contains("must start with http:// or https://")),
            "{:?}",
            err.problems
        );
    }

    #[test]
    fn empty_endpoint_is_rejected_before_scheme_check() {
        let mut config = valid_config();
        config.endpoint = "   ".to_owned();
        let err = config.validate().unwrap_err();
        assert_eq!(err.problems, vec!["endpoint must not be empty".to_owned()]);
    }

    #[test]
    fn watermark_bounds_are_enforced() {
        let mut config = valid_config();
        config.high_watermark_ratio = 0.0;
        assert!(config.validate().is_err());
        config.high_watermark_ratio = 1.0;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn policy_names_are_stable() {
        assert_eq!(BufferOverflowPolicy::Drop.as_str(), "drop");
        assert_eq!(BufferOverflowPolicy::Block.as_str(), "block");
        assert_eq!(BufferOverflowPolicy::Raise.as_str(), "raise");
        assert_eq!(BufferOverflowPolicy::default(), BufferOverflowPolicy::Drop);
    }

    #[test]
    fn project_id_defaults_to_default_literal() {
        let mut config = valid_config();
        assert_eq!(config.payload_project_id(), "default");
        config.project_id = Some("proj_123".to_owned());
        assert_eq!(config.payload_project_id(), "proj_123");
    }

    #[test]
    fn debug_redacts_secrets() {
        let mut config = valid_config();
        config.payload_signing_secret = Some("super-secret".to_owned());
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(!rendered.contains("test-api-key-1234"));
        assert!(rendered.contains("<redacted>"));
    }

    #[cfg(feature = "persistence")]
    #[test]
    fn redis_defaults_and_validation() {
        let redis = RedisConfig::default();
        assert_eq!(redis.url, "redis://127.0.0.1:6379");
        assert_eq!(redis.key_prefix, DEFAULT_REDIS_KEY_PREFIX);
        assert_eq!(redis.command_timeout_ms, 5_000);

        let mut config = valid_config();
        config.redis = Some(RedisConfig::new("redis://127.0.0.1:6379"));
        assert!(config.validate().is_ok());

        let mut empty = valid_config();
        empty.redis = Some(RedisConfig::new(""));
        let err = empty.validate().unwrap_err();
        assert!(err.problems[0].contains("redis.url must not be empty"));
    }
}
