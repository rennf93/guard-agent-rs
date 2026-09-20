//! HTTP transport: gzip compression, HMAC signing, retries with backoff,
//! 429 `Retry-After` handling, 413 split-or-drop, and permanent-rejection
//! classification.
//!
//! The transport mirrors `guard_agent/_transport_send.py` and
//! `_transport_dispatch.py`:
//!
//! - success is any 2xx; a 200 body with `success == false` or a non-empty
//!   `errors` list is a partial failure and is requeued by the caller
//!   (the ingestion API returns 200 even on partial failure,
//!   `telemetry_service.py:741-750`);
//! - 429 honors `Retry-After` (seconds, capped, default 60);
//! - 400, 404, and 422 are permanent rejections: the batch is dropped, never
//!   retried, and reported as confirmed so the flush layer deletes its
//!   durable records;
//! - 413 triggers binary split-or-drop: the batch is halved and each half
//!   retried recursively; a singleton that still 413s is dropped;
//! - 401, 403, other 4xx, 5xx, and network errors are retryable with
//!   exponential backoff under the circuit breaker.
//!
//! One deliberate difference from the Python and TypeScript agents: the HMAC
//! signature covers the uncompressed JSON body (see [`crate::signing`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::Utc;
use reqwest::header::{
    CONTENT_ENCODING, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, RETRY_AFTER, USER_AGENT,
};
use serde_json::{Value, json};

use crate::circuit_breaker::CircuitBreaker;
use crate::config::AgentConfig;
use crate::error::{ErrorStage, GuardAgentError};
use crate::models::{AgentStatus, SecurityEvent, SecurityMetric, TelemetryAck};
use crate::signing::sign_payload;
use crate::utils::{
    calculate_backoff_delay, generate_batch_id, gzip_bytes, parse_retry_after_seconds,
    summarize_response_body,
};

/// Status codes that are permanent rejections; the batch is dropped without
/// retrying.
pub(crate) const NON_RETRYABLE_STATUS_CODES: [u16; 3] = [400, 404, 422];

/// Upper bound, in seconds, applied to a server-provided `Retry-After`.
pub(crate) const MAX_RETRY_AFTER_SECS: f64 = 300.0;

/// Upper bound, in seconds, applied to a transport backoff delay.
pub(crate) const MAX_RETRY_BACKOFF_SECS: f64 = 60.0;

/// Default `Retry-After`, in seconds, when the header is missing or
/// unparseable.
pub(crate) const DEFAULT_RETRY_AFTER_SECS: f64 = 60.0;

/// Maximum length of a `Retry-After` value kept for parsing.
const RETRY_AFTER_HEADER_MAX_LEN: usize = 32;

const HEADER_X_API_KEY: &str = "X-API-Key";
const HEADER_X_INSTALL_ID: &str = "X-Agent-Install-Id";
const HEADER_X_PROJECT_ID: &str = "X-Project-Id";
const HEADER_X_PAYLOAD_SIGNATURE: &str = "X-Payload-Signature";

/// Result of a batch or status send, consumed by the flush layer.
#[derive(Debug)]
pub(crate) enum SendOutcome {
    /// The server accepted the send.
    Accepted,
    /// The server permanently rejected the send (or a singleton exceeded the
    /// payload cap); the batch is intentionally dropped and counts as
    /// confirmed for at-least-once purposes.
    PermanentDrop {
        /// Status code that caused the drop.
        status_code: u16,
        /// Truncated response body.
        detail: String,
    },
    /// The send failed after exhausting retries (or on a partial failure);
    /// the batch must be requeued.
    Failed {
        /// The final error, also reported through the `on_error` hook.
        error: GuardAgentError,
    },
}

impl SendOutcome {
    /// Returns `true` when the flush layer should delete the batch's durable
    /// records instead of requeueing.
    #[must_use]
    pub(crate) const fn is_confirmed(&self) -> bool {
        matches!(self, Self::Accepted | Self::PermanentDrop { .. })
    }
}

/// Internal classification of a single HTTP attempt.
enum AttemptResult {
    Accepted,
    PartialFailure { errors: Vec<String> },
    Permanent { status_code: u16, detail: String },
    TooLarge { detail: String },
    RateLimited { retry_after_seconds: f64 },
    Retryable { error: GuardAgentError },
}

/// Signal raised when the server rejects a batch as too large; the caller
/// splits the batch and retries.
struct TooLargeSignal {
    detail: String,
}

/// The batch payload handed to the transport.
#[derive(Debug)]
pub(crate) enum BatchItems {
    /// A batch of events, sent to `/api/v1/events`.
    Events(Vec<SecurityEvent>),
    /// A batch of metrics, sent to `/api/v1/metrics`.
    Metrics(Vec<SecurityMetric>),
}

impl BatchItems {
    /// Number of items in the batch.
    const fn len(&self) -> usize {
        match self {
            Self::Events(events) => events.len(),
            Self::Metrics(metrics) => metrics.len(),
        }
    }

    /// Endpoint label used by the transport: `"events"` or `"metrics"`.
    const fn label(&self) -> &'static str {
        match self {
            Self::Events(_) => "events",
            Self::Metrics(_) => "metrics",
        }
    }

    /// Splits the batch in half for 413 recovery.
    fn split(self) -> (Self, Self) {
        match self {
            Self::Events(mut events) => {
                let midpoint = events.len() / 2;
                let right = events.split_off(midpoint);
                (Self::Events(events), Self::Events(right))
            }
            Self::Metrics(mut metrics) => {
                let midpoint = metrics.len() / 2;
                let right = metrics.split_off(midpoint);
                (Self::Metrics(metrics), Self::Metrics(right))
            }
        }
    }

    /// Serializes only the item list for the batch envelope.
    fn items_value(&self) -> Result<Value, serde_json::Error> {
        match self {
            Self::Events(events) => serde_json::to_value(events),
            Self::Metrics(metrics) => serde_json::to_value(metrics),
        }
    }

    /// Returns the item ids for logging, best effort.
    fn summary(&self) -> String {
        match self {
            Self::Events(events) => format!("{} event(s)", events.len()),
            Self::Metrics(metrics) => format!("{} metric(s)", metrics.len()),
        }
    }
}

fn header_name(name: &str) -> HeaderName {
    HeaderName::from_bytes(name.as_bytes()).expect("static header names are valid tokens")
}

/// HTTP transport shared by all agent operations.
pub(crate) struct HttpTransport {
    client: reqwest::Client,
    config: Arc<AgentConfig>,
    breaker: CircuitBreaker,
    requests_sent: AtomicU64,
    requests_failed: AtomicU64,
    bytes_sent: AtomicU64,
    header_signature: HeaderName,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("breaker", &self.breaker.state())
            .field("requests_sent", &self.requests_sent.load(Ordering::Relaxed))
            .field(
                "requests_failed",
                &self.requests_failed.load(Ordering::Relaxed),
            )
            .field("bytes_sent", &self.bytes_sent.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl HttpTransport {
    /// Builds the transport, including the `reqwest` client with the default
    /// ingestion headers.
    pub(crate) fn new(config: Arc<AgentConfig>, install_id: &str) -> Result<Self, GuardAgentError> {
        let header_value = |value: &str| -> Result<HeaderValue, GuardAgentError> {
            HeaderValue::from_str(value).map_err(|_| {
                GuardAgentError::Transport("header value contains invalid characters".to_owned())
            })
        };

        let mut default_headers = HeaderMap::new();
        default_headers.insert(
            USER_AGENT,
            header_value(&format!("guard-agent-rs/{}", crate::AGENT_VERSION))?,
        );
        default_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        default_headers.insert(
            header_name(HEADER_X_API_KEY),
            header_value(&config.api_key)?,
        );
        default_headers.insert(header_name(HEADER_X_INSTALL_ID), header_value(install_id)?);
        if let Some(project_id) = &config.project_id {
            default_headers.insert(header_name(HEADER_X_PROJECT_ID), header_value(project_id)?);
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .default_headers(default_headers)
            .build()
            .map_err(|error| {
                GuardAgentError::Transport(format!("failed to build HTTP client: {error}"))
            })?;

        Ok(Self {
            client,
            config,
            breaker: CircuitBreaker::default(),
            requests_sent: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            header_signature: header_name(HEADER_X_PAYLOAD_SIGNATURE),
        })
    }

    /// Returns the breaker's current position.
    #[must_use]
    pub(crate) fn breaker_state(&self) -> crate::circuit_breaker::CircuitBreakerState {
        self.breaker.state()
    }

    /// Lifetime counters for stats reporting.
    #[must_use]
    pub(crate) fn counters(&self) -> (u64, u64, u64) {
        (
            self.requests_sent.load(Ordering::Relaxed),
            self.requests_failed.load(Ordering::Relaxed),
            self.bytes_sent.load(Ordering::Relaxed),
        )
    }

    /// Sends an events or metrics batch, splitting on 413 as needed.
    pub(crate) async fn send_batch(&self, items: BatchItems) -> SendOutcome {
        let body = match self.build_batch_body(&items) {
            Ok(body) => body,
            Err(error) => {
                let error = GuardAgentError::Serialization(error);
                log::error!(
                    "Aborting POST to /api/v1/{}; payload serialization failed and batch retained: {error}",
                    items.label()
                );
                self.fire_hook(ErrorStage::TransportSend, &error);
                return SendOutcome::Failed { error };
            }
        };

        match self.send_with_retry(items.label(), &body).await {
            Ok(SendOutcome::PermanentDrop {
                status_code,
                detail,
            }) => {
                log::warn!(
                    "Dropping {} batch of {}; permanently rejected ({}): {detail}",
                    items.label(),
                    items.summary(),
                    status_code
                );
                let error = GuardAgentError::Permanent {
                    status_code,
                    detail: detail.clone(),
                };
                self.fire_hook(ErrorStage::TransportSend, &error);
                SendOutcome::PermanentDrop {
                    status_code,
                    detail,
                }
            }
            Ok(outcome) => outcome,
            Err(too_large) => self.split_or_drop(items, too_large.detail).await,
        }
    }

    /// Sends the status payload to `/api/v1/status`. Too-large statuses are
    /// not split; they surface as failures.
    pub(crate) async fn send_status(&self, status: &AgentStatus) -> SendOutcome {
        let body = match serde_json::to_vec(status) {
            Ok(body) => body,
            Err(error) => {
                let error = GuardAgentError::Serialization(error);
                log::error!(
                    "Aborting POST to /api/v1/status; payload serialization failed and status push skipped: {error}"
                );
                self.fire_hook(ErrorStage::TransportSend, &error);
                return SendOutcome::Failed { error };
            }
        };

        match self.send_with_retry("status", &body).await {
            Ok(outcome) => outcome,
            Err(too_large) => {
                let error = GuardAgentError::PayloadTooLarge {
                    detail: too_large.detail,
                };
                self.fire_hook(ErrorStage::TransportSend, &error);
                SendOutcome::Failed { error }
            }
        }
    }

    /// Recursively halves the batch until it fits under the payload cap; a
    /// singleton that still 413s is dropped and reported as confirmed.
    async fn split_or_drop(&self, items: BatchItems, detail: String) -> SendOutcome {
        let count = items.len();
        if count <= 1 {
            log::warn!(
                "Dropping {} batch of {count} item; payload exceeds size cap even as a single item: {detail}",
                items.label()
            );
            let error = GuardAgentError::PayloadTooLarge {
                detail: detail.clone(),
            };
            self.fire_hook(ErrorStage::TransportSend, &error);
            return SendOutcome::PermanentDrop {
                status_code: 413,
                detail,
            };
        }
        let (left, right) = items.split();
        // Boxed to break the async-fn recursion cycle: each half may 413
        // again, but real depth is bounded by log2 of the batch size.
        let left_outcome = Box::pin(self.send_batch(left)).await;
        if left_outcome.is_confirmed() {
            Box::pin(self.send_batch(right)).await
        } else {
            left_outcome
        }
    }

    /// Builds the batch envelope for `/api/v1/events` and `/api/v1/metrics`,
    /// mirroring the Python agent's `EventBatch` dump.
    fn build_batch_body(&self, items: &BatchItems) -> Result<Vec<u8>, serde_json::Error> {
        let items_value = items.items_value()?;
        let (events, metrics) = match items {
            BatchItems::Events(_) => (items_value, Value::Array(Vec::new())),
            BatchItems::Metrics(_) => (Value::Array(Vec::new()), items_value),
        };
        let envelope = json!({
            "project_id": self.config.payload_project_id(),
            "events": events,
            "metrics": metrics,
            "batch_id": generate_batch_id(),
            "created_at": Utc::now(),
            "compressed": false,
            "agent_version": crate::AGENT_VERSION,
            "guard_version": self.config.guard_version,
            "guard_core_version": self.config.guard_core_version,
        });
        serde_json::to_vec(&envelope)
    }

    /// The retry loop: breaker admission, exponential backoff, and
    /// `Retry-After` handling. 413 escapes as [`TooLargeSignal`] for the
    /// split-or-drop caller.
    async fn send_with_retry(
        &self,
        label: &'static str,
        body: &[u8],
    ) -> Result<SendOutcome, TooLargeSignal> {
        let total_attempts = self.config.retry_attempts.saturating_add(1);
        let mut attempt: u32 = 0;

        while attempt < total_attempts {
            if !self.breaker.admit() {
                let error = GuardAgentError::Transport("Circuit breaker is OPEN".to_owned());
                if attempt + 1 == total_attempts {
                    self.requests_failed.fetch_add(1, Ordering::Relaxed);
                    self.fire_hook(ErrorStage::TransportSend, &error);
                    return Ok(SendOutcome::Failed { error });
                }
                log::warn!(
                    "Circuit breaker is OPEN; delaying attempt {} for {label}",
                    attempt + 1
                );
                self.sleep_backoff(attempt).await;
                attempt += 1;
                continue;
            }

            match self.attempt(label, body).await {
                AttemptResult::Accepted => {
                    self.breaker.record_success();
                    return Ok(SendOutcome::Accepted);
                }
                AttemptResult::PartialFailure { errors } => {
                    self.breaker.record_success();
                    let error = GuardAgentError::Transport(format!(
                        "Server acknowledged {label} batch with partial failure: {errors:?}"
                    ));
                    log::warn!("{error}");
                    return Ok(SendOutcome::Failed { error });
                }
                AttemptResult::Permanent {
                    status_code,
                    detail,
                } => {
                    return Ok(SendOutcome::PermanentDrop {
                        status_code,
                        detail,
                    });
                }
                AttemptResult::TooLarge { detail } => {
                    return Err(TooLargeSignal { detail });
                }
                AttemptResult::RateLimited {
                    retry_after_seconds,
                } => {
                    self.breaker.record_failure();
                    if attempt + 1 == total_attempts {
                        self.requests_failed.fetch_add(1, Ordering::Relaxed);
                        let error = GuardAgentError::RateLimited {
                            retry_after_seconds,
                        };
                        log::error!("All retry attempts failed for {label}: {error}");
                        self.fire_hook(ErrorStage::TransportSend, &error);
                        return Ok(SendOutcome::Failed { error });
                    }
                    let delay = retry_after_seconds.min(MAX_RETRY_AFTER_SECS);
                    log::warn!(
                        "Rate limited on attempt {} for {label}; honoring Retry-After of {delay:.0}s",
                        attempt + 1
                    );
                    tokio::time::sleep(Duration::from_secs_f64(delay)).await;
                    attempt += 1;
                }
                AttemptResult::Retryable { error } => {
                    self.breaker.record_failure();
                    if attempt + 1 == total_attempts {
                        self.requests_failed.fetch_add(1, Ordering::Relaxed);
                        log::error!("All retry attempts failed for {label}: {error}");
                        self.fire_hook(ErrorStage::TransportSend, &error);
                        return Ok(SendOutcome::Failed { error });
                    }
                    log::warn!("Attempt {} failed for {label}: {error}", attempt + 1);
                    self.sleep_backoff(attempt).await;
                    attempt += 1;
                }
            }
        }

        // The loop above always returns; this is a defensive fallback.
        Ok(SendOutcome::Failed {
            error: GuardAgentError::Transport("retry loop exited unexpectedly".to_owned()),
        })
    }

    /// Sleeps the exponential backoff delay for `attempt`, capped.
    async fn sleep_backoff(&self, attempt: u32) {
        let delay =
            calculate_backoff_delay(attempt, self.config.backoff_factor, MAX_RETRY_BACKOFF_SECS);
        tokio::time::sleep(Duration::from_secs_f64(delay)).await;
    }

    /// Performs one HTTP attempt and classifies the outcome.
    async fn attempt(&self, label: &str, body: &[u8]) -> AttemptResult {
        let (wire_body, gzipped) = self.maybe_compress(body);
        self.bytes_sent.fetch_add(
            u64::try_from(wire_body.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );

        let url = format!("{}/api/v1/{label}", self.config.endpoint);
        let mut request = self.client.post(&url).body(wire_body);
        if gzipped {
            request = request.header(CONTENT_ENCODING, "gzip");
        }
        if let Some(signature) = sign_payload(body, self.config.payload_signing_secret.as_deref()) {
            request = request.header(self.header_signature.clone(), signature);
        }

        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                return AttemptResult::Retryable {
                    error: GuardAgentError::Transport(format!(
                        "HTTP client error for POST {url}: {error}"
                    )),
                };
            }
        };
        self.requests_sent.fetch_add(1, Ordering::Relaxed);

        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .chars()
                    .take(RETRY_AFTER_HEADER_MAX_LEN)
                    .collect::<String>()
            });
        let body_text = match response.text().await {
            Ok(text) => text,
            Err(error) => {
                return AttemptResult::Retryable {
                    error: GuardAgentError::Transport(format!(
                        "Failed to read response body for POST {url}: {error}"
                    )),
                };
            }
        };

        Self::classify_response(status, &body_text, &url, retry_after.as_deref())
    }

    /// Applies the compression threshold, mirroring the Python agent.
    fn maybe_compress(&self, body: &[u8]) -> (Vec<u8>, bool) {
        if self.config.compression_enabled && body.len() >= self.config.compression_threshold {
            (gzip_bytes(body), true)
        } else {
            (body.to_vec(), false)
        }
    }

    /// Maps a status code and body onto the attempt classification.
    fn classify_response(
        status: u16,
        body_text: &str,
        url: &str,
        retry_after: Option<&str>,
    ) -> AttemptResult {
        match status {
            200 => Self::parse_ack(body_text),
            201..=299 => AttemptResult::Accepted,
            429 => AttemptResult::RateLimited {
                retry_after_seconds: parse_retry_after_seconds(
                    retry_after,
                    DEFAULT_RETRY_AFTER_SECS,
                ),
            },
            413 => AttemptResult::TooLarge {
                detail: summarize_response_body(body_text),
            },
            code if NON_RETRYABLE_STATUS_CODES.contains(&code) => AttemptResult::Permanent {
                status_code: code,
                detail: summarize_response_body(body_text),
            },
            401 | 403 => AttemptResult::Retryable {
                error: GuardAgentError::Transport(format!(
                    "Authentication failed: {status} for POST {url}"
                )),
            },
            500..=599 => AttemptResult::Retryable {
                error: GuardAgentError::Transport(format!(
                    "Server error {status} for POST {url}: {}",
                    summarize_response_body(body_text)
                )),
            },
            code => AttemptResult::Retryable {
                error: GuardAgentError::Transport(format!(
                    "Client error {code} for POST {url}: {}",
                    summarize_response_body(body_text)
                )),
            },
        }
    }

    /// Parses a 200 acknowledgement; `success == false` or a non-empty
    /// `errors` list means a partial failure that the flush layer requeues.
    fn parse_ack(body_text: &str) -> AttemptResult {
        if let Ok(ack) = serde_json::from_str::<TelemetryAck>(body_text) {
            let errors = ack.errors.unwrap_or_default();
            if ack.success == Some(false) || !errors.is_empty() {
                AttemptResult::PartialFailure { errors }
            } else {
                AttemptResult::Accepted
            }
        } else {
            log::warn!("200 response with unparseable JSON body; treating as transient failure");
            AttemptResult::Retryable {
                error: GuardAgentError::Transport(
                    "200 response with unparseable JSON body".to_owned(),
                ),
            }
        }
    }

    /// Fires the optional `on_error` hook, absorbing hook panics.
    fn fire_hook(&self, stage: ErrorStage, error: &GuardAgentError) {
        if let Some(hook) = &self.config.on_error {
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(stage, error)));
            if outcome.is_err() {
                log::error!("on_error hook raised while handling '{stage}'");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::float_cmp)]

    use super::*;
    use crate::config::AgentConfig;
    use crate::models::MetricType;

    fn transport_for_test() -> HttpTransport {
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = "http://127.0.0.1:1".to_owned();
        config.timeout = 1;
        config.retry_attempts = 0;
        config.compression_enabled = false;
        HttpTransport::new(Arc::new(config), "install-id-1").unwrap()
    }

    #[test]
    fn permanent_status_codes_are_exactly_the_python_set() {
        assert_eq!(NON_RETRYABLE_STATUS_CODES, [400, 404, 422]);
    }

    #[test]
    fn batch_items_len_label_and_split() {
        let events = BatchItems::Events(vec![
            SecurityEvent::new("a"),
            SecurityEvent::new("b"),
            SecurityEvent::new("c"),
        ]);
        assert_eq!(events.len(), 3);
        assert_eq!(events.label(), "events");
        assert_eq!(events.summary(), "3 event(s)");

        let (left, right) = events.split();
        match (left, right) {
            (BatchItems::Events(left), BatchItems::Events(right)) => {
                assert_eq!(left.len(), 1);
                assert_eq!(right.len(), 2);
                assert_eq!(left[0].event_type, "a");
                assert_eq!(right[0].event_type, "b");
            }
            _ => panic!("wrong variants"),
        }
    }

    #[test]
    fn metrics_split_preserves_order() {
        let metrics = BatchItems::Metrics(vec![
            SecurityMetric::new(MetricType::RequestCount, 1.0),
            SecurityMetric::new(MetricType::RequestCount, 2.0),
        ]);
        let (left, right) = metrics.split();
        match (left, right) {
            (BatchItems::Metrics(left), BatchItems::Metrics(right)) => {
                assert_eq!(left.len(), 1);
                assert_eq!(right.len(), 1);
                assert_eq!(left[0].value, 1.0);
                assert_eq!(right[0].value, 2.0);
            }
            _ => panic!("wrong variants"),
        }
    }

    #[test]
    fn batch_envelope_matches_the_python_shape() {
        let mut config = AgentConfig::new("test-api-key-1234");
        config.endpoint = "http://127.0.0.1:1".to_owned();
        config.guard_version = Some("1.2.3".to_owned());
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let body = transport
            .build_batch_body(&BatchItems::Events(vec![SecurityEvent::new(
                "rate_limited",
            )]))
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(value["project_id"], "default");
        assert_eq!(value["events"].as_array().unwrap().len(), 1);
        assert_eq!(value["metrics"].as_array().unwrap().len(), 0);
        assert_eq!(value["compressed"], false);
        assert_eq!(value["agent_version"], crate::AGENT_VERSION);
        assert_eq!(value["guard_version"], "1.2.3");
        assert!(value["guard_core_version"].is_null());
        let batch_id = value["batch_id"].as_str().unwrap();
        assert!(batch_id.contains('-'), "{batch_id}");
        assert!(value["created_at"].as_str().unwrap().contains('T'));
    }

    #[test]
    fn metrics_batch_places_items_under_metrics_key() {
        let transport = transport_for_test();
        let body = transport
            .build_batch_body(&BatchItems::Metrics(vec![SecurityMetric::new(
                MetricType::RequestCount,
                5.0,
            )]))
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["metrics"].as_array().unwrap().len(), 1);
        assert_eq!(value["events"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn compression_threshold_is_respected() {
        let mut config = AgentConfig::new("test-api-key-1234");
        config.compression_enabled = true;
        config.compression_threshold = 16;
        let transport = HttpTransport::new(Arc::new(config), "install-1").unwrap();

        let small = b"tiny";
        let (body, gzipped) = transport.maybe_compress(small);
        assert!(!gzipped);
        assert_eq!(body, small);

        let large = vec![b'a'; 64];
        let (body, gzipped) = transport.maybe_compress(&large);
        assert!(gzipped);
        assert!(body.len() < large.len());
    }

    #[test]
    fn classification_accepts_two_hundreds() {
        for status in [200, 201, 202, 204] {
            let body = if status == 200 {
                r#"{"success": true}"#
            } else {
                ""
            };
            let result = HttpTransport::classify_response(status, body, "http://x", None);
            assert!(matches!(result, AttemptResult::Accepted), "status {status}");
        }
    }

    #[test]
    fn classification_parses_partial_failure() {
        let result = HttpTransport::classify_response(
            200,
            r#"{"success": false, "errors": ["Event quota exceeded."]}"#,
            "http://x",
            None,
        );
        match result {
            AttemptResult::PartialFailure { errors } => {
                assert_eq!(errors, vec!["Event quota exceeded.".to_owned()]);
            }
            _ => panic!("expected partial failure"),
        }

        let errors_only = HttpTransport::classify_response(
            200,
            r#"{"errors": ["bad timestamp"]}"#,
            "http://x",
            None,
        );
        assert!(matches!(errors_only, AttemptResult::PartialFailure { .. }));

        let success_with_empty_errors =
            HttpTransport::classify_response(200, r#"{"errors": []}"#, "http://x", None);
        assert!(matches!(success_with_empty_errors, AttemptResult::Accepted));
    }

    #[test]
    fn classification_retries_unparseable_200() {
        let result = HttpTransport::classify_response(200, "not json", "http://x", None);
        assert!(matches!(result, AttemptResult::Retryable { .. }));
    }

    #[test]
    fn classification_retries_server_and_auth_errors() {
        for status in [401, 403, 500, 502, 503] {
            let result = HttpTransport::classify_response(status, "boom", "http://x", None);
            assert!(
                matches!(result, AttemptResult::Retryable { .. }),
                "status {status}"
            );
        }
    }

    #[test]
    fn classification_permanent_codes() {
        for status in NON_RETRYABLE_STATUS_CODES {
            let result = HttpTransport::classify_response(status, "nope", "http://x", None);
            match result {
                AttemptResult::Permanent {
                    status_code,
                    detail,
                } => {
                    assert_eq!(status_code, status);
                    assert_eq!(detail, "nope");
                }
                _ => panic!("expected permanent for {status}"),
            }
        }
    }

    #[test]
    fn classification_honors_retry_after_header() {
        let result = HttpTransport::classify_response(429, "slow down", "http://x", Some("7"));
        match result {
            AttemptResult::RateLimited {
                retry_after_seconds,
            } => {
                assert!((retry_after_seconds - 7.0).abs() < f64::EPSILON);
            }
            _ => panic!("expected rate limited"),
        }

        let defaulted = HttpTransport::classify_response(429, "slow down", "http://x", None);
        match defaulted {
            AttemptResult::RateLimited {
                retry_after_seconds,
            } => {
                assert!((retry_after_seconds - DEFAULT_RETRY_AFTER_SECS).abs() < f64::EPSILON);
            }
            _ => panic!("expected rate limited"),
        }
    }

    #[test]
    fn classification_flags_too_large() {
        let result =
            HttpTransport::classify_response(413, "Payload exceeds 262144 bytes", "http://x", None);
        match result {
            AttemptResult::TooLarge { detail } => {
                assert_eq!(detail, "Payload exceeds 262144 bytes");
            }
            _ => panic!("expected too large"),
        }
    }

    #[test]
    fn other_client_errors_are_retryable() {
        let result = HttpTransport::classify_response(409, "conflict", "http://x", None);
        assert!(matches!(result, AttemptResult::Retryable { .. }));
    }

    #[test]
    fn send_outcome_confirmed_matches_python_handshake() {
        assert!(SendOutcome::Accepted.is_confirmed());
        assert!(
            SendOutcome::PermanentDrop {
                status_code: 400,
                detail: "x".to_owned()
            }
            .is_confirmed()
        );
        assert!(
            !SendOutcome::Failed {
                error: GuardAgentError::Transport("x".to_owned())
            }
            .is_confirmed()
        );
    }

    #[test]
    fn transport_counters_start_at_zero() {
        let transport = transport_for_test();
        let (sent, failed, bytes) = transport.counters();
        assert_eq!((sent, failed, bytes), (0, 0, 0));
        assert_eq!(
            transport.breaker_state(),
            crate::circuit_breaker::CircuitBreakerState::Closed
        );
    }

    #[test]
    fn invalid_api_key_characters_are_rejected_without_panicking() {
        let mut config = AgentConfig::new("test-api-key-1234");
        config.api_key = "bad\nkey".to_owned();
        let result = HttpTransport::new(Arc::new(config), "install");
        assert!(matches!(result, Err(GuardAgentError::Transport(_))));
    }
}
