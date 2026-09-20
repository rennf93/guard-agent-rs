//! Shared helpers: backoff math, `Retry-After` parsing, payload redaction,
//! batch identifiers, and gzip compression.

use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::Value;
use uuid::Uuid;

/// Maximum depth walked when redacting nested structured data.
pub const MAX_REDACT_DEPTH: usize = 10;

/// Maximum response body length kept in error details.
pub const MAX_DETAIL_CHARS: usize = 300;

/// Placeholder substituted for redacted values.
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// Computes `min(base * 2^attempt, max)`.
///
/// Mirrors `calculate_backoff_delay` in the Python agent: no jitter, and the
/// cap applies to the final value.
#[must_use]
pub fn calculate_backoff_delay(attempt: u32, base: f64, max: f64) -> f64 {
    let exponent = i32::try_from(attempt).unwrap_or(i32::MAX);
    let raw = base * 2_f64.powi(exponent);
    if raw.is_finite() { raw.min(max) } else { max }
}

/// Parses a `Retry-After` header value into seconds.
///
/// Mirrors the Python agent: only the delay-seconds form is parsed, HTTP dates
/// fall back to `default`, and negative values clamp to zero.
#[must_use]
pub fn parse_retry_after_seconds(header: Option<&str>, default: f64) -> f64 {
    let Some(raw) = header else {
        return default;
    };
    match raw.trim().parse::<f64>() {
        Ok(seconds) if seconds.is_finite() => seconds.max(0.0),
        _ => default,
    }
}

/// Generates a batch identifier in the Python agent's format:
/// `<epoch-millis>-<8 hex chars>`.
#[must_use]
pub fn generate_batch_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |delta| delta.as_millis());
    let uuid = Uuid::new_v4().simple().to_string();
    let suffix = &uuid[..8];
    format!("{millis}-{suffix}")
}

/// Generates a short, collision-resistant Redis key suffix in the Python
/// agent's format: `<prefix>_<nanos>_<8 hex chars>`.
#[must_use]
pub fn generate_short_key(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |delta| delta.as_nanos());
    let uuid = Uuid::new_v4().simple().to_string();
    let suffix = &uuid[..8];
    format!("{prefix}_{nanos}_{suffix}")
}

/// Collapses a response body into a single line, truncated for error details.
#[must_use]
pub fn summarize_response_body(body: &str) -> String {
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= MAX_DETAIL_CHARS {
        return collapsed;
    }
    let truncated: String = collapsed.chars().take(MAX_DETAIL_CHARS).collect();
    format!("{truncated}...")
}

/// Compresses a payload with gzip at the default level.
#[must_use]
pub fn gzip_bytes(body: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    // Writing into a `Vec` cannot fail, and `finish` only surfaces that
    // impossible I/O error; fall back to the raw payload instead of panicking.
    if encoder.write_all(body).is_err() {
        return body.to_vec();
    }
    encoder.finish().unwrap_or_else(|_| body.to_vec())
}

/// Redacts sensitive keys from event metadata and metric tags.
#[derive(Debug, Clone)]
pub struct Redactor {
    keys: Vec<String>,
}

impl Redactor {
    /// Builds a redactor from configured sensitive key names.
    ///
    /// Keys are compared case-insensitively after trimming whitespace; empty
    /// entries are ignored.
    #[must_use]
    pub fn new(sensitive_keys: &[String]) -> Self {
        let keys = sensitive_keys
            .iter()
            .map(|key| key.trim().to_lowercase())
            .filter(|key| !key.is_empty())
            .collect();
        Self { keys }
    }

    /// Returns `true` when the key is sensitive.
    #[must_use]
    pub fn is_sensitive(&self, key: &str) -> bool {
        let normalized = key.trim().to_lowercase();
        self.keys.contains(&normalized)
    }

    /// Recursively redacts sensitive keys inside a JSON value.
    pub fn redact_value(&self, value: &mut Value) {
        self.redact_inner(value, 0);
    }

    fn redact_inner(&self, value: &mut Value, depth: usize) {
        if depth >= MAX_REDACT_DEPTH {
            return;
        }
        match value {
            Value::Object(map) => {
                for (key, entry) in map.iter_mut() {
                    if self.is_sensitive(key) {
                        *entry = Value::String(REDACTED_PLACEHOLDER.to_owned());
                    } else {
                        self.redact_inner(entry, depth + 1);
                    }
                }
            }
            Value::Array(items) => {
                for entry in items.iter_mut() {
                    self.redact_inner(entry, depth + 1);
                }
            }
            _ => {}
        }
    }

    /// Redacts sensitive keys from a flat string map.
    pub fn redact_tags(&self, tags: &mut std::collections::BTreeMap<String, String>) {
        for (key, value) in tags.iter_mut() {
            if self.is_sensitive(key) {
                REDACTED_PLACEHOLDER.clone_into(value);
            }
        }
    }
}

/// Types whose sensitive fields are redacted before buffering.
pub(crate) trait Redactable {
    /// Redacts sensitive keys in place.
    fn redact(&mut self, redactor: &Redactor);
}

impl Redactable for crate::models::SecurityEvent {
    fn redact(&mut self, redactor: &Redactor) {
        redactor.redact_value(&mut self.metadata);
    }
}

impl Redactable for crate::models::SecurityMetric {
    fn redact(&mut self, redactor: &Redactor) {
        redactor.redact_tags(&mut self.tags);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn backoff_doubles_and_caps() {
        assert!((calculate_backoff_delay(0, 1.0, 60.0) - 1.0).abs() < f64::EPSILON);
        assert!((calculate_backoff_delay(1, 1.0, 60.0) - 2.0).abs() < f64::EPSILON);
        assert!((calculate_backoff_delay(5, 1.0, 60.0) - 32.0).abs() < f64::EPSILON);
        assert!((calculate_backoff_delay(10, 1.0, 60.0) - 60.0).abs() < f64::EPSILON);
        // Flush level streak backoff uses the flush interval as the base.
        assert!((calculate_backoff_delay(0, 30.0, 300.0) - 30.0).abs() < f64::EPSILON);
        assert!((calculate_backoff_delay(3, 30.0, 300.0) - 240.0).abs() < f64::EPSILON);
        assert!((calculate_backoff_delay(4, 30.0, 300.0) - 300.0).abs() < f64::EPSILON);
    }

    #[test]
    fn backoff_saturates_instead_of_overflowing() {
        assert!((calculate_backoff_delay(u32::MAX, 1.0, 60.0) - 60.0).abs() < f64::EPSILON);
    }

    #[test]
    fn retry_after_parsing_matches_python() {
        assert!((parse_retry_after_seconds(Some("30"), 60.0) - 30.0).abs() < f64::EPSILON);
        assert!((parse_retry_after_seconds(Some("0.5"), 60.0) - 0.5).abs() < f64::EPSILON);
        assert!((parse_retry_after_seconds(None, 60.0) - 60.0).abs() < f64::EPSILON);
        assert!((parse_retry_after_seconds(Some("soon"), 60.0) - 60.0).abs() < f64::EPSILON);
        // HTTP dates are not parsed, matching the Python agent.
        assert!(
            (parse_retry_after_seconds(Some("Wed, 21 Oct 2026 07:28:00 GMT"), 60.0) - 60.0).abs()
                < f64::EPSILON
        );
        assert!((parse_retry_after_seconds(Some("-5"), 60.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn batch_id_has_the_python_shape() {
        let batch_id = generate_batch_id();
        let (millis, suffix) = batch_id.split_once('-').unwrap();
        assert!(millis.parse::<u128>().is_ok());
        assert_eq!(suffix.len(), 8);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn short_key_has_the_python_shape() {
        let key = generate_short_key("event");
        let parts: Vec<&str> = key.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "event");
        assert!(parts[1].parse::<u128>().is_ok());
        assert_eq!(parts[2].len(), 8);
    }

    #[test]
    fn short_keys_are_unique() {
        let first = generate_short_key("event");
        let second = generate_short_key("event");
        assert_ne!(first, second);
    }

    #[test]
    fn response_body_summary_collapses_and_truncates() {
        assert_eq!(summarize_response_body("a\n b\tc"), "a b c");
        let long = "x".repeat(MAX_DETAIL_CHARS + 50);
        let summary = summarize_response_body(&long);
        assert_eq!(summary.chars().count(), MAX_DETAIL_CHARS + 3);
        assert!(summary.ends_with("..."));
    }

    #[test]
    fn gzip_round_trips_and_shrinks_repetitive_payloads() {
        let payload =
            br#"{"events":[{"a":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#;
        let compressed = gzip_bytes(payload);
        assert_ne!(compressed, payload);
        // gzip magic bytes.
        assert_eq!(&compressed[..2], &[0x1f, 0x8b]);
        let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
        let mut restored = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut restored).unwrap();
        assert_eq!(restored, payload);
    }

    #[test]
    fn redactor_matches_keys_case_insensitively() {
        let redactor = Redactor::new(&["Authorization".to_owned(), " x-api-key ".to_owned()]);
        assert!(redactor.is_sensitive("authorization"));
        assert!(redactor.is_sensitive("X-API-Key"));
        assert!(!redactor.is_sensitive("user-agent"));
        assert!(!Redactor::new(&["  ".to_owned()]).is_sensitive("anything"));
    }

    #[test]
    fn redactor_walks_nested_metadata() {
        let redactor = Redactor::new(&["authorization".to_owned(), "cookie".to_owned()]);
        let mut value = json!({
            "rule": "rl-1",
            "headers": {
                "Authorization": "Bearer token",
                "Cookie": "session=abc",
                "Accept": "application/json"
            },
            "chain": [{"cookie": "nested=1"}, {"safe": "value"}]
        });
        redactor.redact_value(&mut value);

        assert_eq!(value["headers"]["Authorization"], REDACTED_PLACEHOLDER);
        assert_eq!(value["headers"]["Cookie"], REDACTED_PLACEHOLDER);
        assert_eq!(value["headers"]["Accept"], "application/json");
        assert_eq!(value["chain"][0]["cookie"], REDACTED_PLACEHOLDER);
        assert_eq!(value["chain"][1]["safe"], "value");
        assert_eq!(value["rule"], "rl-1");
    }

    #[test]
    fn redactor_stops_at_max_depth() {
        let redactor = Redactor::new(&["cookie".to_owned()]);
        // Build a chain deeper than the walk limit.
        let mut value = json!({"cookie": "deep"});
        for _ in 0..(MAX_REDACT_DEPTH + 2) {
            value = json!({"level": value});
        }
        redactor.redact_value(&mut value);
        let mut cursor = &value;
        for _ in 0..(MAX_REDACT_DEPTH + 2) {
            cursor = &cursor["level"];
        }
        assert_eq!(cursor["cookie"], "deep");
    }

    #[test]
    fn redactor_handles_event_metadata_and_metric_tags() {
        use crate::models::{MetricType, SecurityEvent, SecurityMetric};

        let redactor = Redactor::new(&["x-api-key".to_owned()]);

        let mut event = SecurityEvent::new("test").with_metadata(json!({"X-Api-Key": "secret"}));
        event.redact(&redactor);
        assert_eq!(event.metadata["X-Api-Key"], REDACTED_PLACEHOLDER);

        let mut metric =
            SecurityMetric::new(MetricType::RequestCount, 1.0).with_tag("X-API-KEY", "secret");
        metric.redact(&redactor);
        assert_eq!(metric.tags["X-API-KEY"], REDACTED_PLACEHOLDER);
    }
}
