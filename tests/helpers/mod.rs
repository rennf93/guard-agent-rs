//! Mock Guard ingestion server used by the integration tests.
//!
//! Mirrors the verified contract of `guard-core-app/backend/guard-core-api`:
//!
//! - `POST /api/v1/events`, `/api/v1/metrics`, `/api/v1/status`
//! - success is HTTP 200 with a `TelemetryResponse` body
//! - `Content-Encoding: gzip` bodies are decompressed before the handler sees
//!   them (`GzipRequestMiddleware`), including for signature verification
//! - `X-Payload-Signature: v1=<hex>` is HMAC-SHA256 over the decompressed body
//! - 413 is returned when the decompressed payload exceeds the size cap
//!
//! A pluggable [`Behavior`] drives failure injection per request. The module
//! is compiled into every integration test binary, so not all items are used
//! by each binary.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

use hmac::{Hmac, Mac as _};
use log::{Level, Metadata, Record};
use sha2::Sha256;
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

/// Warnings captured by [`CapturingLogger`], shared by the test binary.
static WARNINGS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

/// A `log` facade implementation that records warning-level messages so
/// tests can assert on log content.
struct CapturingLogger;

impl log::Log for CapturingLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= Level::Warn
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata())
            && let Some(records) = WARNINGS.get()
        {
            records
                .lock()
                .expect("warning buffer is not poisoned")
                .push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

/// Installs the process-wide capturing logger exactly once (the `log` facade
/// allows a single logger per process).
pub fn init_log_capture() {
    static SETUP: std::sync::Once = std::sync::Once::new();
    SETUP.call_once(|| {
        let _ = WARNINGS.set(Mutex::new(Vec::new()));
        let _ = log::set_boxed_logger(Box::new(CapturingLogger));
        log::set_max_level(log::LevelFilter::Warn);
    });
}

/// Returns every warning captured since the capturing logger was installed.
pub fn captured_warnings() -> Vec<String> {
    init_log_capture();
    WARNINGS
        .get()
        .map(|records| {
            records
                .lock()
                .expect("warning buffer is not poisoned")
                .clone()
        })
        .unwrap_or_default()
}

/// Capture of one request seen by the mock server.
#[derive(Clone, Debug)]
pub struct Captured {
    /// Request path, for example `/api/v1/events`.
    pub path: String,
    /// All request headers.
    pub headers: wiremock::http::HeaderMap,
    /// Body exactly as sent on the wire.
    pub raw_body: Vec<u8>,
    /// Body after gzip decompression (or equal to `raw_body`).
    pub decompressed_body: Vec<u8>,
    /// Status code the mock answered with.
    pub response_status: u16,
}

impl Captured {
    /// Header value by name, case-insensitive.
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }

    /// Parses the decompressed body as JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.decompressed_body).expect("captured body is valid JSON")
    }
}

/// Failure injection mode of the mock server.
#[derive(Debug, Clone, Default)]
pub enum Behavior {
    /// Always return a 200 success acknowledgement.
    #[default]
    Success,
    /// Return `status` with `body` for the first `times` batch requests, then
    /// 200 success.
    FailThenSuccess {
        status: u16,
        times: u32,
        body: &'static str,
        /// Optional `Retry-After` header value for the failing responses.
        retry_after: Option<&'static str>,
    },
    /// Return the status for every batch request.
    AlwaysFail { status: u16, body: &'static str },
    /// Return 413 for batch requests whose decompressed JSON holds more than
    /// `threshold` items under the batch's own kind key.
    TooLargeAbove { threshold: usize },
    /// Return 413 for every batch request.
    AlwaysTooLarge,
}

struct MockState {
    behavior: Behavior,
    requests: Vec<Captured>,
    batch_requests_seen: u32,
}

/// Wiremock-backed Guard ingestion API.
pub struct MockApi {
    server: MockServer,
    state: Arc<Mutex<MockState>>,
}

impl MockApi {
    /// Starts a mock server with the given behavior.
    pub async fn start(behavior: Behavior) -> Self {
        let state = Arc::new(Mutex::new(MockState {
            behavior,
            requests: Vec::new(),
            batch_requests_seen: 0,
        }));

        let handler_state = Arc::clone(&state);
        let mock = Mock::given(PathPrefixMatcher::new("/api/v1/")).respond_with(
            move |request: &Request| {
                let mut state = handler_state.lock().unwrap();
                let captured = capture(request);
                let route =
                    if captured.path == "/api/v1/events" || captured.path == "/api/v1/metrics" {
                        Route::Batch
                    } else {
                        Route::Status
                    };
                if route == Route::Batch {
                    state.batch_requests_seen += 1;
                }
                let behavior = state.behavior.clone();
                let seen = state.batch_requests_seen;
                let (status, response) = respond(&behavior, route, seen, &captured);
                state.requests.push(Captured {
                    response_status: status,
                    ..captured
                });
                response
            },
        );

        let server = MockServer::start().await;
        mock.mount(&server).await;
        Self { server, state }
    }

    /// Base URL for `AgentConfig::endpoint`.
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Every captured request so far.
    pub fn captured(&self) -> Vec<Captured> {
        self.state.lock().unwrap().requests.clone()
    }

    /// Captured requests to `/api/v1/events`.
    pub fn event_requests(&self) -> Vec<Captured> {
        self.filter_path("/api/v1/events")
    }

    /// Captured requests to `/api/v1/metrics`.
    #[allow(dead_code)]
    pub fn metric_requests(&self) -> Vec<Captured> {
        self.filter_path("/api/v1/metrics")
    }

    /// Captured requests to `/api/v1/status`.
    pub fn status_requests(&self) -> Vec<Captured> {
        self.filter_path("/api/v1/status")
    }

    /// All captured event idempotency keys across batches the server accepted.
    pub fn received_event_keys(&self) -> Vec<String> {
        self.event_requests()
            .iter()
            .filter(|captured| (200..300).contains(&captured.response_status))
            .filter_map(|captured| {
                let value = captured.json();
                let events = value["events"].as_array()?.clone();
                Some(
                    events
                        .iter()
                        .map(|event| event["idempotency_key"].as_str().unwrap().to_owned())
                        .collect::<Vec<_>>(),
                )
            })
            .flatten()
            .collect()
    }

    fn filter_path(&self, path: &str) -> Vec<Captured> {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|captured| captured.path == path)
            .cloned()
            .collect()
    }
}

/// Matcher matching any path with the given prefix.
struct PathPrefixMatcher {
    prefix: &'static str,
}

impl PathPrefixMatcher {
    const fn new(prefix: &'static str) -> Self {
        Self { prefix }
    }
}

impl Match for PathPrefixMatcher {
    fn matches(&self, request: &Request) -> bool {
        request.url.path().starts_with(self.prefix)
    }
}

fn capture(request: &Request) -> Captured {
    let gzipped = request
        .headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("gzip"));
    let decompressed_body = if gzipped {
        let mut decoder = flate2::read::GzDecoder::new(&request.body[..]);
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut buffer).expect("valid gzip body");
        buffer
    } else {
        request.body.clone()
    };
    Captured {
        path: request.url.path().to_owned(),
        headers: request.headers.clone(),
        raw_body: request.body.clone(),
        decompressed_body,
        response_status: 0,
    }
}

/// Which ingestion route a captured request targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Batch,
    Status,
}

/// Builds the response for one request according to the behavior, returning
/// the status code alongside the template.
fn respond(
    behavior: &Behavior,
    route: Route,
    batch_requests_seen: u32,
    captured: &Captured,
) -> (u16, ResponseTemplate) {
    match behavior {
        Behavior::Success => {
            if route == Route::Batch {
                (200, json_response(200, SUCCESS_BODY))
            } else {
                (200, json_response(200, STATUS_SUCCESS_BODY))
            }
        }
        Behavior::FailThenSuccess {
            status,
            times,
            body,
            retry_after,
        } => {
            if batch_requests_seen <= *times {
                let mut response = ResponseTemplate::new(*status)
                    .set_body_raw(body.as_bytes().to_vec(), "application/json");
                if let Some(retry_after) = retry_after {
                    response = response.insert_header("Retry-After", *retry_after);
                }
                (*status, response)
            } else {
                success_for(route)
            }
        }
        Behavior::AlwaysFail { status, body } => (
            *status,
            ResponseTemplate::new(*status)
                .set_body_raw(body.as_bytes().to_vec(), "application/json"),
        ),
        Behavior::TooLargeAbove { threshold } => {
            if route == Route::Batch && batch_item_count(captured) > *threshold {
                (
                    413,
                    ResponseTemplate::new(413).set_body_raw(
                        b"{\"detail\": \"Payload exceeds 262144 bytes\"}".to_vec(),
                        "application/json",
                    ),
                )
            } else {
                success_for(route)
            }
        }
        Behavior::AlwaysTooLarge => {
            if route == Route::Batch {
                (
                    413,
                    ResponseTemplate::new(413).set_body_raw(
                        b"{\"detail\": \"Payload exceeds 262144 bytes\"}".to_vec(),
                        "application/json",
                    ),
                )
            } else {
                success_for(route)
            }
        }
    }
}

fn success_for(route: Route) -> (u16, ResponseTemplate) {
    if route == Route::Batch {
        (200, json_response(200, SUCCESS_BODY))
    } else {
        (200, json_response(200, STATUS_SUCCESS_BODY))
    }
}

const SUCCESS_BODY: &[u8] =
    br#"{"success": true, "events_received": 1, "events_dropped_invalid_timestamp": 0, "metrics_received": 0, "events_processed": 1, "metrics_processed": 0, "errors": null}"#;

const STATUS_SUCCESS_BODY: &[u8] = br#"{"success": true, "message": "Status received"}"#;

fn json_response(status: u16, body: &[u8]) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(body.to_vec(), "application/json")
}

/// Counts items in the decompressed batch under whichever kind key is
/// non-empty.
fn batch_item_count(captured: &Captured) -> usize {
    let value: serde_json::Value = serde_json::from_slice(&captured.decompressed_body).unwrap();
    let events = value["events"].as_array().map_or(0, Vec::len);
    let metrics = value["metrics"].as_array().map_or(0, Vec::len);
    events + metrics
}

/// Computes the `v1=<hex>` signature the real server expects: HMAC-SHA256 of
/// the decompressed body.
pub fn expected_signature(secret: &str, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body);
    format!("v1={}", hex_encode(&mac.finalize().into_bytes()))
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing into a `String` never fails.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}
