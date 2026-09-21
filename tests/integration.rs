//! End-to-end integration tests against a wiremock server that mirrors the
//! Guard ingestion API contract.

mod helpers;

use std::time::Duration;

use guard_agent_rs::{
    AGENT_VERSION, AgentConfig, AgentHealth, GuardAgent, MetricType, SecurityEvent, SecurityMetric,
};
use helpers::{Behavior, MockApi, expected_signature};

const API_KEY: &str = "test-api-key-1234";
const INSTALL_ID: &str = "install-test-0001";
const SIGNING_SECRET: &str = "test-signing-secret";

/// Base config pointed at a mock server with fast retries.
fn config_for(mock: &MockApi) -> AgentConfig {
    let mut config = AgentConfig::new(API_KEY);
    config.endpoint = mock.uri();
    config.install_id = Some(INSTALL_ID.to_owned());
    config.timeout = 5;
    config.retry_attempts = 3;
    config.backoff_factor = 0.01;
    config.payload_signing_secret = Some(SIGNING_SECRET.to_owned());
    config
}

fn event(index: usize) -> SecurityEvent {
    SecurityEvent::new("rate_limited")
        .with_ip_address(format!("10.0.0.{index}"))
        .with_endpoint("/api/users")
        .with_method("GET")
        .with_action_taken("blocked")
}

/// Polls a condition until it holds or the deadline passes.
async fn wait_until<F>(mut condition: F, deadline: Duration) -> bool
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    condition()
}

#[tokio::test]
async fn delivers_events_with_ingestion_headers_and_snake_case_body() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    let sent = event(1);
    agent.send_event(sent.clone()).await;
    agent.flush_buffer().await;

    let requests = mock.event_requests();
    assert_eq!(requests.len(), 1, "one batch request");
    let request = &requests[0];

    // Auth and identity headers from the verified contract.
    assert_eq!(request.header("x-api-key").as_deref(), Some(API_KEY));
    assert_eq!(
        request.header("x-agent-install-id").as_deref(),
        Some(INSTALL_ID)
    );
    assert_eq!(
        request.header("content-type").as_deref(),
        Some("application/json")
    );
    assert_eq!(
        request.header("user-agent").as_deref(),
        Some(format!("guard-agent-rs/{AGENT_VERSION}").as_str())
    );
    assert!(request.header("x-project-id").is_none());

    // Signature covers the uncompressed body, which is what the server
    // verifies after its gzip middleware decompresses.
    assert_eq!(
        request.header("x-payload-signature").as_deref(),
        Some(expected_signature(SIGNING_SECRET, &request.decompressed_body).as_str())
    );

    let body = request.json();
    assert_eq!(body["project_id"], "default");
    assert_eq!(body["compressed"], false);
    assert_eq!(body["agent_version"], AGENT_VERSION);
    assert!(body["guard_version"].is_null());
    assert_eq!(body["metrics"].as_array().unwrap().len(), 0);

    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "rate_limited");
    assert_eq!(events[0]["ip_address"], "10.0.0.1");
    assert_eq!(events[0]["endpoint"], "/api/users");
    assert_eq!(events[0]["action_taken"], "blocked");
    assert_eq!(
        events[0]["idempotency_key"],
        sent.idempotency_key.to_string()
    );
    assert!(events[0]["timestamp"].as_str().unwrap().contains('T'));
    assert!(events[0]["country"].is_null());

    let batch_id = body["batch_id"].as_str().unwrap();
    assert!(batch_id.contains('-'), "{batch_id}");

    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 1);
    assert_eq!(stats.events_buffered, 0);
    assert_eq!(stats.events_failed, 0);
    assert_eq!(stats.requests_sent, 1);
    assert!(stats.last_flush.is_some());
}

#[tokio::test]
async fn sends_project_header_and_payload_project_id_when_configured() {
    let mock = MockApi::start(Behavior::Success).await;
    let mut config = config_for(&mock);
    config.project_id = Some("proj_abc123".to_owned());
    let agent = GuardAgent::new(config).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    let request = &mock.event_requests()[0];
    assert_eq!(
        request.header("x-project-id").as_deref(),
        Some("proj_abc123")
    );
    assert_eq!(request.json()["project_id"], "proj_abc123");
}

#[tokio::test]
async fn gzip_compresses_large_batches_and_signs_the_plain_body() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    // Metadata above the 1024-byte compression threshold.
    let filler = "x".repeat(2_000);
    agent
        .send_event(
            SecurityEvent::new("suspicious_request")
                .with_metadata(serde_json::json!({ "payload": filler })),
        )
        .await;
    agent.flush_buffer().await;

    let request = &mock.event_requests()[0];
    assert_eq!(request.header("content-encoding").as_deref(), Some("gzip"));
    assert!(request.raw_body.len() < request.decompressed_body.len());
    assert_eq!(
        request.header("x-payload-signature").as_deref(),
        Some(expected_signature(SIGNING_SECRET, &request.decompressed_body).as_str())
    );
    assert_eq!(request.json()["events"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn small_batches_are_not_compressed_and_send_no_content_encoding() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    let request = &mock.event_requests()[0];
    assert!(request.header("content-encoding").is_none());
    assert_eq!(request.raw_body, request.decompressed_body);
}

#[tokio::test]
async fn signature_header_is_omitted_without_a_secret() {
    let mock = MockApi::start(Behavior::Success).await;
    let mut config = config_for(&mock);
    config.payload_signing_secret = None;
    let agent = GuardAgent::new(config).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    assert!(
        mock.event_requests()[0]
            .header("x-payload-signature")
            .is_none()
    );
}

#[tokio::test]
async fn metrics_go_to_the_metrics_endpoint() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent
        .send_metric(SecurityMetric::new(MetricType::RequestCount, 12.0).with_tag("route", "/x"))
        .await;
    agent.flush_buffer().await;

    assert!(mock.event_requests().is_empty());
    let requests = mock.metric_requests();
    assert_eq!(requests.len(), 1);
    let body = requests[0].json();
    assert_eq!(body["events"].as_array().unwrap().len(), 0);
    let metrics = body["metrics"].as_array().unwrap();
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0]["metric_type"], "request_count");
    assert_eq!(metrics[0]["value"], 12.0);
    assert_eq!(metrics[0]["tags"]["route"], "/x");

    let stats = agent.get_stats().await;
    assert_eq!(stats.metrics_sent, 1);
}

#[tokio::test]
async fn retries_server_errors_with_backoff_then_succeeds() {
    let mock = MockApi::start(Behavior::FailThenSuccess {
        status: 500,
        times: 2,
        body: "{\"detail\": \"boom\"}",
        retry_after: None,
    })
    .await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    let requests = mock.event_requests();
    assert_eq!(requests.len(), 3, "two failures plus one success");
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 1);
    assert_eq!(stats.events_failed, 0);
    assert_eq!(stats.requests_sent, 3);
    assert_eq!(stats.events_buffered, 0);
}

#[tokio::test]
async fn honors_retry_after_on_429() {
    let mock = MockApi::start(Behavior::FailThenSuccess {
        status: 429,
        times: 1,
        body: "{\"detail\": \"Too many requests\"}",
        retry_after: Some("1"),
    })
    .await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    let started = std::time::Instant::now();
    agent.flush_buffer().await;
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(900),
        "waited for Retry-After, elapsed {elapsed:?}"
    );
    assert_eq!(mock.event_requests().len(), 2);
    assert_eq!(agent.get_stats().await.events_sent, 1);
}

#[tokio::test]
async fn requeues_after_exhausting_retries() {
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 503,
        body: "{\"detail\": \"unavailable\"}",
    })
    .await;
    let mut config = config_for(&mock);
    config.retry_attempts = 2;
    config.flush_interval = 3_600; // no background pressure
    let agent = GuardAgent::new(config).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    assert_eq!(
        mock.event_requests().len(),
        3,
        "initial attempt plus 2 retries"
    );
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_failed, 1);
    assert_eq!(stats.events_buffered, 1, "requeued in memory");
    assert_eq!(stats.events_sent, 0);
    assert_eq!(stats.requests_failed, 1);

    // A second flush is gated by the per-kind backoff, so no new request.
    agent.flush_buffer().await;
    assert_eq!(mock.event_requests().len(), 3, "gated by streak backoff");
}

#[tokio::test]
async fn permanent_rejection_drops_the_batch_without_retrying() {
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 400,
        body: "{\"detail\": \"Malformed batch\"}",
    })
    .await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    assert_eq!(mock.event_requests().len(), 1, "no retries on 400");
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_buffered, 0, "intentionally dropped");
    assert_eq!(stats.events_failed, 0, "drop is not a failed send");
    assert_eq!(stats.events_sent, 0);

    // Nothing left to send.
    agent.flush_buffer().await;
    assert_eq!(mock.event_requests().len(), 1);
}

#[tokio::test]
async fn treats_partial_failure_200_as_requeue() {
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 200,
        body: "{\"success\": false, \"errors\": [\"Event quota exceeded. Upgrade your plan.\"]}",
    })
    .await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    assert_eq!(
        mock.event_requests().len(),
        1,
        "200 is terminal, no in-loop retry"
    );
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_failed, 1);
    assert_eq!(stats.events_buffered, 1);
}

#[tokio::test]
async fn splits_on_413_until_each_half_fits() {
    let mock = MockApi::start(Behavior::TooLargeAbove { threshold: 2 }).await;
    let mut config = config_for(&mock);
    config.buffer_size = 10;
    let agent = GuardAgent::new(config).unwrap();

    let mut keys = Vec::new();
    for index in 0..4 {
        let item = event(index);
        keys.push(item.idempotency_key.to_string());
        agent.send_event(item).await;
    }
    agent.flush_buffer().await;

    let requests = mock.event_requests();
    assert_eq!(requests.len(), 3, "4 items rejected, then 2 + 2 accepted");
    assert_eq!(requests[0].json()["events"].as_array().unwrap().len(), 4);

    let mut received = mock.received_event_keys();
    received.sort();
    keys.sort();
    assert_eq!(received, keys, "every event delivered exactly once");
    assert_eq!(agent.get_stats().await.events_sent, 4);
    assert_eq!(agent.get_stats().await.events_buffered, 0);
}

#[tokio::test]
async fn drops_a_singleton_that_still_exceeds_the_cap() {
    let mock = MockApi::start(Behavior::AlwaysTooLarge).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    assert_eq!(mock.event_requests().len(), 1, "singleton is not split");
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_buffered, 0, "dropped, not requeued");
    assert_eq!(
        stats.events_failed, 0,
        "intentional drop counts as confirmed"
    );
}

#[tokio::test]
async fn auth_failures_are_retried_like_the_python_agent() {
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 401,
        body: "{\"detail\": \"Invalid API key or project ID\"}",
    })
    .await;
    let mut config = config_for(&mock);
    config.retry_attempts = 1;
    let agent = GuardAgent::new(config).unwrap();

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    assert_eq!(
        mock.event_requests().len(),
        2,
        "401 is retryable, not permanent"
    );
    assert_eq!(agent.get_stats().await.events_buffered, 1);
}

#[tokio::test]
async fn status_push_posts_the_agent_status_payload() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.push_status().await;

    let requests = mock.status_requests();
    assert_eq!(requests.len(), 1);
    let body = requests[0].json();
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["events_sent"], 0);
    assert_eq!(body["buffer_size"], 0);
    assert!(body["uptime"].as_f64().unwrap() >= 0.0);
    assert!(body["last_flush"].is_null());

    let stats = agent.get_stats().await;
    assert_eq!(stats.last_status_push_ok, Some(true));
    assert_eq!(stats.status_consecutive_failures, 0);
}

#[tokio::test]
async fn status_push_failures_are_counted_not_propagated() {
    let mock = MockApi::start(Behavior::AlwaysFail {
        status: 500,
        body: "boom",
    })
    .await;
    let mut config = config_for(&mock);
    config.retry_attempts = 0;
    let agent = GuardAgent::new(config).unwrap();

    agent.push_status().await;
    agent.push_status().await;

    let stats = agent.get_stats().await;
    assert_eq!(stats.last_status_push_ok, Some(false));
    assert_eq!(stats.status_consecutive_failures, 2);
    assert_eq!(stats.loop_failures.status, 2);
}

#[tokio::test]
async fn endpoint_down_isolates_failures_and_reports_degraded() {
    let mut config = AgentConfig::new(API_KEY);
    // Port 9 (discard) is not listening; connection is refused immediately.
    config.endpoint = "http://127.0.0.1:9".to_owned();
    config.install_id = Some(INSTALL_ID.to_owned());
    config.timeout = 1;
    // Enough attempts in a single flush to trip the breaker threshold (5).
    config.retry_attempts = 6;
    config.backoff_factor = 0.01;
    config.flush_interval = 3_600;
    config.status_interval = 3_600;
    let agent = GuardAgent::new(config).unwrap();
    agent.start().await;

    // Ingest must never fail or panic, even with the endpoint down.
    for index in 0..3 {
        agent.send_event(event(index)).await;
    }
    agent.flush_buffer().await;

    let stats = agent.get_stats().await;
    assert_eq!(stats.events_failed, 3, "batch requeued");
    assert_eq!(stats.events_buffered, 3, "events survive the outage");
    assert!(stats.requests_failed >= 1);

    let health = agent.get_status().await;
    assert_eq!(health.status, AgentHealth::Degraded);
    assert!(
        health
            .errors
            .iter()
            .any(|error| error.contains("High failure rate")),
        "{:?}",
        health.errors
    );
    assert_eq!(
        stats.circuit_breaker_state.as_str(),
        "OPEN",
        "breaker opens after repeated transport failures"
    );
    assert!(
        health
            .errors
            .iter()
            .any(|error| error == "Transport circuit breaker is open"),
        "{:?}",
        health.errors
    );
    assert!(
        !agent.health_check().await,
        "unhealthy under a total outage"
    );

    agent.stop().await;
}

#[tokio::test]
async fn shutdown_flush_delivers_buffered_events() {
    let mock = MockApi::start(Behavior::Success).await;
    let mut config = config_for(&mock);
    config.flush_interval = 3_600;
    config.status_interval = 3_600;
    let agent = GuardAgent::new(config).unwrap();
    agent.start().await;

    agent.send_event(event(1)).await;
    agent.send_event(event(2)).await;
    assert!(mock.event_requests().is_empty(), "no flush yet");

    agent.stop().await;

    let received = mock.received_event_keys();
    assert_eq!(received.len(), 2, "final flush on shutdown");
    let stats = agent.get_stats().await;
    assert!(!stats.running);
    assert_eq!(stats.events_buffered, 0);
}

#[tokio::test]
async fn watermark_triggers_an_early_flush() {
    let mock = MockApi::start(Behavior::Success).await;
    let mut config = config_for(&mock);
    config.buffer_size = 10;
    config.high_watermark_ratio = 0.8;
    config.flush_interval = 3_600; // only the watermark can trigger a flush
    config.status_interval = 3_600;
    let agent = GuardAgent::new(config).unwrap();
    agent.start().await;

    for index in 0..8 {
        agent.send_event(event(index)).await;
    }

    let delivered = wait_until(
        || mock.received_event_keys().len() == 8,
        Duration::from_secs(3),
    )
    .await;
    assert!(delivered, "watermark flush delivered the batch");
    assert_eq!(agent.get_stats().await.events_buffered, 0);

    agent.stop().await;
}

#[tokio::test]
async fn flush_interval_triggers_a_time_based_flush() {
    let mock = MockApi::start(Behavior::Success).await;
    let mut config = config_for(&mock);
    config.flush_interval = 1;
    config.status_interval = 3_600;
    let agent = GuardAgent::new(config).unwrap();
    agent.start().await;

    agent.send_event(event(1)).await;

    let delivered = wait_until(
        || mock.received_event_keys().len() == 1,
        Duration::from_secs(4),
    )
    .await;
    assert!(delivered, "time trigger flushed the buffer");

    agent.stop().await;
}

#[tokio::test]
async fn redaction_happens_before_buffering_and_on_the_wire() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent
        .send_event(
            SecurityEvent::new("auth_failure").with_metadata(serde_json::json!({
                "authorization": "Bearer super-secret",
                "nested": { "X-API-Key": "key-material" },
                "safe": "value"
            })),
        )
        .await;
    agent.flush_buffer().await;

    let body = mock.event_requests()[0].json();
    let metadata = &body["events"][0]["metadata"];
    assert_eq!(metadata["authorization"], "[REDACTED]");
    assert_eq!(metadata["nested"]["X-API-Key"], "[REDACTED]");
    assert_eq!(metadata["safe"], "value");
}

#[tokio::test]
async fn metrics_and_events_flush_independently() {
    let mock = MockApi::start(Behavior::Success).await;
    let agent = GuardAgent::new(config_for(&mock)).unwrap();

    agent.send_event(event(1)).await;
    agent
        .send_metric(SecurityMetric::new(MetricType::ErrorRate, 0.5))
        .await;
    agent.flush_buffer().await;

    assert_eq!(mock.event_requests().len(), 1);
    assert_eq!(mock.metric_requests().len(), 1);
    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 1);
    assert_eq!(stats.metrics_sent, 1);
    assert_eq!(stats.events_flushed, 1);
    assert_eq!(stats.metrics_flushed, 1);
    assert!(stats.bytes_sent > 0);
}
