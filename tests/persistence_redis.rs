//! Redis persistence integration tests against a real Redis server.
//!
//! These tests require Redis on `127.0.0.1:6379` and the `persistence`
//! feature. They are ignored by default; run them with:
//!
//! ```bash
//! cargo test --all-features --test persistence_redis -- --include-ignored
//! ```
//!
//! With the CI Redis service in place the same command runs there.

#![cfg(feature = "persistence")]

mod helpers;

use std::time::Duration;

use guard_agent_rs::{AgentConfig, GuardAgent, RedisConfig, SecurityEvent};
use redis::AsyncCommands as _;

const API_KEY: &str = "test-api-key-1234";
const REDIS_URL: &str = "redis://127.0.0.1:6379";

fn redis_config(prefix: &str) -> RedisConfig {
    RedisConfig {
        url: REDIS_URL.to_owned(),
        key_prefix: prefix.to_owned(),
        command_timeout_ms: 2_000,
    }
}

fn failing_agent_config(prefix: &str) -> AgentConfig {
    let mut config = AgentConfig::new(API_KEY);
    config.endpoint = String::from("http://127.0.0.1:9");
    config.install_id = Some("install-redis-test".to_owned());
    config.timeout = 1;
    config.retry_attempts = 0;
    config.backoff_factor = 0.01;
    config.flush_interval = 3_600;
    config.status_interval = 3_600;
    config.redis = Some(redis_config(prefix));
    config
}

fn event(index: usize) -> SecurityEvent {
    SecurityEvent::new("rate_limited")
        .with_ip_address(format!("10.0.0.{index}"))
        .with_endpoint("/api/x")
}

/// Opens a raw Redis connection for assertions.
async fn raw_connection() -> redis::aio::MultiplexedConnection {
    let client = redis::Client::open(REDIS_URL).expect("valid redis url");
    client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis must be reachable on 127.0.0.1:6379")
}

/// Lists keys under a prefix using raw KEYS.
async fn raw_keys(conn: &mut redis::aio::MultiplexedConnection, pattern: &str) -> Vec<String> {
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(pattern)
        .query_async(conn)
        .await
        .unwrap();
    let mut keys = keys;
    keys.sort();
    keys
}

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
#[ignore = "requires Redis on 127.0.0.1:6379; run with: cargo test --all-features -- --include-ignored"]
async fn persists_events_with_ttl_and_confirms_on_success() {
    let prefix = format!("guard-agent-rs-test:{}", uuid::Uuid::new_v4());
    let mock = helpers::MockApi::start(helpers::Behavior::Success).await;
    let mut config = AgentConfig::new(API_KEY);
    config.endpoint = mock.uri();
    config.install_id = Some("install-redis-test".to_owned());
    config.timeout = 2;
    config.retry_attempts = 0;
    config.flush_interval = 3_600;
    config.status_interval = 3_600;
    config.redis = Some(redis_config(&prefix));
    let agent = GuardAgent::new(config).unwrap();
    agent.start().await;

    for index in 0..3 {
        agent.send_event(event(index)).await;
    }

    let mut conn = raw_connection().await;
    let pattern = format!("{prefix}:agent_events:*");
    let keys = raw_keys(&mut conn, &pattern).await;
    assert_eq!(keys.len(), 3, "one record per event: {keys:?}");

    for key in &keys {
        let ttl: i64 = redis::cmd("TTL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap();
        let ttl_limit = guard_agent_rs::PERSIST_TTL_SECONDS.cast_signed();
        assert!(
            ttl > 0 && ttl <= ttl_limit,
            "TTL set to the persistence window, got {ttl}"
        );
        let value: String = conn.get(key).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&value).unwrap();
        assert_eq!(parsed["event_type"], "rate_limited");
    }

    agent.flush_buffer().await;
    let keys = raw_keys(&mut conn, &pattern).await;
    assert!(
        keys.is_empty(),
        "successful flush confirms (deletes) records"
    );

    agent.stop().await;
}

#[tokio::test]
#[ignore = "requires Redis on 127.0.0.1:6379; run with: cargo test --all-features -- --include-ignored"]
async fn retains_records_across_a_restart() {
    let prefix = format!("guard-agent-rs-test:{}", uuid::Uuid::new_v4());
    let pattern = format!("{prefix}:agent_events:*");

    // Agent A: endpoint down, so the flush fails and records are retained.
    let failing = GuardAgent::new(failing_agent_config(&prefix)).unwrap();
    failing.start().await;
    for index in 0..2 {
        failing.send_event(event(index)).await;
    }
    failing.flush_buffer().await;

    let mut conn = raw_connection().await;
    let keys = raw_keys(&mut conn, &pattern).await;
    assert_eq!(keys.len(), 2, "records retained after failed flush");
    drop(failing);

    // Agent B: healthy endpoint; startup reload restores the buffer.
    let mock = helpers::MockApi::start(helpers::Behavior::Success).await;
    let mut config = AgentConfig::new(API_KEY);
    config.endpoint = mock.uri();
    config.install_id = Some("install-redis-test".to_owned());
    config.timeout = 2;
    config.retry_attempts = 0;
    config.flush_interval = 3_600;
    config.status_interval = 3_600;
    config.redis = Some(redis_config(&prefix));
    let healthy = GuardAgent::new(config).unwrap();
    healthy.start().await;

    let stats = healthy.get_stats().await;
    assert_eq!(stats.events_buffered, 2, "reloaded from Redis on startup");

    healthy.flush_buffer().await;
    let delivered = wait_until(
        || mock.received_event_keys().len() == 2,
        Duration::from_secs(2),
    )
    .await;
    assert!(
        delivered,
        "reloaded events delivered: {:?}",
        mock.received_event_keys()
    );
    let keys = raw_keys(&mut conn, &pattern).await;
    assert!(keys.is_empty(), "records confirmed after delivery");

    healthy.stop().await;
}

#[tokio::test]
#[ignore = "requires Redis on 127.0.0.1:6379; run with: cargo test --all-features -- --include-ignored"]
async fn connection_failure_degrades_to_memory_only() {
    let prefix = format!("guard-agent-rs-test:{}", uuid::Uuid::new_v4());
    let mock = helpers::MockApi::start(helpers::Behavior::Success).await;
    let mut config = AgentConfig::new(API_KEY);
    config.endpoint = mock.uri();
    config.install_id = Some("install-redis-test".to_owned());
    config.timeout = 2;
    config.retry_attempts = 0;
    config.flush_interval = 3_600;
    config.status_interval = 3_600;
    // Unreachable Redis: startup degrades with a warning instead of failing.
    config.redis = Some(RedisConfig {
        url: "redis://127.0.0.1:9".to_owned(),
        key_prefix: prefix,
        command_timeout_ms: 500,
    });
    let agent = GuardAgent::new(config).unwrap();
    agent.start().await;

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 1, "telemetry still delivered");
    assert_eq!(stats.redis_persist_failures, 0, "no handler attached");
    assert!(!stats.durability_degraded);

    agent.stop().await;
}

#[tokio::test]
#[ignore = "requires Redis on 127.0.0.1:6379; run with: cargo test --all-features -- --include-ignored"]
async fn partial_failure_warning_mentions_redis_retention_with_redis() {
    helpers::init_log_capture();
    let prefix = format!("guard-agent-rs-test:{}", uuid::Uuid::new_v4());

    // Dead endpoint, so the flush fails while Redis records are retained.
    let agent = GuardAgent::new(failing_agent_config(&prefix)).unwrap();
    agent.start().await;

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    let warnings = helpers::captured_warnings();
    let warning = warnings
        .iter()
        .find(|message| message.contains("Failed to send 1 events"))
        .expect("partial-failure warning captured");
    assert!(
        warning.contains("requeued in memory and retained in Redis (events) for retry"),
        "warning must mention Redis retention when a Redis handler is attached: {warning}"
    );

    agent.stop().await;
}
