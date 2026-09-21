//! Persistence handshake tests using the in-memory `RedisHandler`
//! implementation. These run without any Redis server and validate the
//! at-least-once key lifecycle: persist on enqueue, retain on failure,
//! confirm on success, reload on startup.

mod helpers;

use std::sync::Arc;

use guard_agent_rs::{
    AgentConfig, BufferOverflowPolicy, GuardAgent, InMemoryRedisStore, MetricType, SecurityEvent,
    SecurityMetric,
};

const API_KEY: &str = "test-api-key-1234";

fn failing_config() -> AgentConfig {
    let mut config = AgentConfig::new(API_KEY);
    // Port 9 (discard) is not listening; connection is refused immediately.
    config.endpoint = String::from("http://127.0.0.1:9");
    config.install_id = Some("install-fake-redis".to_owned());
    config.timeout = 1;
    config.retry_attempts = 0;
    config.backoff_factor = 0.01;
    config.flush_interval = 3_600;
    config.status_interval = 3_600;
    config
}

fn mock_config(uri: String) -> AgentConfig {
    let mut config = AgentConfig::new(API_KEY);
    config.endpoint = uri;
    config.install_id = Some("install-fake-redis".to_owned());
    config.timeout = 2;
    config.retry_attempts = 0;
    config.flush_interval = 3_600;
    config.status_interval = 3_600;
    config
}

fn event(index: usize) -> SecurityEvent {
    SecurityEvent::new("rate_limited")
        .with_ip_address(format!("10.0.0.{index}"))
        .with_endpoint("/api/x")
}

#[tokio::test]
async fn enqueue_persists_and_failed_flush_retains_the_keys() {
    let store = Arc::new(InMemoryRedisStore::new());
    let agent = GuardAgent::new(failing_config()).unwrap();
    agent
        .attach_redis_handler(Arc::clone(&store) as Arc<_>)
        .await;

    agent.send_event(event(1)).await;
    agent.send_event(event(2)).await;

    assert_eq!(store.len(), 2, "both events persisted on enqueue");
    assert!(!agent.get_stats().await.durability_degraded);
    assert_eq!(store.keys(guard_agent_rs::NAMESPACE_EVENTS).len(), 2);

    agent.flush_buffer().await;

    let stats = agent.get_stats().await;
    assert_eq!(stats.events_failed, 2, "send failed");
    assert_eq!(stats.events_buffered, 2, "requeued in memory");
    assert_eq!(store.len(), 2, "durable records retained for retry");
}

#[tokio::test]
async fn reload_on_startup_and_confirm_on_success() {
    // Agent A fails against a dead endpoint, persisting records.
    let store = Arc::new(InMemoryRedisStore::new());
    let failing = GuardAgent::new(failing_config()).unwrap();
    failing
        .attach_redis_handler(Arc::clone(&store) as Arc<_>)
        .await;
    failing.send_event(event(1)).await;
    failing.flush_buffer().await;
    assert_eq!(store.len(), 1);

    // Agent B (healthy endpoint) reloads the record at startup, then the
    // successful flush confirms and deletes it.
    let mock = helpers::MockApi::start(helpers::Behavior::Success).await;
    let healthy = GuardAgent::new(mock_config(mock.uri())).unwrap();
    healthy
        .attach_redis_handler(Arc::clone(&store) as Arc<_>)
        .await;
    healthy.start().await;

    let stats = healthy.get_stats().await;
    assert_eq!(
        stats.events_buffered, 1,
        "startup reload restored the event"
    );
    assert_eq!(stats.events_failed, 0, "failure streaks do not transfer");

    healthy.flush_buffer().await;
    let stats = healthy.get_stats().await;
    assert_eq!(stats.events_sent, 1);
    assert_eq!(store.len(), 0, "durable record confirmed (deleted)");
    assert!(!stats.durability_degraded);

    healthy.stop().await;
}

#[tokio::test]
async fn drop_policy_confirms_the_evicted_record() {
    let store = Arc::new(InMemoryRedisStore::new());
    let mut config = failing_config();
    config.buffer_size = 1;
    config.buffer_overflow_policy = BufferOverflowPolicy::Drop;
    let agent = GuardAgent::new(config).unwrap();
    agent
        .attach_redis_handler(Arc::clone(&store) as Arc<_>)
        .await;

    agent.send_event(event(1)).await;
    agent.send_event(event(2)).await;

    let stats = agent.get_stats().await;
    assert_eq!(stats.events_buffered, 1, "capacity 1");
    assert_eq!(stats.events_dropped, 1, "oldest evicted");
    assert_eq!(store.len(), 1, "evicted record confirmed (deleted)");
}

#[tokio::test]
async fn clear_buffer_wipes_memory_and_durable_records() {
    let store = Arc::new(InMemoryRedisStore::new());
    let agent = GuardAgent::new(failing_config()).unwrap();
    agent
        .attach_redis_handler(Arc::clone(&store) as Arc<_>)
        .await;

    agent.send_event(event(1)).await;
    agent
        .send_metric(SecurityMetric::new(MetricType::RequestCount, 1.0))
        .await;
    assert_eq!(store.len(), 2);

    agent.clear_buffer().await;

    assert_eq!(store.len(), 0);
    assert_eq!(agent.get_stats().await.events_buffered, 0);
    assert_eq!(agent.get_stats().await.metrics_buffered, 0);
}

#[tokio::test]
async fn persistence_failures_are_fail_open() {
    // A handler that always fails; the agent must keep buffering and sending.
    struct AlwaysBroken;

    #[async_trait::async_trait]
    impl guard_agent_rs::RedisHandler for AlwaysBroken {
        async fn set_key(
            &self,
            _namespace: &str,
            _key: &str,
            _value: &str,
            _ttl_seconds: u64,
        ) -> Result<(), guard_agent_rs::GuardAgentError> {
            Err(guard_agent_rs::GuardAgentError::Redis("broken".to_owned()))
        }

        async fn get_key(
            &self,
            _namespace: &str,
            _key: &str,
        ) -> Result<Option<String>, guard_agent_rs::GuardAgentError> {
            Err(guard_agent_rs::GuardAgentError::Redis("broken".to_owned()))
        }

        async fn delete_keys(
            &self,
            _namespace: &str,
            _keys: &[String],
        ) -> Result<(), guard_agent_rs::GuardAgentError> {
            Err(guard_agent_rs::GuardAgentError::Redis("broken".to_owned()))
        }

        async fn list_keys(
            &self,
            _namespace: &str,
        ) -> Result<Vec<String>, guard_agent_rs::GuardAgentError> {
            Err(guard_agent_rs::GuardAgentError::Redis("broken".to_owned()))
        }

        async fn clear_namespace(
            &self,
            _namespace: &str,
        ) -> Result<(), guard_agent_rs::GuardAgentError> {
            Err(guard_agent_rs::GuardAgentError::Redis("broken".to_owned()))
        }
    }

    let mock = helpers::MockApi::start(helpers::Behavior::Success).await;
    let agent = GuardAgent::new(mock_config(mock.uri())).unwrap();
    agent
        .attach_redis_handler(Arc::new(AlwaysBroken) as Arc<_>)
        .await;

    agent.send_event(event(1)).await;
    agent.flush_buffer().await;

    let stats = agent.get_stats().await;
    assert_eq!(stats.events_sent, 1, "ingest path unaffected");
    assert_eq!(stats.redis_persist_failures, 1);
    assert!(stats.durability_degraded);
}
