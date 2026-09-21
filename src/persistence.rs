//! Optional buffer persistence.
//!
//! Every accepted event and metric can be written to a durable store before it
//! is buffered, so a process crash does not lose telemetry that the ingestion
//! API never acknowledged. The handshake is at-least-once: records are written
//! on enqueue, deleted only after the server confirms the batch, and reloaded
//! into the in-memory buffer on startup.
//!
//! Persistence is fail-open. Any store error increments
//! `redis_persist_failures` (surfaced through
//! [`AgentStats`](crate::AgentStats)), logs a warning, and leaves the event in
//! memory; it never blocks or fails a `send_*` call.
//!
//! Two backends ship in the crate:
//!
//! - [`InMemoryRedisStore`], always available, useful for tests and for
//!   embedding.
//! - [`RedisClientHandler`], behind the `persistence` feature, wrapping the
//!   `redis` crate's multiplexed async connection.
//!
//! Callers may also implement [`RedisHandler`] themselves and attach it with
//! [`GuardAgent::attach_redis_handler`](crate::GuardAgent::attach_redis_handler),
//! mirroring the Python agent's injected handler protocol.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::GuardAgentError;
use async_trait::async_trait;

/// Namespace for persisted events.
pub const NAMESPACE_EVENTS: &str = "agent_events";

/// Namespace for persisted metrics.
pub const NAMESPACE_METRICS: &str = "agent_metrics";

/// TTL applied to every persisted record, in seconds.
pub const PERSIST_TTL_SECONDS: u64 = 3600;

/// Durable store used by the agent for buffer persistence.
///
/// Implementations receive a namespace ([`NAMESPACE_EVENTS`] or
/// [`NAMESPACE_METRICS`]) and a short record key. Keys returned by
/// [`list_keys`](RedisHandler::list_keys) must be the short keys, without any
/// prefix the implementation adds internally.
#[async_trait]
pub trait RedisHandler: Send + Sync + 'static {
    /// Stores `value` under `key`, expiring after `ttl_seconds`.
    async fn set_key(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> Result<(), GuardAgentError>;

    /// Loads a record, returning `None` when it is missing or expired.
    async fn get_key(&self, namespace: &str, key: &str) -> Result<Option<String>, GuardAgentError>;

    /// Deletes the given records. Missing keys are ignored.
    async fn delete_keys(&self, namespace: &str, keys: &[String]) -> Result<(), GuardAgentError>;

    /// Lists the short keys currently stored in `namespace`.
    async fn list_keys(&self, namespace: &str) -> Result<Vec<String>, GuardAgentError>;

    /// Deletes every record in `namespace`.
    async fn clear_namespace(&self, namespace: &str) -> Result<(), GuardAgentError>;
}

fn namespaced_key(namespace: &str, key: &str) -> String {
    format!("{namespace}:{key}")
}

#[derive(Debug)]
struct Entry {
    value: String,
    expires_at: Option<Instant>,
}

impl Entry {
    fn is_expired(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }
}

/// In-memory [`RedisHandler`] with lazy TTL expiry.
///
/// Intended for tests and embedded use. It is not shared across processes, so
/// it only protects against failures within a single agent lifetime.
#[derive(Debug, Default)]
pub struct InMemoryRedisStore {
    entries: Mutex<HashMap<String, Entry>>,
}

impl InMemoryRedisStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of live (non-expired) records.
    #[must_use]
    pub fn len(&self) -> usize {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("store mutex not poisoned");
        entries.retain(|_, entry| !entry.is_expired(now));
        entries.len()
    }

    /// Returns `true` when no live records are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the value stored under `namespace:key`, ignoring expiry.
    ///
    /// Useful in tests that assert retained records regardless of TTL.
    #[must_use]
    pub fn peek(&self, namespace: &str, key: &str) -> Option<String> {
        let entries = self.entries.lock().expect("store mutex not poisoned");
        entries
            .get(&namespaced_key(namespace, key))
            .map(|entry| entry.value.clone())
    }

    /// Returns every short key stored in `namespace`, including expired ones.
    #[must_use]
    pub fn keys(&self, namespace: &str) -> Vec<String> {
        let prefix = format!("{namespace}:");
        let entries = self.entries.lock().expect("store mutex not poisoned");
        let mut keys: Vec<String> = entries
            .keys()
            .filter_map(|key| key.strip_prefix(&prefix).map(str::to_owned))
            .collect();
        keys.sort();
        keys
    }
}

#[async_trait]
impl RedisHandler for InMemoryRedisStore {
    async fn set_key(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> Result<(), GuardAgentError> {
        let expires_at = if ttl_seconds == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(ttl_seconds))
        };
        let mut entries = self.entries.lock().expect("store mutex not poisoned");
        entries.insert(
            namespaced_key(namespace, key),
            Entry {
                value: value.to_owned(),
                expires_at,
            },
        );
        Ok(())
    }

    async fn get_key(&self, namespace: &str, key: &str) -> Result<Option<String>, GuardAgentError> {
        let now = Instant::now();
        let full_key = namespaced_key(namespace, key);
        let mut entries = self.entries.lock().expect("store mutex not poisoned");
        if entries
            .get(&full_key)
            .is_some_and(|entry| entry.is_expired(now))
        {
            entries.remove(&full_key);
        }
        Ok(entries.get(&full_key).map(|entry| entry.value.clone()))
    }

    async fn delete_keys(&self, namespace: &str, keys: &[String]) -> Result<(), GuardAgentError> {
        let mut entries = self.entries.lock().expect("store mutex not poisoned");
        for key in keys {
            entries.remove(&namespaced_key(namespace, key));
        }
        Ok(())
    }

    async fn list_keys(&self, namespace: &str) -> Result<Vec<String>, GuardAgentError> {
        let now = Instant::now();
        let prefix = format!("{namespace}:");
        let mut entries = self.entries.lock().expect("store mutex not poisoned");
        entries.retain(|_, entry| !entry.is_expired(now));
        let mut keys: Vec<String> = entries
            .keys()
            .filter_map(|key| key.strip_prefix(&prefix).map(str::to_owned))
            .collect();
        keys.sort();
        Ok(keys)
    }

    async fn clear_namespace(&self, namespace: &str) -> Result<(), GuardAgentError> {
        let prefix = format!("{namespace}:");
        let mut entries = self.entries.lock().expect("store mutex not poisoned");
        entries.retain(|key, _| !key.starts_with(&prefix));
        Ok(())
    }
}

/// [`RedisHandler`] backed by the `redis` crate.
///
/// Keys are composed as `<key_prefix>:<namespace>:<key>` and the record value
/// is the compact JSON wire form of the event or metric.
#[cfg(feature = "persistence")]
#[derive(Debug, Clone)]
pub struct RedisClientHandler {
    connection: redis::aio::MultiplexedConnection,
    key_prefix: String,
    command_timeout: Duration,
}

#[cfg(feature = "persistence")]
impl RedisClientHandler {
    /// Connects to Redis using [`RedisConfig`](crate::RedisConfig).
    ///
    /// The connection is established eagerly so a misconfigured or unreachable
    /// server surfaces at startup, where the agent can degrade to memory-only
    /// operation with a single warning.
    pub async fn connect(config: &crate::config::RedisConfig) -> Result<Self, GuardAgentError> {
        let client = redis::Client::open(config.url.as_str())
            .map_err(|error| GuardAgentError::Redis(error.to_string()))?;
        let connection = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|error| GuardAgentError::Redis(error.to_string()))?;
        Ok(Self {
            connection,
            key_prefix: config.key_prefix.clone(),
            command_timeout: Duration::from_millis(config.command_timeout_ms),
        })
    }

    fn full_key(&self, namespace: &str, key: &str) -> String {
        format!("{}:{namespace}:{key}", self.key_prefix)
    }

    async fn query<T: redis::FromRedisValue>(
        &self,
        cmd: &redis::Cmd,
    ) -> Result<T, GuardAgentError> {
        let mut connection = self.connection.clone();
        let pending = cmd.query_async::<T>(&mut connection);
        tokio::time::timeout(self.command_timeout, pending)
            .await
            .map_err(|_| GuardAgentError::Redis("command timed out".to_owned()))?
            .map_err(|error| GuardAgentError::Redis(error.to_string()))
    }
}

#[cfg(feature = "persistence")]
#[async_trait]
impl RedisHandler for RedisClientHandler {
    async fn set_key(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> Result<(), GuardAgentError> {
        let mut cmd = redis::cmd("SET");
        cmd.arg(self.full_key(namespace, key))
            .arg(value)
            .arg("EX")
            .arg(ttl_seconds);
        let _: () = self.query(&cmd).await?;
        Ok(())
    }

    async fn get_key(&self, namespace: &str, key: &str) -> Result<Option<String>, GuardAgentError> {
        let mut cmd = redis::cmd("GET");
        cmd.arg(self.full_key(namespace, key));
        self.query(&cmd).await
    }

    async fn delete_keys(&self, namespace: &str, keys: &[String]) -> Result<(), GuardAgentError> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut cmd = redis::cmd("DEL");
        for key in keys {
            cmd.arg(self.full_key(namespace, key));
        }
        let _: () = self.query(&cmd).await?;
        Ok(())
    }

    async fn list_keys(&self, namespace: &str) -> Result<Vec<String>, GuardAgentError> {
        let prefix = format!("{}:{namespace}:", self.key_prefix);
        let mut cmd = redis::cmd("KEYS");
        cmd.arg(format!("{prefix}*"));
        let full_keys: Vec<String> = self.query(&cmd).await?;
        let mut short_keys: Vec<String> = full_keys
            .iter()
            .filter_map(|key| key.strip_prefix(&prefix).map(str::to_owned))
            .collect();
        short_keys.sort();
        Ok(short_keys)
    }

    async fn clear_namespace(&self, namespace: &str) -> Result<(), GuardAgentError> {
        let keys = self.list_keys(namespace).await?;
        self.delete_keys(namespace, &keys).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn stored_keys(store: &InMemoryRedisStore, namespace: &str) -> Vec<String> {
        store.list_keys(namespace).await.unwrap()
    }

    #[tokio::test]
    async fn set_and_get_round_trip() {
        let store = InMemoryRedisStore::new();
        store
            .set_key(
                NAMESPACE_EVENTS,
                "event_1",
                "{\"a\":1}",
                PERSIST_TTL_SECONDS,
            )
            .await
            .unwrap();
        let loaded = store.get_key(NAMESPACE_EVENTS, "event_1").await.unwrap();
        assert_eq!(loaded.as_deref(), Some("{\"a\":1}"));
        assert!(
            store
                .get_key(NAMESPACE_EVENTS, "missing")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn namespaces_are_isolated() {
        let store = InMemoryRedisStore::new();
        store
            .set_key(NAMESPACE_EVENTS, "shared", "event", PERSIST_TTL_SECONDS)
            .await
            .unwrap();
        store
            .set_key(NAMESPACE_METRICS, "shared", "metric", PERSIST_TTL_SECONDS)
            .await
            .unwrap();

        assert_eq!(
            stored_keys(&store, NAMESPACE_EVENTS).await,
            vec!["shared".to_owned()]
        );
        assert_eq!(
            stored_keys(&store, NAMESPACE_METRICS).await,
            vec!["shared".to_owned()]
        );
        assert_eq!(
            store
                .get_key(NAMESPACE_EVENTS, "shared")
                .await
                .unwrap()
                .as_deref(),
            Some("event")
        );
    }

    #[tokio::test]
    async fn delete_removes_records_and_ignores_missing() {
        let store = InMemoryRedisStore::new();
        store
            .set_key(NAMESPACE_EVENTS, "a", "1", PERSIST_TTL_SECONDS)
            .await
            .unwrap();
        store
            .set_key(NAMESPACE_EVENTS, "b", "2", PERSIST_TTL_SECONDS)
            .await
            .unwrap();

        store
            .delete_keys(NAMESPACE_EVENTS, &["a".to_owned(), "missing".to_owned()])
            .await
            .unwrap();
        assert_eq!(
            stored_keys(&store, NAMESPACE_EVENTS).await,
            vec!["b".to_owned()]
        );
    }

    #[tokio::test]
    async fn clear_namespace_wipes_only_that_namespace() {
        let store = InMemoryRedisStore::new();
        store
            .set_key(NAMESPACE_EVENTS, "a", "1", PERSIST_TTL_SECONDS)
            .await
            .unwrap();
        store
            .set_key(NAMESPACE_METRICS, "b", "2", PERSIST_TTL_SECONDS)
            .await
            .unwrap();

        store.clear_namespace(NAMESPACE_EVENTS).await.unwrap();
        assert!(stored_keys(&store, NAMESPACE_EVENTS).await.is_empty());
        assert_eq!(
            stored_keys(&store, NAMESPACE_METRICS).await,
            vec!["b".to_owned()]
        );
    }

    #[tokio::test]
    async fn expired_records_disappear() {
        let store = InMemoryRedisStore::new();
        store
            .set_key(NAMESPACE_EVENTS, "short_lived", "1", 1)
            .await
            .unwrap();
        assert!(
            store
                .get_key(NAMESPACE_EVENTS, "short_lived")
                .await
                .unwrap()
                .is_some()
        );

        tokio::time::sleep(Duration::from_millis(1100)).await;

        assert!(
            store
                .get_key(NAMESPACE_EVENTS, "short_lived")
                .await
                .unwrap()
                .is_none()
        );
        assert!(stored_keys(&store, NAMESPACE_EVENTS).await.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn ttl_zero_never_expires() {
        let store = InMemoryRedisStore::new();
        store
            .set_key(NAMESPACE_EVENTS, "forever", "1", 0)
            .await
            .unwrap();
        assert!(
            store
                .get_key(NAMESPACE_EVENTS, "forever")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn namespaced_keys_are_prefixed() {
        assert_eq!(
            namespaced_key(NAMESPACE_EVENTS, "event_1"),
            "agent_events:event_1"
        );
    }
}
