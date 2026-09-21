//! guard-agent-rs: telemetry and monitoring agent for the Guard ecosystem.
//!
//! This crate is the Rust counterpart of the Python [`guard-agent`] and
//! TypeScript [`guardagent`] telemetry agents. It ships security events,
//! metrics, and agent status to the Guard ingestion API
//! (`POST /api/v1/events`, `/api/v1/metrics`, `/api/v1/status`) with the same
//! reliability semantics:
//!
//! - bounded per-kind buffers with `drop` (evict oldest), `block`, and
//!   `raise` overflow policies;
//! - flush triggers on buffer high watermark and on a fixed interval;
//! - at-least-once flush handshake: drain, send, confirm (delete persisted
//!   records) or requeue in original order;
//! - transport retries with exponential backoff, honoring `Retry-After` on
//!   429;
//! - 413 split-or-drop with binary halving and a singleton drop threshold;
//! - permanent rejection (400, 404, 422) drops the batch without retrying;
//! - per-kind failure streaks with capped backoff and a computed degraded
//!   state;
//! - optional Redis persistence with TTL and startup reload.
//!
//! Telemetry failures never propagate into the caller's request path:
//! [`GuardAgent::send_event`] and [`GuardAgent::send_metric`] cannot fail,
//! and every error is observable through [`GuardAgent::get_stats`], the
//! computed [`AgentStatus`], logs, and the optional `on_error` hook.
//!
//! # Usage
//!
//! ```rust
//! use guard_agent_rs::{AgentConfig, GuardAgent, SecurityEvent};
//!
//! # async fn example() {
//! let mut config = AgentConfig::new("your-api-key-at-least-10-chars");
//! config.endpoint = "https://api.guard-core.com".to_owned();
//! config.install_id = Some("6f0a2880-1a2b-4c3d-9e4f-aabbccddeeff".to_owned());
//! let agent = GuardAgent::new(config).expect("valid configuration");
//!
//! agent
//!     .send_event(
//!         SecurityEvent::new("rate_limited")
//!             .with_ip_address("10.0.0.1")
//!             .with_endpoint("/api/users")
//!             .with_action_taken("blocked"),
//!     )
//!     .await;
//!
//! let stats = agent.get_stats().await;
//! assert_eq!(stats.events_buffered, 1);
//! # }
//! ```
//!
//! See the repository README for the full reliability contract and the
//! `persistence` feature documentation for Redis-backed buffering.
//!
//! [`guard-agent`]: https://pypi.org/project/guard-agent/
//! [`guardagent`]: https://github.com/rennf93/guard-agent-ts

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod agent;
pub mod circuit_breaker;
pub mod config;
pub mod error;
pub mod install_id;
pub mod models;
pub mod persistence;
pub mod signing;
pub mod transport;
pub mod utils;

pub use agent::{AgentStats, GuardAgent, LoopFailures};
pub use circuit_breaker::CircuitBreakerState;
pub use config::{
    AgentConfig, BufferOverflowPolicy, DEFAULT_BACKOFF_FACTOR, DEFAULT_BUFFER_SIZE,
    DEFAULT_COMPRESSION_THRESHOLD, DEFAULT_ENDPOINT, DEFAULT_FLUSH_INTERVAL_SECS,
    DEFAULT_HIGH_WATERMARK_RATIO, DEFAULT_MAX_PAYLOAD_SIZE, DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_SENSITIVE_HEADERS, DEFAULT_STATUS_INTERVAL_SECS, DEFAULT_TIMEOUT_SECS, MIN_API_KEY_LEN,
    MIN_STATUS_INTERVAL_SECS,
};
#[cfg(feature = "persistence")]
#[cfg_attr(docsrs, doc(cfg(feature = "persistence")))]
pub use config::{DEFAULT_REDIS_KEY_PREFIX, RedisConfig};
pub use error::{ConfigError, ErrorStage, GuardAgentError};
pub use models::{AgentHealth, AgentStatus, MetricType, SecurityEvent, SecurityMetric};
#[cfg(feature = "persistence")]
#[cfg_attr(docsrs, doc(cfg(feature = "persistence")))]
pub use persistence::RedisClientHandler;
pub use persistence::{
    InMemoryRedisStore, NAMESPACE_EVENTS, NAMESPACE_METRICS, PERSIST_TTL_SECONDS, RedisHandler,
};

/// Version of this agent, reported in batch payloads and the User-Agent.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
