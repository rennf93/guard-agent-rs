//! The [`GuardAgent`]: buffered telemetry ingestion with at-least-once flush,
//! per-kind failure backoff, degraded-state computation, and optional durable
//! persistence.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use crate::circuit_breaker::CircuitBreakerState;
use crate::config::{AgentConfig, BufferOverflowPolicy};
use crate::error::{ErrorStage, GuardAgentError};
use crate::install_id::resolve_install_id;
use crate::models::{AgentHealth, AgentStatus, SecurityEvent, SecurityMetric};
use crate::persistence::{NAMESPACE_EVENTS, NAMESPACE_METRICS, PERSIST_TTL_SECONDS, RedisHandler};
use crate::transport::{BatchItems, HttpTransport, SendOutcome};
use crate::utils::{Redactable, Redactor, calculate_backoff_delay, generate_short_key};

/// Cap, in seconds, for the per-kind flush streak backoff.
pub const PARTIAL_FAILURE_MAX_BACKOFF_SECS: f64 = 300.0;

/// Poll interval, in milliseconds, while the `block` overflow policy waits
/// for buffer space.
pub const BLOCK_POLICY_POLL_MS: u64 = 50;

/// Log every Nth drop under the `drop` overflow policy (first drop included).
pub const DROP_LOG_INTERVAL: u64 = 100;

/// Buffered occupancy ratio that marks the agent degraded.
pub const DEGRADED_BUFFER_RATIO: f64 = 0.9;

/// Buffered occupancy ratio that fails the health check.
pub const HEALTH_BUFFER_RATIO: f64 = 0.95;

/// Lifetime failure rate that marks the agent degraded.
pub const DEGRADED_FAILURE_RATE: f64 = 0.1;

/// Lifetime failure rate that fails the health check.
pub const HEALTH_FAILURE_RATE_MAX: f64 = 0.5;

/// Consecutive status-loop failures logged at error severity (below this,
/// warnings).
pub const STATUS_LOG_ERROR_THRESHOLD: u32 = 3;

/// How long `stop` waits for background loops to exit before aborting them.
const LOOP_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// A buffered telemetry item paired with its optional persistence key.
struct BufferedItem<T> {
    item: T,
    redis_key: Option<String>,
}

/// Consecutive background-loop failure counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoopFailures {
    /// Consecutive failures of the flush loop task.
    pub flush: u32,
    /// Consecutive failures of the status loop task.
    pub status: u32,
}

/// Interior shared state guarded by a single async mutex.
struct CoreState {
    events: VecDeque<BufferedItem<SecurityEvent>>,
    metrics: VecDeque<BufferedItem<SecurityMetric>>,
    redis_handler: Option<Arc<dyn RedisHandler>>,
    space_freed: Arc<Notify>,
    events_flushed: u64,
    metrics_flushed: u64,
    events_dropped: u64,
    metrics_dropped: u64,
    events_sent: u64,
    metrics_sent: u64,
    events_failed: u64,
    metrics_failed: u64,
    redis_persist_failures: u64,
    events_failure_streak: u32,
    metrics_failure_streak: u32,
    events_retry_after: Option<Instant>,
    metrics_retry_after: Option<Instant>,
    last_flush_instant: Option<Instant>,
    last_flush: Option<DateTime<Utc>>,
    loop_failures: LoopFailures,
    status_consecutive_failures: u32,
    last_status_push_ok: Option<bool>,
}

impl CoreState {
    fn new(capacity: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(capacity),
            metrics: VecDeque::with_capacity(capacity),
            redis_handler: None,
            space_freed: Arc::new(Notify::new()),
            events_flushed: 0,
            metrics_flushed: 0,
            events_dropped: 0,
            metrics_dropped: 0,
            events_sent: 0,
            metrics_sent: 0,
            events_failed: 0,
            metrics_failed: 0,
            redis_persist_failures: 0,
            events_failure_streak: 0,
            metrics_failure_streak: 0,
            events_retry_after: None,
            metrics_retry_after: None,
            last_flush_instant: None,
            last_flush: None,
            loop_failures: LoopFailures::default(),
            status_consecutive_failures: 0,
            last_status_push_ok: None,
        }
    }
}

/// Snapshot of transport and loop state for stats reporting.
#[derive(Debug, Clone)]
pub struct AgentStats {
    /// Whether the background loops are running.
    pub running: bool,
    /// Seconds since agent construction.
    pub uptime_seconds: f64,
    /// Lifetime confirmed events.
    pub events_sent: u64,
    /// Lifetime events requeued after failed flushes.
    pub events_failed: u64,
    /// Lifetime confirmed metrics.
    pub metrics_sent: u64,
    /// Lifetime metrics requeued after failed flushes.
    pub metrics_failed: u64,
    /// Lifetime drained events (confirmed or not).
    pub events_flushed: u64,
    /// Lifetime drained metrics.
    pub metrics_flushed: u64,
    /// Lifetime events evicted by the `drop` policy or requeue pressure.
    pub events_dropped: u64,
    /// Lifetime metrics evicted by the `drop` policy or requeue pressure.
    pub metrics_dropped: u64,
    /// Events currently buffered.
    pub events_buffered: usize,
    /// Metrics currently buffered.
    pub metrics_buffered: usize,
    /// Lifetime HTTP requests issued.
    pub requests_sent: u64,
    /// Lifetime sends that exhausted their retries.
    pub requests_failed: u64,
    /// Lifetime wire bytes handed to the HTTP client.
    pub bytes_sent: u64,
    /// Current circuit breaker position.
    pub circuit_breaker_state: CircuitBreakerState,
    /// Consecutive background-loop failures.
    pub loop_failures: LoopFailures,
    /// Lifetime persistence write failures.
    pub redis_persist_failures: u64,
    /// `true` when a persistence handler is attached and at least one write
    /// failed.
    pub durability_degraded: bool,
    /// Last drain time, when any flush ran.
    pub last_flush: Option<DateTime<Utc>>,
    /// Consecutive failed status pushes.
    pub status_consecutive_failures: u32,
    /// Outcome of the most recent status push.
    pub last_status_push_ok: Option<bool>,
}

struct LoopHandles {
    flush: JoinHandle<()>,
    status: JoinHandle<()>,
}

/// State shared between the public handle and the background loops.
struct Shared {
    config: Arc<AgentConfig>,
    install_id: String,
    transport: HttpTransport,
    redactor: Redactor,
    core: tokio::sync::Mutex<CoreState>,
    flush_permits: Arc<Semaphore>,
    inflight: std::sync::Mutex<Vec<JoinHandle<()>>>,
    shutdown: Arc<Notify>,
    started_at: Instant,
    running: AtomicBool,
}

impl Shared {
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

/// Buffered telemetry agent for the Guard ecosystem.
///
/// The agent is the Rust counterpart of `guard-agent` (Python) and
/// `guardagent` (TypeScript). It buffers [`SecurityEvent`]s and
/// [`SecurityMetric`]s in memory, flushes them to the Guard ingestion API on
/// size and time triggers, and applies an at-least-once handshake: batches are
/// drained, sent, and either confirmed (durable records deleted) or requeued
/// in front of the buffer in their original order.
///
/// # Failure isolation
///
/// Telemetry failures never propagate to the caller's request path:
/// [`send_event`](Self::send_event) and [`send_metric`](Self::send_metric)
/// cannot fail; every transport, persistence, and loop error is logged,
/// counted in [`get_stats`](Self::get_stats), and reported through the
/// optional `on_error` hook. The only fallible entry points are
/// [`new`](Self::new) (configuration) and
/// [`try_send_event`](Self::try_send_event) under the `Raise` overflow policy.
///
/// # Examples
///
/// ```rust
/// use guard_agent_rs::{AgentConfig, GuardAgent, SecurityEvent};
///
/// # async fn example() {
/// let mut config = AgentConfig::new("your-api-key-at-least-10-chars");
/// config.endpoint = "https://api.guard-core.com".to_owned();
/// let agent = GuardAgent::new(config).expect("valid configuration");
///
/// agent.send_event(SecurityEvent::new("rate_limited").with_ip_address("10.0.0.1")).await;
///
/// let stats = agent.get_stats().await;
/// assert_eq!(stats.events_buffered, 1);
/// # }
/// ```
#[derive(Clone)]
pub struct GuardAgent {
    shared: Arc<Shared>,
    loops: Arc<std::sync::Mutex<Option<LoopHandles>>>,
}

impl std::fmt::Debug for GuardAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardAgent")
            .field("install_id", &self.shared.install_id)
            .field("running", &self.shared.running.load(Ordering::Relaxed))
            .field("endpoint", &self.shared.config.endpoint)
            .finish_non_exhaustive()
    }
}

impl GuardAgent {
    /// Validates the configuration and builds the agent.
    ///
    /// Resolves the install identifier (override, `~/.guard-agent/install-id`,
    /// or fresh UUID) and constructs the HTTP client. Persistence is not
    /// connected here; call [`start`](Self::start) to attach the configured
    /// Redis backend and spawn the background loops.
    pub fn new(config: AgentConfig) -> Result<Self, GuardAgentError> {
        let mut config = config;
        config.validate()?;
        let config = Arc::new(config);

        let install_id = resolve_install_id(config.install_id.as_deref());
        let transport = HttpTransport::new(Arc::clone(&config), &install_id)?;
        let capacity = config.buffer_size;
        let permits = config.max_concurrent_flushes.max(1);
        let redactor = Redactor::new(&config.sensitive_headers);

        Ok(Self {
            shared: Arc::new(Shared {
                config,
                install_id,
                transport,
                redactor,
                core: tokio::sync::Mutex::new(CoreState::new(capacity)),
                flush_permits: Arc::new(Semaphore::new(permits)),
                inflight: std::sync::Mutex::new(Vec::new()),
                shutdown: Arc::new(Notify::new()),
                started_at: Instant::now(),
                running: AtomicBool::new(false),
            }),
            loops: Arc::new(std::sync::Mutex::new(None)),
        })
    }

    /// Returns the resolved install identifier sent as `X-Agent-Install-Id`.
    #[must_use]
    pub fn install_id(&self) -> &str {
        &self.shared.install_id
    }

    /// Attaches a custom persistence handler.
    ///
    /// Call before [`start`](Self::start) so persisted records are reloaded
    /// into the buffer at startup. Attaching after start skips the reload.
    pub async fn attach_redis_handler(&self, handler: Arc<dyn RedisHandler>) {
        self.shared.core.lock().await.redis_handler = Some(handler);
    }

    /// Starts the background flush and status loops.
    ///
    /// When the `persistence` feature is enabled and `redis` is configured,
    /// this connects the built-in Redis backend (degrading to memory-only
    /// operation with a warning on failure) and reloads persisted records.
    /// Idempotent: repeated calls are no-ops.
    pub async fn start(&self) {
        if self.shared.running.swap(true, Ordering::AcqRel) {
            return;
        }

        #[cfg(feature = "persistence")]
        if let Some(redis_config) = &self.shared.config.redis {
            match crate::persistence::RedisClientHandler::connect(redis_config).await {
                Ok(handler) => {
                    self.shared.core.lock().await.redis_handler = Some(Arc::new(handler));
                }
                Err(error) => {
                    log::warn!("Redis persistence disabled (connection failed): {error}");
                }
            }
        }

        self.reload_from_redis().await;

        let mut loops = self.loops.lock().expect("loops mutex not poisoned");
        if loops.is_some() {
            return;
        }
        *loops = Some(LoopHandles {
            flush: tokio::spawn(flush_loop(Arc::clone(&self.shared))),
            status: tokio::spawn(status_loop(Arc::clone(&self.shared))),
        });
    }

    /// Stops the background loops and performs a final flush.
    ///
    /// Mirrors the Python agent's shutdown: loops are signalled to exit,
    /// in-flight flushes are awaited, and the remaining buffer is flushed once
    /// (subject to the per-kind retry gates). Unconfirmed batches stay
    /// buffered and, when persistence is attached, durable for the next
    /// process.
    pub async fn stop(&self) {
        self.shared.running.store(false, Ordering::Release);
        self.shared.shutdown.notify_waiters();

        let handles = self.loops.lock().expect("loops mutex not poisoned").take();
        if let Some(handles) = handles {
            let LoopHandles {
                mut flush,
                mut status,
            } = handles;
            let _ = tokio::time::timeout(LOOP_SHUTDOWN_GRACE, async {
                let _ = (&mut flush).await;
                let _ = (&mut status).await;
            })
            .await;
            flush.abort();
            status.abort();
        }

        self.await_inflight().await;
        self.flush_buffer().await;
    }

    /// Waits (bounded) for in-flight watermark-triggered flushes.
    async fn await_inflight(&self) {
        let inflight: Vec<JoinHandle<()>> = {
            let mut inflight = self
                .shared
                .inflight
                .lock()
                .expect("inflight mutex not poisoned");
            std::mem::take(&mut *inflight)
        };
        if inflight.is_empty() {
            return;
        }
        let _ = tokio::time::timeout(LOOP_SHUTDOWN_GRACE, async move {
            for handle in inflight {
                let _ = handle.await;
            }
        })
        .await;
    }

    /// Buffers an event; never fails.
    ///
    /// Errors (including `Raise` policy rejections and persistence failures)
    /// are logged and reported through the `on_error` hook, mirroring the
    /// Python agent's fire-and-forget ingest path.
    pub async fn send_event(&self, event: SecurityEvent) {
        if let Err(error) = self.try_send_event(event).await {
            log::error!("Failed to buffer event: {error}");
            self.shared.fire_hook(ErrorStage::FlushEvents, &error);
        }
    }

    /// Buffers a metric; never fails.
    ///
    /// See [`send_event`](Self::send_event) for the failure-isolation policy.
    pub async fn send_metric(&self, metric: SecurityMetric) {
        if let Err(error) = self.try_send_metric(metric).await {
            log::error!("Failed to buffer metric: {error}");
            self.shared.fire_hook(ErrorStage::FlushMetrics, &error);
        }
    }

    /// Buffers an event, surfacing `Raise` policy rejections.
    ///
    /// Under `Drop` and `Block` this behaves like
    /// [`send_event`](Self::send_event); under `Raise` it returns
    /// [`GuardAgentError::BufferFull`] when the buffer is at capacity.
    pub async fn try_send_event(&self, mut event: SecurityEvent) -> Result<(), GuardAgentError> {
        if !self.shared.config.enable_events {
            return Ok(());
        }
        event.redact(&self.shared.redactor);
        self.enqueue_event(event).await
    }

    /// Buffers a metric, surfacing `Raise` policy rejections.
    pub async fn try_send_metric(&self, mut metric: SecurityMetric) -> Result<(), GuardAgentError> {
        if !self.shared.config.enable_metrics {
            return Ok(());
        }
        metric.redact(&self.shared.redactor);
        self.enqueue_metric(metric).await
    }

    async fn enqueue_event(&self, event: SecurityEvent) -> Result<(), GuardAgentError> {
        let capacity = self.shared.config.buffer_size;
        let policy = self.shared.config.buffer_overflow_policy;
        let watermark = self.watermark_threshold();

        let mut event = Some(event);
        loop {
            let mut core = self.shared.core.lock().await;
            if core.events.len() < capacity {
                let event = event.take().expect("event present while buffering");
                let redis_key = persist_item(&mut core, NAMESPACE_EVENTS, "event", &event).await;
                core.events.push_back(BufferedItem {
                    item: event,
                    redis_key,
                });
                let trigger = core.events.len() as f64 >= watermark;
                drop(core);
                if trigger {
                    spawn_gated_flush(&self.shared);
                }
                return Ok(());
            }

            match policy {
                BufferOverflowPolicy::Drop => {
                    if let Some(evicted) = core.events.pop_front() {
                        core.events_dropped += 1;
                        if core.events_dropped % DROP_LOG_INTERVAL == 1 {
                            log::warn!(
                                "Event buffer full at maxlen={capacity}; dropping oldest event \
                                 ({} dropped total)",
                                core.events_dropped
                            );
                        }
                        forget_key(&core, NAMESPACE_EVENTS, evicted.redis_key).await;
                    }
                    // Retry the insert immediately: capacity freed by the pop.
                }
                BufferOverflowPolicy::Raise => {
                    return Err(GuardAgentError::BufferFull { capacity });
                }
                BufferOverflowPolicy::Block => {
                    let notify = Arc::clone(&core.space_freed);
                    drop(core);
                    tokio::select! {
                        () = notify.notified() => {},
                        () = tokio::time::sleep(Duration::from_millis(BLOCK_POLICY_POLL_MS)) => {},
                    }
                }
            }
        }
    }

    async fn enqueue_metric(&self, metric: SecurityMetric) -> Result<(), GuardAgentError> {
        let capacity = self.shared.config.buffer_size;
        let policy = self.shared.config.buffer_overflow_policy;
        let watermark = self.watermark_threshold();

        let mut metric = Some(metric);
        loop {
            let mut core = self.shared.core.lock().await;
            if core.metrics.len() < capacity {
                let metric = metric.take().expect("metric present while buffering");
                let redis_key = persist_item(&mut core, NAMESPACE_METRICS, "metric", &metric).await;
                core.metrics.push_back(BufferedItem {
                    item: metric,
                    redis_key,
                });
                let trigger = core.metrics.len() as f64 >= watermark;
                drop(core);
                if trigger {
                    spawn_gated_flush(&self.shared);
                }
                return Ok(());
            }

            match policy {
                BufferOverflowPolicy::Drop => {
                    if let Some(evicted) = core.metrics.pop_front() {
                        core.metrics_dropped += 1;
                        if core.metrics_dropped % DROP_LOG_INTERVAL == 1 {
                            log::warn!(
                                "Metric buffer full at maxlen={capacity}; dropping oldest metric \
                                 ({} dropped total)",
                                core.metrics_dropped
                            );
                        }
                        forget_key(&core, NAMESPACE_METRICS, evicted.redis_key).await;
                    }
                }
                BufferOverflowPolicy::Raise => {
                    return Err(GuardAgentError::BufferFull { capacity });
                }
                BufferOverflowPolicy::Block => {
                    let notify = Arc::clone(&core.space_freed);
                    drop(core);
                    tokio::select! {
                        () = notify.notified() => {},
                        () = tokio::time::sleep(Duration::from_millis(BLOCK_POLICY_POLL_MS)) => {},
                    }
                }
            }
        }
    }

    /// Occupancy threshold (in items) that triggers an early flush.
    fn watermark_threshold(&self) -> f64 {
        self.shared.config.buffer_size as f64 * self.shared.config.high_watermark_ratio
    }

    /// Flushes both kinds now, subject to the per-kind retry gates.
    ///
    /// Serialized with the background loops through the flush semaphore.
    pub async fn flush_buffer(&self) {
        let permit = self
            .shared
            .flush_permits
            .clone()
            .acquire_owned()
            .await
            .expect("flush semaphore is never closed");
        do_flush(&self.shared).await;
        drop(permit);
    }

    /// Drops every buffered event and metric and clears persisted records.
    pub async fn clear_buffer(&self) {
        let handler = {
            let mut core = self.shared.core.lock().await;
            core.events.clear();
            core.metrics.clear();
            core.space_freed.notify_waiters();
            core.redis_handler.clone()
        };
        let Some(handler) = handler else {
            return;
        };
        for (namespace, label) in [(NAMESPACE_EVENTS, "events"), (NAMESPACE_METRICS, "metrics")] {
            if let Err(error) = handler.clear_namespace(namespace).await {
                log::warn!("Failed to clear persisted {label} from Redis: {error}");
            }
        }
    }

    /// Computes the current status, marking the agent degraded when the
    /// circuit breaker is open, the buffer is at least 90% full, or the
    /// lifetime failure rate exceeds 10%.
    pub async fn get_status(&self) -> AgentStatus {
        let core = self.shared.core.lock().await;
        compute_status(&self.shared, &core)
    }

    /// Pushes the current status to `/api/v1/status` immediately.
    ///
    /// The background loop calls this on [`status_interval`](AgentConfig)
    /// cadence; exposing it allows tests and operators to force a push.
    pub async fn push_status(&self) {
        push_status_once(&self.shared).await;
    }

    /// Returns a snapshot of agent counters and transport state.
    pub async fn get_stats(&self) -> AgentStats {
        let core = self.shared.core.lock().await;
        let (requests_sent, requests_failed, bytes_sent) = self.shared.transport.counters();
        AgentStats {
            running: self.shared.running.load(Ordering::Acquire),
            uptime_seconds: self.shared.started_at.elapsed().as_secs_f64(),
            events_sent: core.events_sent,
            events_failed: core.events_failed,
            metrics_sent: core.metrics_sent,
            metrics_failed: core.metrics_failed,
            events_flushed: core.events_flushed,
            metrics_flushed: core.metrics_flushed,
            events_dropped: core.events_dropped,
            metrics_dropped: core.metrics_dropped,
            events_buffered: core.events.len(),
            metrics_buffered: core.metrics.len(),
            requests_sent,
            requests_failed,
            bytes_sent,
            circuit_breaker_state: self.shared.transport.breaker_state(),
            loop_failures: core.loop_failures,
            redis_persist_failures: core.redis_persist_failures,
            durability_degraded: core.redis_handler.is_some() && core.redis_persist_failures > 0,
            last_flush: core.last_flush,
            status_consecutive_failures: core.status_consecutive_failures,
            last_status_push_ok: core.last_status_push_ok,
        }
    }

    /// Returns `false` when the loops are stopped, the breaker is open, the
    /// buffer is at least 95% full, or the lifetime failure rate exceeds 50%.
    pub async fn health_check(&self) -> bool {
        let core = self.shared.core.lock().await;
        if !self.shared.running.load(Ordering::Acquire) {
            return false;
        }
        if self.shared.transport.breaker_state() == CircuitBreakerState::Open {
            return false;
        }
        let buffered = core.events.len() + core.metrics.len();
        if (buffered as f64) >= self.shared.config.buffer_size as f64 * HEALTH_BUFFER_RATIO {
            return false;
        }
        failure_rate(&core) <= HEALTH_FAILURE_RATE_MAX
    }

    /// Reloads persisted events and metrics into the in-memory buffers.
    async fn reload_from_redis(&self) {
        let handler = {
            let core = self.shared.core.lock().await;
            core.redis_handler.clone()
        };
        let Some(handler) = handler else {
            return;
        };
        let capacity = self.shared.config.buffer_size;

        let mut core = self.shared.core.lock().await;
        let mut loaded_events = 0usize;
        let mut loaded_metrics = 0usize;

        if let Ok(keys) = handler.list_keys(NAMESPACE_EVENTS).await {
            for key in keys {
                let loaded = match handler.get_key(NAMESPACE_EVENTS, &key).await {
                    Ok(Some(value)) => match serde_json::from_str::<SecurityEvent>(&value) {
                        Ok(event) => Some(event),
                        Err(error) => {
                            log::warn!("Failed to load event from Redis key {key}: {error}");
                            None
                        }
                    },
                    Ok(None) => {
                        log::warn!("Failed to load event from Redis key {key}: no data found");
                        None
                    }
                    Err(error) => {
                        log::warn!("Failed to load event from Redis key {key}: {error}");
                        None
                    }
                };
                if let Some(event) = loaded {
                    if core.events.len() >= capacity
                        && let Some(evicted) = core.events.pop_front()
                    {
                        core.events_dropped += 1;
                        forget_key(&core, NAMESPACE_EVENTS, evicted.redis_key).await;
                    }
                    core.events.push_back(BufferedItem {
                        item: event,
                        redis_key: Some(key),
                    });
                    loaded_events += 1;
                }
            }
        } else {
            log::warn!("Failed to list persisted events from Redis");
        }

        if let Ok(keys) = handler.list_keys(NAMESPACE_METRICS).await {
            for key in keys {
                let loaded = match handler.get_key(NAMESPACE_METRICS, &key).await {
                    Ok(Some(value)) => match serde_json::from_str::<SecurityMetric>(&value) {
                        Ok(metric) => Some(metric),
                        Err(error) => {
                            log::warn!("Failed to load metric from Redis key {key}: {error}");
                            None
                        }
                    },
                    Ok(None) => {
                        log::warn!("Failed to load metric from Redis key {key}: no data found");
                        None
                    }
                    Err(error) => {
                        log::warn!("Failed to load metric from Redis key {key}: {error}");
                        None
                    }
                };
                if let Some(metric) = loaded {
                    if core.metrics.len() >= capacity
                        && let Some(evicted) = core.metrics.pop_front()
                    {
                        core.metrics_dropped += 1;
                        forget_key(&core, NAMESPACE_METRICS, evicted.redis_key).await;
                    }
                    core.metrics.push_back(BufferedItem {
                        item: metric,
                        redis_key: Some(key),
                    });
                    loaded_metrics += 1;
                }
            }
        } else {
            log::warn!("Failed to list persisted metrics from Redis");
        }

        if loaded_events + loaded_metrics > 0 {
            log::info!("Loaded {loaded_events} events and {loaded_metrics} metrics from Redis");
        }
    }
}

fn failure_rate(core: &CoreState) -> f64 {
    let total = core.events_sent + core.metrics_sent + core.events_failed + core.metrics_failed;
    let failed = core.events_failed + core.metrics_failed;
    failed as f64 / total.max(1) as f64
}

fn compute_status(shared: &Shared, core: &CoreState) -> AgentStatus {
    let mut status = AgentHealth::Healthy;
    let mut errors = Vec::new();

    if shared.transport.breaker_state() == CircuitBreakerState::Open {
        status = AgentHealth::Degraded;
        errors.push("Transport circuit breaker is open".to_owned());
    }

    let buffered = (core.events.len() + core.metrics.len()) as u64;
    if (buffered as f64) >= shared.config.buffer_size as f64 * DEGRADED_BUFFER_RATIO {
        status = AgentHealth::Degraded;
        errors.push("Buffer nearly full".to_owned());
    }

    let rate = failure_rate(core);
    if rate > DEGRADED_FAILURE_RATE {
        status = AgentHealth::Degraded;
        errors.push(format!("High failure rate: {:.1}%", rate * 100.0));
    }

    AgentStatus {
        timestamp: Utc::now(),
        status,
        uptime: shared.started_at.elapsed().as_secs_f64(),
        events_sent: core.events_sent,
        events_failed: core.events_failed,
        buffer_size: buffered,
        last_flush: core.last_flush,
        errors,
    }
}

/// Persists an item, returning the short key on success.
///
/// Persistence failures are counted, logged, and otherwise swallowed: the
/// item still lands in the in-memory buffer (fail-open).
async fn persist_item<T: Serialize + Sync>(
    core: &mut CoreState,
    namespace: &str,
    prefix: &str,
    item: &T,
) -> Option<String> {
    let handler = core.redis_handler.as_ref()?;
    let short_key = generate_short_key(prefix);
    let value = match serde_json::to_string(item) {
        Ok(value) => value,
        Err(error) => {
            core.redis_persist_failures += 1;
            log::warn!("Failed to serialize {prefix} for Redis persistence: {error}");
            return None;
        }
    };
    match handler
        .set_key(namespace, &short_key, &value, PERSIST_TTL_SECONDS)
        .await
    {
        Ok(()) => Some(short_key),
        Err(error) => {
            core.redis_persist_failures += 1;
            log::warn!("Failed to persist {prefix} to Redis: {error}");
            None
        }
    }
}

/// Deletes a record key, best effort. Failures leave an orphan that expires
/// via TTL.
async fn forget_key(core: &CoreState, namespace: &str, key: Option<String>) {
    let Some(key) = key.filter(|key| !key.is_empty()) else {
        return;
    };
    let Some(handler) = &core.redis_handler else {
        return;
    };
    if let Err(error) = handler.delete_keys(namespace, &[key]).await {
        log::warn!("Failed to delete persisted record from Redis: {error}");
    }
}

/// Deletes confirmed keys after a successful or intentionally-dropped send.
async fn confirm_keys(shared: &Shared, namespace: &str, keys: Vec<Option<String>>) {
    let live: Vec<String> = keys
        .into_iter()
        .flatten()
        .filter(|key| !key.is_empty())
        .collect();
    if live.is_empty() {
        return;
    }
    let handler = {
        let core = shared.core.lock().await;
        core.redis_handler.clone()
    };
    let Some(handler) = handler else {
        return;
    };
    if let Err(error) = handler.delete_keys(namespace, &live).await {
        log::warn!("Failed to confirm {namespace} Redis keys: {error}");
    }
}

/// Drains a kind's buffer, restoring original order on requeue.
fn drain<T>(
    deque: &mut VecDeque<BufferedItem<T>>,
    counter: &mut u64,
) -> (Vec<T>, Vec<Option<String>>) {
    let drained: Vec<BufferedItem<T>> = deque.drain(..).collect();
    *counter += drained.len() as u64;
    drained
        .into_iter()
        .map(|buffered| (buffered.item, buffered.redis_key))
        .unzip()
}

/// Pushes failed items back to the front of the buffer in their original
/// order, evicting the newest tail items when at capacity and returning the
/// evicted keys for confirmation.
fn requeue<T>(
    deque: &mut VecDeque<BufferedItem<T>>,
    capacity: usize,
    items: Vec<T>,
    keys: Vec<Option<String>>,
    dropped: &mut u64,
) -> Vec<Option<String>> {
    let mut evicted = Vec::new();
    for (item, redis_key) in items.into_iter().zip(keys).rev() {
        if deque.len() >= capacity
            && let Some(victim) = deque.pop_back()
        {
            *dropped += 1;
            evicted.push(victim.redis_key);
        }
        deque.push_front(BufferedItem { item, redis_key });
    }
    evicted
}

/// Performs both kind flushes while the caller holds a permit.
async fn do_flush(shared: &Shared) {
    flush_events(shared).await;
    flush_metrics(shared).await;
}

/// The watermark/time-gated flush used by background triggers.
async fn flush_if_needed(shared: &Shared, _permit: OwnedSemaphorePermit) {
    let core = shared.core.lock().await;
    if core.events.len() + core.metrics.len() == 0 {
        return;
    }
    let interval = Duration::from_secs(shared.config.flush_interval);
    let elapsed_ok = core
        .last_flush_instant
        .is_none_or(|last| last.elapsed() >= interval);
    let watermark_ok = ((core.events.len() + core.metrics.len()) as f64)
        >= shared.config.buffer_size as f64 * shared.config.high_watermark_ratio;
    if !(elapsed_ok || watermark_ok) {
        return;
    }
    drop(core);
    do_flush(shared).await;
}

/// Flushes buffered events: drain, send, confirm or requeue + backoff.
async fn flush_events(shared: &Shared) {
    let gate = { shared.core.lock().await.events_retry_after };
    if gate_closed(gate) {
        return;
    }
    let (items, keys) = {
        let mut core = shared.core.lock().await;
        let CoreState {
            events,
            events_flushed,
            ..
        } = &mut *core;
        drain(events, events_flushed)
    };
    if items.is_empty() {
        return;
    }
    let count = items.len();
    core_set_last_flush(shared).await;

    let outcome = shared
        .transport
        .send_batch(BatchItems::Events(items.clone()))
        .await;
    match outcome {
        SendOutcome::Accepted => {
            confirm_keys(shared, NAMESPACE_EVENTS, keys).await;
            let mut core = shared.core.lock().await;
            core.events_sent += count as u64;
            if core.events_failure_streak > 0 {
                log::info!(
                    "Events flush recovered after {} consecutive partial failure(s)",
                    core.events_failure_streak
                );
            }
            core.events_failure_streak = 0;
            core.events_retry_after = None;
        }
        SendOutcome::PermanentDrop { .. } => {
            confirm_keys(shared, NAMESPACE_EVENTS, keys).await;
        }
        SendOutcome::Failed { error } => {
            let evicted = {
                let mut core = shared.core.lock().await;
                let CoreState {
                    events,
                    events_dropped,
                    ..
                } = &mut *core;
                requeue(
                    events,
                    shared.config.buffer_size,
                    items,
                    keys,
                    events_dropped,
                )
            };
            let delay = {
                let mut core = shared.core.lock().await;
                core.events_failed += count as u64;
                core.events_failure_streak = core.events_failure_streak.saturating_add(1);
                let delay = calculate_backoff_delay(
                    core.events_failure_streak - 1,
                    shared.config.flush_interval as f64,
                    PARTIAL_FAILURE_MAX_BACKOFF_SECS,
                );
                core.events_retry_after = Some(Instant::now() + Duration::from_secs_f64(delay));
                core.loop_failures.flush += 1;
                delay
            };
            if !evicted.is_empty() {
                confirm_keys(shared, NAMESPACE_EVENTS, evicted).await;
            }
            shared.fire_hook(ErrorStage::FlushEvents, &error);
            let retention = retention_description(shared, "events").await;
            log::warn!(
                "Failed to send {count} events; {retention} for retry; backing off up to \
                 {delay:.0}s between attempts: {error}"
            );
        }
    }
}

/// Flushes buffered metrics; mirrors [`flush_events`].
async fn flush_metrics(shared: &Shared) {
    let gate = { shared.core.lock().await.metrics_retry_after };
    if gate_closed(gate) {
        return;
    }
    let (items, keys) = {
        let mut core = shared.core.lock().await;
        let CoreState {
            metrics,
            metrics_flushed,
            ..
        } = &mut *core;
        drain(metrics, metrics_flushed)
    };
    if items.is_empty() {
        return;
    }
    let count = items.len();
    core_set_last_flush(shared).await;

    let outcome = shared
        .transport
        .send_batch(BatchItems::Metrics(items.clone()))
        .await;
    match outcome {
        SendOutcome::Accepted => {
            confirm_keys(shared, NAMESPACE_METRICS, keys).await;
            let mut core = shared.core.lock().await;
            core.metrics_sent += count as u64;
            if core.metrics_failure_streak > 0 {
                log::info!(
                    "Metrics flush recovered after {} consecutive partial failure(s)",
                    core.metrics_failure_streak
                );
            }
            core.metrics_failure_streak = 0;
            core.metrics_retry_after = None;
        }
        SendOutcome::PermanentDrop { .. } => {
            confirm_keys(shared, NAMESPACE_METRICS, keys).await;
        }
        SendOutcome::Failed { error } => {
            let evicted = {
                let mut core = shared.core.lock().await;
                let CoreState {
                    metrics,
                    metrics_dropped,
                    ..
                } = &mut *core;
                requeue(
                    metrics,
                    shared.config.buffer_size,
                    items,
                    keys,
                    metrics_dropped,
                )
            };
            let delay = {
                let mut core = shared.core.lock().await;
                core.metrics_failed += count as u64;
                core.metrics_failure_streak = core.metrics_failure_streak.saturating_add(1);
                let delay = calculate_backoff_delay(
                    core.metrics_failure_streak - 1,
                    shared.config.flush_interval as f64,
                    PARTIAL_FAILURE_MAX_BACKOFF_SECS,
                );
                core.metrics_retry_after = Some(Instant::now() + Duration::from_secs_f64(delay));
                core.loop_failures.flush += 1;
                delay
            };
            if !evicted.is_empty() {
                confirm_keys(shared, NAMESPACE_METRICS, evicted).await;
            }
            shared.fire_hook(ErrorStage::FlushMetrics, &error);
            let retention = retention_description(shared, "metrics").await;
            log::warn!(
                "Failed to send {count} metrics; {retention} for retry; backing off up to \
                 {delay:.0}s between attempts: {error}"
            );
        }
    }
}

/// Returns `true` when a per-kind retry gate still blocks this kind.
fn gate_closed(gate: Option<Instant>) -> bool {
    gate.is_some_and(|gate| Instant::now() < gate)
}

/// Describes where unsent items wait for retry, based on whether a Redis
/// handler is attached to the core state. Without Redis the items live only
/// in the in-memory buffer, so claiming Redis retention would be misleading
/// (mirrors Python `_client_flush.FlushMixin._retention_description`).
async fn retention_description(shared: &Shared, kind: &str) -> String {
    let has_redis = shared.core.lock().await.redis_handler.is_some();
    let redis_part = if has_redis {
        " and retained in Redis"
    } else {
        ""
    };
    format!("requeued in memory{redis_part} ({kind})")
}

async fn core_set_last_flush(shared: &Shared) {
    let mut core = shared.core.lock().await;
    core.last_flush_instant = Some(Instant::now());
    core.last_flush = Some(Utc::now());
    core.space_freed.notify_waiters();
}

/// Spawns a watermark-triggered flush when a permit is free.
fn spawn_gated_flush(shared: &Arc<Shared>) {
    if !shared.running.load(Ordering::Acquire) {
        return;
    }
    let task_shared = Arc::clone(shared);
    let handle = tokio::spawn(async move {
        if let Ok(permit) = task_shared.flush_permits.clone().try_acquire_owned() {
            flush_if_needed(&task_shared, permit).await;
        }
    });
    track_inflight(shared, handle);
}

fn track_inflight(shared: &Shared, handle: JoinHandle<()>) {
    let mut inflight = shared.inflight.lock().expect("inflight mutex not poisoned");
    inflight.retain(|handle| !handle.is_finished());
    inflight.push(handle);
}

/// Background flush loop: every `flush_interval` seconds, run a gated flush.
async fn flush_loop(shared: Arc<Shared>) {
    let interval = Duration::from_secs(shared.config.flush_interval);
    loop {
        tokio::select! {
            () = tokio::time::sleep(interval) => {},
            () = shared.shutdown.notified() => break,
        }
        if !shared.running.load(Ordering::Acquire) {
            break;
        }
        if let Ok(permit) = shared.flush_permits.clone().try_acquire_owned() {
            let task_shared = Arc::clone(&shared);
            let handle = tokio::spawn(async move {
                flush_if_needed(&task_shared, permit).await;
            });
            if let Err(error) = handle.await
                && error.is_panic()
            {
                let mut core = shared.core.lock().await;
                core.loop_failures.flush += 1;
                log::error!("Flush task panicked: {error}");
            }
        }
    }
}

/// Sends one status push, counting consecutive failures for log severity.
async fn push_status_once(shared: &Shared) {
    let status = {
        let core = shared.core.lock().await;
        compute_status(shared, &core)
    };
    let outcome = shared.transport.send_status(&status).await;
    let mut core = shared.core.lock().await;
    match outcome {
        SendOutcome::Accepted | SendOutcome::PermanentDrop { .. } => {
            core.status_consecutive_failures = 0;
            core.loop_failures.status = 0;
            core.last_status_push_ok = Some(true);
        }
        SendOutcome::Failed { error } => {
            core.status_consecutive_failures = core.status_consecutive_failures.saturating_add(1);
            core.loop_failures.status = core.loop_failures.status.saturating_add(1);
            core.last_status_push_ok = Some(false);
            let consecutive = core.status_consecutive_failures;
            if consecutive >= STATUS_LOG_ERROR_THRESHOLD {
                log::error!("Status push failed ({consecutive} consecutive): {error}");
            } else {
                log::warn!("Status push failed: {error}");
            }
        }
    }
}

/// Background status loop: every `status_interval` seconds, push status.
async fn status_loop(shared: Arc<Shared>) {
    let interval = Duration::from_secs(shared.config.status_interval);
    loop {
        tokio::select! {
            () = tokio::time::sleep(interval) => {},
            () = shared.shutdown.notified() => break,
        }
        if !shared.running.load(Ordering::Acquire) {
            break;
        }
        push_status_once(&shared).await;
    }
}
