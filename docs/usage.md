# Usage

## Lifecycle

```rust
use guard_agent_rs::{AgentConfig, GuardAgent};

let config = AgentConfig::new("your-api-key-at-least-10-chars");
let agent = GuardAgent::new(config)?;  // validates config, resolves install id

agent.start().await;                   // starts flush and status loops
agent.send_event(event).await;         // enqueue a security event (never fails)
agent.send_metric(metric).await;       // enqueue a security metric (never fails)
agent.try_send_event(event).await?;    // error-surfacing variant
agent.flush_buffer().await;            // force a flush cycle
agent.get_status().await;              // current status snapshot
agent.health_check().await;            // true when the ingestion API is reachable
agent.get_stats().await;               // buffer occupancy, drops, retries
agent.stop().await;                    // final flush, stop loops
```

`GuardAgent::new` rejects an empty or too-short `APIKey` (minimum 10
characters) with a config error. `start` is loop-spawn guarded; `stop`
performs one final forced flush and confirms persisted records for
everything it successfully sends.

## Events and metrics

`SecurityEvent` and `SecurityMetric` mirror the ingestion API's
`BatchTelemetryRequest` payload. Timestamps serialize as RFC 3339;
`idempotency_key` (generated per event by `SecurityEvent::new`) deduplicates
retries server-side. `SecurityEvent` carries `event_type`, `ip_address`,
`endpoint`, `method`, `action_taken`, `reason`, `status_code`,
`decorator_type`, `rule_type`, `pattern_matched`, and a free-form
`metadata` JSON value; `SecurityMetric` carries a `MetricType`
(`request_count`, `response_time`, `error_rate`, `bandwidth_usage`,
`threat_level`, `block_rate`, `cache_hit_rate`), a value, an optional
endpoint scope, and string tags. Field-by-field descriptions live on the
struct definitions in `src/models.rs`.

## Buffering and overflow

Each kind (events, metrics) has its own buffer (`buffer_size`, default 100).
When a buffer fills, `buffer_overflow_policy` decides:

| Policy | Behavior |
|---|---|
| `Drop` (default) | evicts the oldest item of the same kind, deletes its persisted record, counts a drop |
| `Block` | waits for a flush to free a slot; durability over the new writer |
| `Raise` | `try_send_*` returns a `GuardAgentError` without buffering |

A combined occupancy at or above `high_watermark_ratio` (default 0.8)
triggers an early flush.

## Delivery semantics

- Flushes run on `flush_interval` (default 30s), on watermark, and on demand
- A failed batch retries up to `retry_attempts` with exponential backoff
  (`backoff_factor`), honoring `Retry-After` on 429
- A 413 (the ingestion API rejects batches above 262144 bytes decompressed)
  splits the batch in half recursively or drops its oldest item rather than
  retrying a permanently oversized payload
- 400, 404, and 422 are permanent: the batch is dropped and confirmed, not
  retried
- 401, 403, other 4xx, 5xx, and network errors are retryable
- A 200 with `success: false` (or a non-empty `errors` list) requeues the
  failed items in the original order
- The circuit breaker opens after 5 consecutive transport failures and
  half-opens to probe recovery after 60 seconds
- Per-kind failure streaks gate flushes for up to 300 seconds; success resets

## Signing

When `payload_signing_secret` is set, every request carries
`X-Payload-Signature: v1=<hex hmac-sha256>`. The signature covers the
UNCOMPRESSED JSON body; the server verifies after decompression. Gzip
(`compression_enabled`) only affects the wire bytes.

## Persistence

With the `persistence` feature and a `redis: Option<RedisConfig>` set, every
buffered item is persisted before the send attempt and deleted only on
confirmation, so a crash between buffer and network loses nothing. Without
the feature, implement the `RedisHandler` trait and call
`agent.attach_redis_handler(Arc::new(store)).await` before `start()`.
Persistence is fail-open: a store error never blocks buffering or sending.
See [Configuration](configuration.md).
