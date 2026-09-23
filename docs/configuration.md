# Configuration

Everything is the `guard_agent_rs::AgentConfig` struct; there are no
environment variables inside the agent (your application maps its
environment onto the struct, as the example app does).
`AgentConfig::new(api_key)` fills the documented defaults; `GuardAgent::new`
validates and normalizes (endpoint trailing slashes and a legacy `/api/v1`
suffix are stripped).

## Required

| Field | Purpose |
|---|---|
| `api_key` | Ingestion API key, sent as `X-API-Key` (minimum 10 characters) |

## Endpoints and identity

| Field | Default | Purpose |
|---|---|---|
| `endpoint` | `https://api.guard-core.com` | Ingestion base URL; a trailing `/api/v1` suffix is removed automatically |
| `project_id` | `None` | Sent as `X-Project-Id` when `Some` |
| `install_id` | auto | Persisted agent identity (resolved under `~/.guard-agent/install-id`), sent as `X-Agent-Install-Id` |
| `guard_version` / `guard_core_version` | `None` | Reported in batch payloads as the wrapper/engine versions |

## Buffering

| Field | Default | Purpose |
|---|---|---|
| `buffer_size` | 100 | Per-kind queue capacity |
| `flush_interval` | 30s | Periodic flush cadence and retry backoff base |
| `status_interval` | 300s | Status report cadence (minimum 60s) |
| `high_watermark_ratio` | 0.8 | Combined occupancy that triggers an early flush |
| `max_concurrent_flushes` | 1 | In-flight flush cycle bound |
| `buffer_overflow_policy` | `Drop` | Full-buffer policy (`Drop`, `Block`, `Raise`) |
| `enable_events` / `enable_metrics` | true | Per-kind send switches |

## Network

| Field | Default | Purpose |
|---|---|---|
| `retry_attempts` | 3 | Retries after a failed attempt (0 disables) |
| `timeout` | 30s | Per-request HTTP timeout |
| `backoff_factor` | 1.0 | Exponential retry delay base in seconds |
| `compression_enabled` | true | Gzip bodies at or above the threshold |
| `compression_threshold` | 1024 | Gzip cutoff in bytes |
| `max_payload_size` | 1024 | Advisory payload size hint (kept for agent-family parity; the transport does not truncate) |
| `payload_signing_secret` | `None` | HMAC-SHA256 secret over the uncompressed body (`X-Payload-Signature: v1=<hex>`) |
| `sensitive_headers` | default list | Header names redacted from event metadata |

## Redis persistence

Requires the `persistence` feature (built-in `redis` tokio client):

```rust
use guard_agent_rs::{AgentConfig, RedisConfig};

let mut config = AgentConfig::new("your-api-key-at-least-10-chars");
config.redis = Some(RedisConfig::new("redis://127.0.0.1:6379")); // URL carries credentials and DB index
config.redis.as_mut().unwrap().key_prefix = "guard:agent".to_owned(); // default
```

Keys are `{key_prefix}:{namespace}:{id}` with namespaces `agent_events` and
`agent_metrics`. Records are written with a TTL on enqueue, deleted on
confirmation, and reloaded into the buffers on `start`. Persistence is
optional; without it (or with a custom `RedisHandler` implementation and no
feature), a process crash loses buffered-but-unsent items.

## Error hook

`on_error: Option<ErrorHook>` receives an `ErrorStage` and a
`GuardAgentError` for every internal failure (transport, persistence,
serialization), keeping telemetry failures observable without ever failing
`send_event` / `send_metric`.
