# guard-agent-rs

Telemetry and monitoring agent for the [Guard ecosystem](https://github.com/rennf93) (Rust). Companion agent to [guard-core-rs](https://github.com/rennf93/guard-core-rs) and its thin adapters, mirroring the semantics of [guard-agent](https://github.com/rennf93/guard-agent) (Python) and [guardagent](https://github.com/rennf93/guard-agent-ts) (TypeScript).

The agent buffers security events, metrics, and status reports in memory, ships them to the Guard ingestion API, and applies an at-least-once reliability contract: nothing acknowledged is lost, nothing unacknowledged is forgotten.

## Status

Implemented and functional. Version 0.1.0.

## Features

- **Buffered ingestion** with size (high watermark) and time (flush interval) triggers, and three overflow policies: `drop` (evict oldest), `block` (backpressure), and `raise` (surface an error).
- **At-least-once flush handshake**: drain, send, confirm (delete persisted records) or requeue in the original order.
- **Retry with exponential backoff**, honoring `Retry-After` on 429, with a client-side circuit breaker (5 consecutive failures open the circuit for 60 seconds).
- **413 split-or-drop**: batches rejected as too large are halved recursively; a singleton that still exceeds the cap is dropped.
- **Permanent rejection** for 400, 404, and 422: the batch is dropped without retrying and counted as confirmed.
- **Per-kind failure streaks**: events and metrics back off independently (up to 300 seconds) after failed flushes, and a computed degraded state is exposed to callers and the status endpoint.
- **Optional Redis persistence** (feature `persistence`): every accepted record is written with a TTL on enqueue, deleted only on confirmation, and reloaded into the buffer on startup. Alternatively, implement the `RedisHandler` trait and inject your own store.
- **Payload hygiene**: gzip compression above a threshold, HMAC-SHA256 request signing (`X-Payload-Signature: v1=<hex>`), and redaction of sensitive metadata and tag keys.
- **Failure isolation**: `send_event` and `send_metric` never fail; telemetry problems are visible through stats, status, logs, and an optional `on_error` hook, never in the caller's request path.

## Installation

```bash
cargo add guard-agent-rs
# with the built-in Redis backend:
cargo add guard-agent-rs --features persistence
```

## Usage

```rust
use guard_agent_rs::{AgentConfig, GuardAgent, SecurityEvent};

#[tokio::main]
async fn main() {
    let mut config = AgentConfig::new("your-api-key-at-least-10-chars");
    config.endpoint = "https://api.guard-core.com".to_owned();
    config.project_id = Some("proj_your-project".to_owned());
    config.payload_signing_secret = Some("server-provided-signing-secret".to_owned());

    let agent = GuardAgent::new(config).expect("valid configuration");
    agent.start().await;

    agent
        .send_event(
            SecurityEvent::new("rate_limited")
                .with_ip_address("10.0.0.1")
                .with_endpoint("/api/users")
                .with_action_taken("blocked"),
        )
        .await;

    // ... at shutdown:
    agent.stop().await;
}
```

Manual flushes are available at any time:

```rust
agent.flush_buffer().await;
let status = agent.get_status().await;
let stats = agent.get_stats().await;
```

## Reliability semantics

The ingestion API contract is verified against the Guard backend source (`guard-core-api/guard_core_api/api/routers/telemetry_router.py`):

| Situation | Behavior |
| --- | --- |
| 2xx from `POST /api/v1/events`, `/api/v1/metrics`, `/api/v1/status` | Batch confirmed; persisted records deleted |
| 200 with `success: false` or non-empty `errors` | Partial failure: batch requeued, no in-loop retry |
| 429 | Honors `Retry-After` (seconds; default 60, capped at 300) inside the retry loop |
| 400, 404, 422 | Permanent rejection: batch dropped, durable records deleted, no retry |
| 413 | Split the batch in half and retry each half; drop a singleton that still 413s |
| 401, 403, other 4xx, 5xx, network errors | Retryable with exponential backoff under the circuit breaker |
| Buffer overflow | Configurable: evict oldest (default), block the caller, or surface an error |
| Redis write failure | Fail-open: record stays in memory, failure counted in stats |
| Process restart with persistence | Records with surviving TTL are reloaded into the buffer |

The HMAC signature covers the uncompressed JSON body, which is what the server verifies after its gzip middleware decompresses the request (this intentionally differs from the Python and TypeScript agents, which sign the post-gzip wire bytes and therefore fail verification when compression is active).

## Configuration

All fields live on `AgentConfig` and have defaults; see the rustdoc for the full list. Highlights:

| Field | Default | Notes |
| --- | --- | --- |
| `endpoint` | `https://api.guard-core.com` | Trailing slashes and a legacy `/api/v1` suffix are stripped |
| `buffer_size` | `100` | Per kind (events and metrics each) |
| `flush_interval` | `30` seconds | Time trigger |
| `high_watermark_ratio` | `0.8` | Occupancy trigger |
| `buffer_overflow_policy` | `drop` | `drop`, `block`, or `raise` |
| `retry_attempts` | `3` | Total attempts are this value plus one |
| `compression_threshold` | `1024` bytes | Bodies at or above this size are gzipped |
| `payload_signing_secret` | none | No signature header when unset |
| `install_id` | generated | Persisted at `~/.guard-agent/install-id` when not overridden |

## Feature flags

- `persistence` (optional): adds the `redis` dependency and the built-in `RedisClientHandler` plus `RedisConfig`. The `RedisHandler` trait and an in-memory store are always available, so a custom store needs no feature.

## Links

- Repository: <https://github.com/rennf93/guard-agent-rs>
- Guard Core (Rust): <https://github.com/rennf93/guard-core-rs>
- Guard Agent (Python): <https://github.com/rennf93/guard-agent>
- Guard Agent (TypeScript): <https://github.com/rennf93/guard-agent-ts>

## License

Dual licensed under MIT or Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
