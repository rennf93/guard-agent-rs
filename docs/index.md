# guard-agent-rs

`guard-agent-rs` is the Rust telemetry agent of the Guard ecosystem. It
buffers security events, metrics, and status reports produced by your
application (typically through a guard-core-rs adapter's middleware) and
ships them to the
[guard-core-app](https://github.com/rennf93/guard-core-app) ingestion API
with at-least-once delivery.

It mirrors the normative [guard-agent](https://github.com/rennf93/guard-agent)
(Python) semantics: per-kind buffers, periodic and watermark-driven flushes,
overflow policies, retry with backoff, 413 split-or-drop, Retry-After
honoring, a circuit breaker, optional Redis-backed queue persistence, and a
persisted install id.

## Installation

```bash
cargo add guard-agent-rs
# with the built-in Redis persistence backend:
cargo add guard-agent-rs --features persistence
```

Requires Rust 1.92 or later (edition 2024). A custom persistence store is
available without the feature: implement the `RedisHandler` trait and attach
it before `start()`.

## Quick start

```rust
use guard_agent_rs::{AgentConfig, GuardAgent, SecurityEvent};

#[tokio::main]
async fn main() {
    let mut config = AgentConfig::new("your-api-key-at-least-10-chars");
    config.endpoint = "https://api.guard-core.com".to_owned();
    config.project_id = Some("proj_your-project".to_owned());

    let agent = GuardAgent::new(config).expect("valid config");
    agent.start().await;

    let mut event = SecurityEvent::new("rate_limited");
    event.ip_address = "203.0.113.7".to_owned();
    event.endpoint = Some("/api".to_owned());
    event.method = Some("GET".to_owned());
    event.action_taken = "BLOCKED".to_owned();
    event.reason = "endpoint rate limit exceeded".to_owned();
    agent.send_event(event).await;

    agent.stop().await; // final flush
}
```

Most applications do not call the agent directly: engines and adapters
produce the events; the agent ships them. See
[guard-core-rs](https://github.com/rennf93/guard-core-rs) and the adapter
repositories for wiring examples, and
[`examples/basic_usage`](https://github.com/rennf93/guard-agent-rs/tree/master/examples/basic_usage)
for a minimal wiring demonstration.

## What the agent guarantees

- At-least-once delivery: buffered items survive crashes when persistence is
  enabled and are requeued in the original order on partial batch failure
- HMAC request signing: `X-Payload-Signature` covers the uncompressed body,
  matching the ingestion API's post-decompression verification
- Fail-soft: ingestion outages never panic or block the application beyond
  the chosen overflow policy; `send_event` and `send_metric` never fail
- Per-kind isolation: events and metrics buffer, flush, and back off
  independently; one kind failing never stalls the other
