---
name: guard-agent-rs
description: Use when working on the guard-agent-rs Rust telemetry crate (buffering, flushing, retries, persistence, or the ingestion contract) or when wiring Guard telemetry into a Rust service.
---

# guard-agent-rs

Rust telemetry agent for the Guard ecosystem. Buffers security events, metrics, and status; ships them to the Guard ingestion API with at-least-once semantics; optionally persists unconfirmed records in Redis. Standalone crate, edition 2024, MSRV 1.92, dual MIT OR Apache-2.0.

## Quick Reference

- Public entry points: `GuardAgent::new(AgentConfig)`, `start()`, `send_event(SecurityEvent)`, `send_metric(SecurityMetric)`, `flush_buffer()`, `get_status()`, `get_stats()`, `health_check()`, `stop()`.
- Ingest never fails: `send_event`/`send_metric` return `()`; `try_send_event` returns `Err` only under the `raise` overflow policy.
- Endpoints: `POST /api/v1/events`, `/api/v1/metrics`, `/api/v1/status`; headers `X-API-Key`, `X-Project-Id`, `X-Agent-Install-Id`; optional `Content-Encoding: gzip`; optional `X-Payload-Signature: v1=<hmac-sha256 hex of the uncompressed body>`.
- Success is any 2xx (the real API returns 200). 200 with `success: false` or non-empty `errors` = partial failure = requeue. 429 = honor `Retry-After`. 400/404/422 = drop forever. 413 = halve and retry, drop singletons. 401/403/5xx/network = retry with backoff.

## Installation

```bash
cargo add guard-agent-rs
cargo add guard-agent-rs --features persistence   # with the built-in Redis client
```

## Setup

```rust
use guard_agent_rs::{AgentConfig, GuardAgent};

let mut config = AgentConfig::new("your-api-key-at-least-10-chars");
config.endpoint = "https://api.guard-core.com".to_owned();
config.payload_signing_secret = Some("server-signing-secret".to_owned());
let agent = GuardAgent::new(config)?;
agent.start().await;          // spawns flush + status loops, attaches Redis
agent.stop().await;           // final flush, cancels loops
```

Custom store without the `persistence` feature: implement `RedisHandler` and call `agent.attach_redis_handler(store).await` before `start()`.

## Reliability Semantics

- Flush triggers: occupancy >= `buffer_size * high_watermark_ratio` (default 0.8) or `flush_interval` (default 30s) elapsed. `max_concurrent_flushes` serializes.
- Overflow policies: `drop` (evict oldest, default), `block` (backpressure), `raise` (error to the caller of `try_send_*`).
- At-least-once handshake: drain, send, confirm (delete persisted keys) on success or intentional permanent drop, requeue at the front in original order on failure.
- Per-kind streak backoff after failed flushes: `min(flush_interval * 2^(streak-1), 300s)`; the kind is skipped while gated. Success resets the streak.
- Circuit breaker: 5 consecutive non-permanent failures open the circuit for 60s; one probe is admitted at half-open.
- Degraded state (`get_status`): breaker OPEN, buffer >= 90%, or lifetime failure rate > 10%. `health_check` uses 95% / 50% and requires running loops.
- Persistence: records written with TTL 3600s on enqueue, deleted on confirmation, reloaded on `start()`. Failures are fail-open and counted in `redis_persist_failures`.

## Footguns

- The `block` overflow policy can stall the caller indefinitely while the endpoint is down; the Python agent has the same behavior. Prefer `drop` unless backpressure is intentional.
- `try_send_event` returns `Err` only under `raise`; `send_event` swallows that error (logging only), mirroring Python. Do not rely on `send_event` for delivery confirmation; check `get_stats()`.
- Signature covers the uncompressed body (server-verified). If you "fix" it to sign the wire body you reintroduce the Python/TS defect that fails verification whenever gzip kicks in.
- `status_interval` must be >= 60s (validated); `flush_interval` only needs > 0.
- Without `payload_signing_secret`, no signature header is sent; the server may require one (`INGEST_REQUIRE_SIGNED_PAYLOADS`).
- Real-Redis tests are `#[ignore]`d: run `cargo test --all-features -- --include-ignored` with Redis on 127.0.0.1:6379.
- Stable `cargo fmt` warns about nightly-only rustfmt options; that is expected and matches guard-core-rs.

## Related Projects

- guard-core-rs (Rust engine): <https://github.com/rennf93/guard-core-rs>
- guard-agent (Python, reference semantics): <https://github.com/rennf93/guard-agent>
- guard-agent-ts (TypeScript sibling): <https://github.com/rennf93/guard-agent-ts>
- guard-core-app (hosts the ingestion API): <https://github.com/rennf93/guard-core-app>
