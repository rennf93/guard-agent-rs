# AGENTS.md
Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

guard-agent-rs is the Rust telemetry agent for the Guard ecosystem. It buffers security events, metrics, and status reports in memory, flushes them to the Guard ingestion API with at-least-once semantics, and exposes an injectable persistence layer (Redis or custom) so unconfirmed telemetry survives process restarts. It is the Rust counterpart of the Python `guard-agent` and the TypeScript `guardagent` packages, and a standalone crate (it is not a member of the guard-core-rs workspace).

- Package name: `guard-agent-rs` (import name `guard_agent_rs`)
- Version: 0.1.0
- Edition: 2024, MSRV 1.92
- License: dual MIT OR Apache-2.0
- License files: `LICENSE-MIT` and `LICENSE-APACHE` (there is no single `LICENSE` file)

## Ecosystem Position

```
guard-core (Python engine) / guard-core-rs (Rust engine)
├── guard-agent / guard-agent-ts / guard-agent-rs (this repo)   <- Telemetry agents
├── fastapi-guard, flaskapi-guard, djapi-guard, tornadoapi-guard <- Python adapters
└── tower-guard-rs, axum-guard-rs, actix-guard-rs, rocket-guard-rs <- Rust adapters
```

The agent depends only on the ingestion contract of `guard-core-app/backend/guard-core-api` (`POST /api/v1/events`, `/api/v1/metrics`, `/api/v1/status` with `X-API-Key`, `X-Project-Id`, `X-Agent-Install-Id`, optional gzip and `X-Payload-Signature`). It contains no security-detection logic; engines and adapters produce the events, the agent ships them.

## Architecture

```
src/
├── lib.rs             # Crate docs, re-exports, AGENT_VERSION
├── config.rs          # AgentConfig, BufferOverflowPolicy, RedisConfig, validation
├── models.rs          # SecurityEvent, SecurityMetric, MetricType, AgentStatus (wire shapes)
├── error.rs           # GuardAgentError, ConfigError, ErrorStage
├── agent.rs           # GuardAgent: buffers, flush handshake, streaks, loops, stats
├── transport.rs       # HttpTransport: gzip, signing, retry, 413 split, breaker
├── circuit_breaker.rs # CircuitBreaker (5 failures / 60s recovery)
├── persistence.rs     # RedisHandler trait, InMemoryRedisStore, RedisClientHandler (feature)
├── signing.rs         # HMAC-SHA256, v1=<hex> over the uncompressed body
├── install_id.rs      # Install id resolution (~/.guard-agent/install-id)
└── utils.rs           # Backoff, Retry-After parsing, redaction, gzip, batch ids
tests/
├── helpers/mod.rs         # wiremock mock ingestion server mirroring the API contract
├── integration.rs         # End-to-end contract and failure-isolation tests
├── persistence_fake.rs    # Persistence handshake with the in-memory store
└── persistence_redis.rs   # Real-Redis tests (#[ignore]d; run with --include-ignored)
```

Key invariants an agent must preserve when editing:

- `send_event` / `send_metric` never fail. All errors funnel into logs, counters (`get_stats`), and the optional `on_error` hook.
- The flush layer owns the at-least-once handshake: drain, send, then confirm (delete persisted keys) on `Accepted` or intentional `PermanentDrop`, or requeue at the front in original order on `Failed`.
- 400, 404, and 422 are terminal drops; 401, 403, other 4xx, 5xx, and network errors are retryable; 429 consumes an attempt and sleeps the `Retry-After` value.
- Overflow `drop` evicts the oldest item and deletes its persisted record; requeue pressure evicts the newest tail item the same way. No orphaned records.
- Persistence is fail-open: a store error never blocks buffering or sending.

## Quick Start

```bash
# Build and test (default features; no Redis needed)
cargo build
cargo test

# Everything, including the Redis persistence feature
cargo test --all-features

# Real-Redis integration tests (requires Redis on 127.0.0.1:6379)
cargo test --all-features --test persistence_redis -- --include-ignored

# Lint and format
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

## Configuration

`AgentConfig::new(api_key)` fills defaults; `GuardAgent::new` validates and normalizes (endpoint trailing slashes and legacy `/api/v1` suffix are stripped). Important fields: `endpoint`, `project_id`, `buffer_size` (100 per kind), `flush_interval` (30s), `status_interval` (300s, minimum 60), `high_watermark_ratio` (0.8), `buffer_overflow_policy` (`drop`/`block`/`raise`), `retry_attempts` (3), `backoff_factor` (1.0), `timeout` (30s), `compression_enabled` + `compression_threshold` (1024 bytes), `payload_signing_secret`, `install_id`, and with feature `persistence` a `redis: Option<RedisConfig>` (URL carries credentials and DB index; `key_prefix` defaults to `guard:agent`).

A custom store works without the feature: implement `RedisHandler` (five async methods: set, get, delete, list, clear, all namespace-scoped) and call `agent.attach_redis_handler(Arc::new(store)).await` before `start()`.

## Reliability Semantics

Mirror the Python agent unless a deviation is documented here:

- Flush triggers: buffer occupancy at or above `buffer_size * high_watermark_ratio`, or `flush_interval` elapsed since the last drain. A semaphore (`max_concurrent_flushes`) serializes flushes.
- Per-kind failure streaks: after a failed events or metrics flush, that kind is gated for `min(flush_interval * 2^(streak-1), 300)` seconds. Success resets the streak.
- Degraded state (computed in `get_status`): circuit breaker OPEN, buffer at 90% of capacity, or lifetime failure rate above 10%. `health_check` adds the 95% buffer and 50% failure-rate thresholds.
- The HMAC signature covers the uncompressed JSON body. The server verifies the signature after its gzip middleware decompresses the request, so this agent deliberately fixes the Python/TS defect of signing the post-gzip bytes.
- Success is any 2xx. The real API returns 200 (with a `TelemetryResponse` body), not 202; partial failures also return 200 with `success: false` or a non-empty `errors` list.

## Development Commands

```bash
cargo build                                # compile
cargo test                                 # unit + integration (mocked), default features
cargo test --all-features                  # + persistence feature (Redis tests stay ignored)
cargo test --all-features -- --include-ignored  # also run real-Redis tests
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo doc --no-deps --all-features         # rustdoc
```

`rustfmt.toml` enables nightly-only options (`imports_granularity`, `group_imports`, `wrap_comments`, ...). On stable, `cargo fmt` applies the stable subset and prints warnings; this matches guard-core-rs and is expected.

## Testing Guidelines

- Unit tests live inline (`#[cfg(test)] mod tests`) next to the code they cover; contract and end-to-end tests live in `tests/`.
- The mock ingestion server in `tests/helpers/mod.rs` mirrors the verified API contract: 200 success, gzip decompression before verification, signature over the decompressed body, pluggable failure behaviors. Extend it there, never inline.
- Real-Redis tests are `#[ignore]`d with a reason; CI runs them with a Redis service and `--include-ignored`. Keep each test's Redis keys under a unique prefix so tests can run in parallel.
- Timing-sensitive tests poll with `wait_until` rather than sleeping fixed durations.
- Keep the suite green at 100% of these behaviors when touching transport, buffer, or flush code: retry/backoff, Retry-After, 413 split-or-drop, permanent rejection, partial-failure requeue, per-kind gates, degraded state, persistence handshake.

## Best Practices

- No `unsafe` (enforced: `unsafe_code = "forbid"`), no panics across the public API; use typed errors from `error.rs`.
- Clippy is `pedantic` + `nursery` (warn) with `all` denied, and CI runs `-D warnings`; the two blanket-allowed nursery lints (`significant_drop_tightening`, `duration_suboptimal_units`) are documented in `Cargo.toml`. Prefer fixing code over adding allows.
- Every public item needs rustdoc. Wire models serialize snake_case to match the Python agent's `model_dump()` output.
- Keep `Cargo.lock` committed. Do not bump dependencies casually; run `cargo deny check` when touching them.
- Never merge or release without the repository owner; PRs stay drafts until CI is green and reviewed.
- Do not introduce framework dependencies (axum, actix, tokio-web frameworks); the agent is transport-level only.

## Related Projects

- guard-core-rs: Rust security engine, <https://github.com/rennf93/guard-core-rs>
- guard-agent (Python): reference agent semantics, <https://github.com/rennf93/guard-agent>
- guard-agent-ts (TypeScript): sibling agent, <https://github.com/rennf93/guard-agent-ts>
- guard-core-app: SaaS platform hosting the ingestion API, <https://github.com/rennf93/guard-core-app>
- guard-core (Python engine): <https://github.com/rennf93/guard-core>
