# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-20

### Added

- `GuardAgent` with buffered events and metrics: size (high watermark) and time (flush interval) triggers, `drop`/`block`/`raise` overflow policies, and at-least-once flush handshake (drain, send, confirm or requeue in original order).
- HTTP transport: gzip compression above a configurable threshold, HMAC-SHA256 request signing over the uncompressed body (`X-Payload-Signature: v1=<hex>`), exponential backoff with `Retry-After` handling on 429, 413 split-or-drop, permanent rejection for 400/404/422, and a client-side circuit breaker.
- Per-kind failure streaks with capped backoff (up to 300s) and a computed degraded state exposed through `get_status`, `health_check`, and status pushes to `/api/v1/status`.
- Optional `persistence` feature with a built-in Redis client (`RedisClientHandler`, `RedisConfig`), a store-agnostic `RedisHandler` trait with an in-memory implementation, TTL-based records (3600s), and startup reload.
- Install identifier resolution (override, `~/.guard-agent/install-id`, or generated UUID) and sensitive metadata/tag redaction.
- Wiremock-based integration tests mirroring the verified ingestion API contract, plus real-Redis integration tests (ignored by default; run with `--include-ignored`).

[0.1.0]: https://github.com/rennf93/guard-agent-rs/releases/tag/v0.1.0
