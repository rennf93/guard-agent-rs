# basic_usage

Minimal guard-agent-rs wiring: a block verdict is translated into a
`SecurityEvent`, the agent buffers it and ships it to the Guard Core App
ingestion API, and shutdown performs a final flush.

## Run

```bash
export GUARD_AGENT_API_KEY="your-api-key"                 # required (min 10 chars)
export GUARD_AGENT_ENDPOINT="https://api.guard-core.com"  # optional
export GUARD_AGENT_PROJECT_ID="your-project-id"           # optional
export GUARD_AGENT_SIGNING_SECRET="your-signing-secret"   # optional, enables HMAC signing

cargo run -p guard-agent-basic-usage
```

With Redis persistence (build the workspace with `--features persistence`):

```bash
export GUARD_AGENT_REDIS_URL="redis://127.0.0.1:6379"     # optional, enables persistence
```

The example stays a wiring demonstration: it constructs the config from the
environment, starts the agent, emits one translated block event, reports
health and stats, and idles until SIGINT/SIGTERM, then stops the agent with
a final flush. For a full guarded HTTP service, see the adapter repos
(tower-guard-rs, axum-guard-rs, actix-guard-rs, rocket-guard-rs), which
combine the engine, the adapter, and this same agent wiring.

## Wiring path

- **Engine hook seam:** guard-core-rs does not expose a telemetry hook seam
  yet (no `OnBlock` equivalent; the `guard_core_rs` facade re-exports the
  detection modules only, with no config, pipeline, or response layer).
  This example therefore wires the event the way the Rust adapters do: the
  adapter middleware runs the engine's detection and translates the block
  verdict into a `SecurityEvent` (see `block_event` in `src/main.rs`).
- **Direct agent API:** `send_event`, `send_metric`, `get_status`, and
  `get_stats` are for custom events or standalone deployments; most
  deployments only need the translation shown here.
- When the engine grows a hook seam, this example should switch to it.

## Environment variables

| Variable | Meaning | Default |
|---|---|---|
| `GUARD_AGENT_API_KEY` | Ingestion API key, required | none |
| `GUARD_AGENT_ENDPOINT` | Ingestion base URL (trailing `/api/v1` stripped) | `https://api.guard-core.com` |
| `GUARD_AGENT_PROJECT_ID` | Sent as `X-Project-Id` | unset |
| `GUARD_AGENT_SIGNING_SECRET` | HMAC-SHA256 secret over the uncompressed body | unset |
| `GUARD_AGENT_REDIS_URL` | Persistence queue URL (with the `persistence` feature) | unset (in-memory only) |

`RUST_LOG` controls logging through `env_logger` (default `info`).
