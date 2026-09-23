//! Command basic_usage wires guard-agent-rs into an application the way a
//! production service would: an engine or adapter middleware translates each
//! block verdict into a `SecurityEvent`, the agent buffers it and ships it
//! to the Guard Core App ingestion API, and shutdown performs a final flush.
//!
//! Set GUARD_AGENT_API_KEY (required), GUARD_AGENT_PROJECT_ID,
//! GUARD_AGENT_SIGNING_SECRET (optional, enables HMAC signing), and
//! GUARD_AGENT_ENDPOINT (optional, defaults to the ingestion API) before
//! running. Optional persistence (feature `persistence`):
//! GUARD_AGENT_REDIS_URL.
//!
//! Wiring path note: guard-core-rs does not expose a telemetry hook seam
//! yet (no `OnBlock` equivalent; the facade re-exports the detection
//! modules only and has no config/pipeline layer). Until it does, the event
//! is built the way the Rust adapters do it: the adapter middleware runs
//! the engine's detection, translates the block verdict into a
//! `SecurityEvent`, and hands it to the agent (`block_event` below shows
//! that translation). When the engine grows a hook seam, this example
//! should switch to it.

use guard_agent_rs::{AgentConfig, GuardAgent, SecurityEvent};

/// The listen address the example reports (the example does not serve
/// traffic; it demonstrates the agent wiring only).
const DEMO_ENDPOINT: &str = "/search";

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let Some(api_key) = env("GUARD_AGENT_API_KEY") else {
        log::error!("GUARD_AGENT_API_KEY is required");
        return;
    };

    let mut config = AgentConfig::new(api_key);
    if let Some(endpoint) = env("GUARD_AGENT_ENDPOINT") {
        config.endpoint = endpoint;
    }
    config.project_id = env("GUARD_AGENT_PROJECT_ID");
    config.payload_signing_secret = env("GUARD_AGENT_SIGNING_SECRET");
    config.guard_version = Some("example".to_owned());
    config.guard_core_version = Some("guard-core-rs 0.0.1".to_owned());

    let agent = match GuardAgent::new(config) {
        Ok(agent) => agent,
        Err(error) => {
            log::error!("agent: {error}");
            return;
        }
    };
    agent.start().await;

    // In a real service this line sits inside the adapter middleware: the
    // engine produced a block verdict, the adapter translates it, the agent
    // ships it. `send_event` never fails; telemetry problems surface
    // through stats, status, logs, and the optional `on_error` hook.
    let event = block_event(
        "203.0.113.9",
        DEMO_ENDPOINT,
        "GET",
        "suspicious content detected in query parameter",
        403,
    );
    agent.send_event(event).await;

    log::info!(
        "agent healthy: {} (stats: {:?})",
        agent.health_check().await,
        agent.get_stats().await
    );

    wait_for_shutdown().await;

    agent.stop().await;
    log::info!("agent stopped after final flush");
}

/// Translates an engine block verdict (the fields an adapter carries per
/// blocked request) into the wire event. This mirrors the Python
/// `SecurityEvent` shape the ingestion API expects.
fn block_event(
    ip_address: &str,
    endpoint: &str,
    method: &str,
    reason: &str,
    status_code: u16,
) -> SecurityEvent {
    let mut event = SecurityEvent::new("suspicious_request");
    event.ip_address = ip_address.to_owned();
    event.endpoint = Some(endpoint.to_owned());
    event.method = Some(method.to_owned());
    event.action_taken = "BLOCKED".to_owned();
    event.reason = reason.to_owned();
    event.status_code = Some(status_code);
    event
}

/// Resolves an environment variable into `None` when unset or empty.
fn env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

/// Idles until SIGINT or SIGTERM, as a service would between events.
async fn wait_for_shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
