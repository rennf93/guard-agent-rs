# guard-agent-rs

Telemetry and monitoring agent for the [guard ecosystem](https://github.com/rennf93) (Rust). Companion agent to [guard-core-rs](https://github.com/rennf93/guard-core-rs) and its thin adapters.

**Status:** Reserved namespace. Implementation pending — see [guard-core-rs](https://github.com/rennf93/guard-core-rs) for the reference engine and roadmap.

## About

The guard ecosystem provides application-layer API security middleware across multiple languages and frameworks:

- **Python**: [fastapi-guard](https://github.com/rennf93/fastapi-guard), [flaskapi-guard](https://github.com/rennf93/flaskapi-guard), [djapi-guard](https://github.com/rennf93/djapi-guard), [tornadoapi-guard](https://github.com/rennf93/tornadoapi-guard), with [guard-agent](https://pypi.org/project/guard-agent/) for telemetry
- **TypeScript**: [guard-core-ts](https://github.com/rennf93/guard-core-ts) with adapters for Express, Fastify, Hono, NestJS, plus [guardagent](https://github.com/rennf93/guard-agent-ts) for telemetry
- **Rust**: [guard-core-rs](https://github.com/rennf93/guard-core-rs) (in development) with adapters for [tower](https://github.com/rennf93/tower-guard-rs), [axum](https://github.com/rennf93/axum-guard-rs), [actix-web](https://github.com/rennf93/actix-guard-rs), [rocket](https://github.com/rennf93/rocket-guard-rs)

## License

MIT
