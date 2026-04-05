# AgentPEP v1.0.0 — General Availability Release Notes

**Release Date:** April 3, 2026
**Status:** General Availability (GA)

---

## Overview

AgentPEP v1.0.0 is the first generally available release of the Agent Policy
Enforcement Point — a deterministic, runtime authorization engine purpose-built
for AI agent systems.

AgentPEP intercepts every tool invocation, API call, and inter-agent delegation
request at the execution boundary and evaluates it against a layered policy
stack. Unlike prompt inspection gateways, AgentPEP enforces hard deterministic
limits in conventional verifiable code that cannot be bypassed by adversarial
prompt engineering.

---

## Key Capabilities

### Intercept API

A single REST and gRPC endpoint that sits between the LLM decision and action
execution. Every tool call is evaluated against the policy stack and receives an
explicit ALLOW or DENY decision with a full audit trail.

### RBAC Policy Engine

Hierarchical role-based access control with:
- Wildcard resource matching (`tool:database:*`)
- Time-window constraints (business-hours-only rules)
- Environment-scoped rules (production vs. staging)
- Policy conflict detection and reporting

### Taint Tracking

Session-scoped, directed-graph taint propagation that:
- Labels data with sensitivity classifications at ingestion
- Propagates taint through tool-call chains automatically
- Enforces sanitisation gates before cross-boundary transfers
- Supports quarantine for suspicious data flows
- Provides full audit trail of taint lifecycle events

### Confused-Deputy Detection

Delegation chain analysis that prevents privilege escalation when one agent
invokes another agent's tools. Detects circular delegations, excessive chain
depth, and cross-trust-boundary escalations.

### Risk-Adaptive Access Control

Dynamic risk scoring that adjusts policy decisions based on real-time context:
- Agent reputation and history
- Request sensitivity and data classification
- Environmental risk signals
- Anomaly detection on request patterns

---

## SDK & Integrations

### Python SDK (`agentpep-sdk`)

```bash
pip install agentpep-sdk
```

- **`AgentPEPClient`** — async HTTP client for the Intercept API
- **`@enforce` decorator** — wrap any function with policy enforcement
- **FastAPI middleware** — automatic interception for FastAPI applications
- **Offline mode** — client-side rule evaluation when server is unavailable

### LangChain

```python
from agentpep.integrations.langchain import AgentPEPToolWrapper

wrapped_tool = AgentPEPToolWrapper(tool=my_tool, client=agentpep_client)
```

### LangGraph

```python
from agentpep.integrations.langgraph import agentpep_guardrail_node

graph.add_node("policy_check", agentpep_guardrail_node(client=agentpep_client))
```

---

## Deployment

### Docker Compose (Development)

```bash
docker compose up
```

Starts the full stack: backend (port 8000), frontend (port 5173), MongoDB, and Kafka.

### Production

- Docker images published with semantic version tags
- Helm chart available for Kubernetes deployments
- Available on AWS Marketplace and GCP Marketplace

### Configuration

All configuration via environment variables with the `AGENTPEP_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTPEP_MONGODB_URL` | `mongodb://localhost:27017` | MongoDB connection string |
| `AGENTPEP_AUTH_ENABLED` | `true` | Enable API key authentication |
| `AGENTPEP_MTLS_ENABLED` | `false` | Enable mTLS for service-to-service |
| `AGENTPEP_GRPC_ENABLED` | `false` | Enable gRPC interface |
| `AGENTPEP_METRICS_ENABLED` | `true` | Enable Prometheus metrics |
| `AGENTPEP_DEFAULT_FAIL_MODE` | `FAIL_CLOSED` | Deny by default on errors |

---

## Performance

| Metric | Target | Measured |
|--------|--------|----------|
| Intercept p50 latency | ≤ 5 ms | 3.2 ms |
| Intercept p99 latency | ≤ 25 ms | 18 ms |
| Throughput (single node) | ≥ 10K decisions/s | 12.4K decisions/s |
| Rule cache hit ratio | ≥ 95% | 97.3% |
| Memory (steady state) | < 512 MB | 380 MB |

---

## SLA Commitments

| Metric | Target |
|--------|--------|
| Availability | 99.95% monthly uptime |
| Decision latency p99 | ≤ 25 ms |
| Data durability (audit logs) | 99.999% |
| Incident response (P0) | ≤ 15 minutes |
| Incident resolution (P0) | ≤ 4 hours |

---

## Known Limitations

- Frontend dashboard is read-only in v1.0.0; policy editing UI ships in v1.1.
- gRPC streaming for bulk decisions is experimental.
- Taint graph visualisation requires external tooling (Grafana plugin planned).
- Maximum delegation chain depth is 10 hops (configurable).

---

## Upgrade Path

This is the initial GA release. Future releases will follow semantic versioning:
- **Patch (1.0.x):** Bug fixes and security patches.
- **Minor (1.x.0):** New features, backward-compatible API additions.
- **Major (x.0.0):** Breaking API changes (with migration guide).

---

## Resources

- [API Conventions](api-conventions.md)
- [SDK Quickstart](sdk-quickstart.md)
- [Contributing Guide](contributing.md)
- [Delegation Model](delegation-model.md)
- [SRE Runbook](sre-runbook.md)
- [Changelog](../CHANGELOG.md)

---

*AgentPEP · TrustFabric Portfolio · © 2026*
