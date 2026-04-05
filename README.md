# AgentPEP

**Deterministic Authorization Engine for AI Agent Systems**

AgentPEP (Agent Policy Enforcement Point) is a runtime authorization engine that intercepts every AI agent tool invocation and enforces hard policy decisions **before** execution. It provides the deterministic last line of defense that prompt inspection and behavioral monitoring cannot achieve.

**Version:** 1.0.0 GA (Released April 3, 2026)
**License:** Commercial (TrustFabric)

---

## Platform Status

| Area | Status |
|------|--------|
| **Release** | v1.0.0 GA |
| **CI/CD Pipeline** | Passing |
| **GA Readiness** | Approved — all checklist items PASS |
| **Security Audit** | SOC 2 Type II completed, pen test passed |
| **Performance SLAs** | All met (p50 ≤ 5ms, p99 ≤ 25ms, ≥ 10K dec/s) |
| **Test Suite** | 500+ test cases, all passing |
| **Dependency Vulnerabilities** | Zero critical/high |

---

## Key Features

- **Intercept API (REST + gRPC)** — Single decision endpoint evaluating every agent tool call against a layered policy stack
- **RBAC Policy Engine** — Role-based access control with wildcard matching, time-window constraints, and environment-scoped rules
- **Risk-Adaptive Access Control (RAdAC)** — Dynamic risk scoring adjusting decisions based on real-time context signals
- **Taint Tracking Engine** — Per-session data-flow propagation with sanitisation gates, quarantine support, and full audit trail
- **Confused-Deputy Detection** — Delegation chain analysis preventing privilege escalation across agents
- **Injection Signature Matching** — Pattern-based detection of prompt injection, SQL injection, path traversal, and command injection
- **Policy Conflict Detection** — Automatic detection of contradictory or shadowed rules
- **Human Escalation Manager** — WebSocket push, approval lifecycle, Slack/email notifications
- **Audit Engine** — Immutable append-only log with SHA-256 integrity chain and Kafka mirroring
- **Policy Simulator** — DRY_RUN evaluation API with test vector library for CI/CD integration
- **Compliance Reports** — Pre-built templates for GDPR, CERT-In, and audit export

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                  AI Agent Frameworks                  │
│   LangChain · CrewAI · AutoGen · OpenAI Agents · …  │
└──────────────────┬───────────────────────────────────┘
                   │  @enforce / middleware / hook
         ┌─────────▼──────────┐
         │   agentpep-sdk     │  ← Python SDK with offline eval
         └─────────┬──────────┘
                   │  REST / gRPC
         ┌─────────▼──────────┐
         │  AgentPEP Server   │  ← FastAPI + gRPC
         │  ┌──────────────┐  │
         │  │ Policy Engine│  │  RBAC · RAdAC · Taint · Injection
         │  └──────────────┘  │
         └──┬─────┬─────┬─────┘
            │     │     │
        MongoDB  Redis  Kafka
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11+, FastAPI, gRPC, Motor (MongoDB), Redis |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS |
| SDK | Python 3.11+, httpx, Pydantic |
| Database | MongoDB 7, Redis 7 |
| Messaging | Apache Kafka |
| Observability | Prometheus, Grafana, OpenTelemetry, Jaeger/Tempo |
| Infrastructure | Docker Compose, Kubernetes (Helm), Terraform (GKE) |
| CI/CD | GitHub Actions |
| Testing | Pytest, Vitest, Playwright, Hypothesis |

---

## SDK Integrations

| Framework | Integration |
|-----------|------------|
| **LangChain** | `AgentPEPToolWrapper` |
| **LangGraph** | `agentpep_guardrail_node` |
| **CrewAI** | Task executor filter |
| **AutoGen** | Speaker hook interception |
| **OpenAI Agents SDK** | Agent hook support |
| **Semantic Kernel** | Plugin filter pipeline |
| **FastAPI** | `@enforce` decorator + middleware |

---

## Quick Start

### Local Development (Docker Compose)

```bash
git clone <repo-url> && cd AgentPEP
docker-compose up -d
```

This starts 14 services: backend, frontend, MongoDB, Redis, Kafka, Prometheus, Grafana, Jaeger, Tempo, OpenTelemetry collector, and supporting containers.

- **Backend API:** http://localhost:8000
- **Frontend Console:** http://localhost:5173
- **Grafana Dashboards:** http://localhost:3000

### SDK Installation

```bash
pip install agentpep-sdk
```

```python
from agentpep import enforce

@enforce(tool="file_read", resource="/etc/passwd")
async def read_file(path: str) -> str:
    ...
```

---

## Frontend Dashboard

The management console provides:

- **Policy Authoring** — YAML editor, rule builder, version history, diff view
- **Agent Registry** — Register agents with roles, session limits, tool allowlists, risk budgets
- **Risk Dashboard** — Real-time heatmaps, DENY/ESCALATE trends, risk distribution charts
- **Audit Explorer** — Full-text search, timeline view, session drill-down
- **Escalation Queue** — Real-time approval queue, bulk actions, SLA timers
- **Taint Map Visualization** — Interactive graph showing data-flow propagation per session
- **Compliance Reports** — GDPR, CERT-In templates, audit export

---

## Performance

| Metric | Target | Status |
|--------|--------|--------|
| Intercept API p50 latency | ≤ 5 ms | PASS |
| Intercept API p99 latency | ≤ 25 ms | PASS |
| Throughput (single node) | ≥ 10,000 dec/s | PASS |
| Rule cache hit ratio | ≥ 95% | PASS |
| Load test (100K agents, 1M dec/min) | 1-hour sustained | PASS |
| 24-hour soak test | No memory leaks | PASS |

---

## Security & Compliance

- OWASP Top 10 mitigations verified
- Penetration test completed — all findings remediated
- SOC 2 Type II audit completed
- GDPR DPA available
- CERT-In export templates included
- Zero critical/high dependency vulnerabilities
- Container images scanned (Trivy) — zero critical findings
- mTLS + API key authentication

---

## Deployment

| Model | Tooling |
|-------|---------|
| **Local dev** | `docker-compose up -d` |
| **Kubernetes** | Helm chart at `infra/helm/agentpep/` |
| **Cloud (GCP)** | Terraform modules at `infra/terraform/` |
| **Beta** | `docker-compose.beta.yml` |

---

## Project Structure

```
AgentPEP/
├── backend/          # FastAPI + gRPC server, policy engine, services
├── frontend/         # React/TypeScript management console
├── sdk/              # Python SDK (agentpep-sdk) with framework integrations
├── infra/            # Helm charts, Terraform, Grafana, Prometheus, OTel configs
├── docs/             # API docs, ADRs, runbooks, release notes
├── loadtests/        # Load testing scripts
└── scripts/          # Utility scripts
```

---

## Running Tests

```bash
# Backend
cd backend && pytest -v

# Frontend
cd frontend && npm test

# E2E
cd frontend && npm run test:e2e

# SDK
cd sdk && pytest -v
```

---

## Documentation

- [Release Notes v1.0.0](docs/release-notes-v1.0.0.md)
- [GA Readiness Checklist](docs/ga-readiness-checklist.md)
- [SDK Quickstart](docs/sdk-quickstart.md)
- [Architecture Decision Records](docs/adr/)
- [SRE Runbooks](docs/runbooks/)
- [API Documentation](docs/site/)
