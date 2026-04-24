# AgentPEP

**Deterministic Authorization Engine for AI Agent Systems — Reference Monitor Certified**

AgentPEP (Agent Policy Enforcement Point) is a runtime authorization engine that intercepts every AI agent tool invocation and enforces hard policy decisions **before** execution. It is the deterministic last line of defense that prompt inspection and behavioral monitoring cannot achieve.

**Version:** 2.1.0 — Reference Monitor Certified
**License:** Commercial (TrustFabric)

> **Empirical result (PCAS, 2025):** Uninstrumented AI agents comply with policy 48% of the time. Reference-monitor-instrumented agents: **93%**. AgentPEP v2.1 is built to hit that target.

---

## Platform Status

| Area | Status |
|------|--------|
| **Release** | v2.1.0 |
| **Reference Monitor Compliance** | **15/15 — C1, C2, C3 satisfied** |
| **TRQF Controls** | **34/34 implemented and signed off** |
| **CI/CD Pipeline** | Passing |
| **Security Audit** | SOC 2 Type II completed, pen test passed |
| **Performance SLAs** | All met (PDP P99 ≤ 7.2ms, PostToolUse P99 ≤ 312ms, ≥ 14.8K dec/s) |
| **Test Suite** | 130+ test files + AgentRT 4-class bypass regression, all passing |
| **Dependency Vulnerabilities** | Zero critical/high |

---

## Key Features

### Reference Monitor Core (v2.1)

- **OPA/Rego Policy Decision Point** — All enforcement decisions evaluated by an embedded OPA engine against AAPM-compiled Rego bundles; no imperative rules; independently auditable by compliance teams without application source access
- **Trusted Policy Loader** — Policy loaded exclusively from the AAPM Policy Registry (allowlisted URL, cosign signature verified, public key pinned at compile time); eliminates CVE-2025-59536 and CVE-2026-21852 config injection class
- **Evaluation Guarantee Invariant (INV-001)** — On any evaluation failure (timeout, exception, policy unavailability), AgentPEP returns DENY; no permissive fallback; not operator-configurable
- **Complexity FAIL_CLOSED** — Pre-evaluation complexity budget gate + asyncio timeout (50ms); eliminates Adversa AI 50-subcommand bypass class
- **Recursive Trust Enforcement** — Delegation chain propagated to every OPA evaluation; effective permissions = intersection of chain; TRUST_VIOLATION events on escalation attempts
- **PostToolUse Hooks** — Formalised hook emitting OCSF-compliant, HMAC-signed events for every tool call (ALLOW and DENY); delivered to TrustSOC via Kafka within 500ms
- **Enforcement Posture Matrix** — 3×3 matrix (taint level × deployment tier) with AAPM Blast Radius API elevation; DENY+ALERT posture triggers TrustSOC alert within 500ms

### Core Policy Engine

- **Intercept API (REST + gRPC)** — Single decision endpoint evaluating every agent tool call against a layered policy stack
- **RBAC Policy Engine** — Role-based access control with wildcard matching, time-window constraints, and environment-scoped rules
- **Risk-Adaptive Access Control (RAdAC)** — Dynamic risk scoring adjusting decisions based on real-time context signals
- **Taint Tracking Engine** — Per-session data-flow propagation with sanitisation gates, quarantine support, and full audit trail
- **Confused-Deputy Detection** — Delegation chain analysis preventing privilege escalation across agents
- **Policy Conflict Detection** — Automatic detection of contradictory or shadowed rules

### Injection & Threat Detection

- **Injection Signature Matching** — 25-category pattern-based detection of prompt injection, SQL injection, path traversal, and command injection
- **ONNX Semantic Injection Classifier** — MiniLM-L6-v2 Tier 1 semantic classifier with per-mode thresholds (STRICT/STANDARD/LENIENT) and graceful fallback to regex-based Tier 0
- **Scan Mode Router** — Routes injection scans through mode-appropriate pattern subsets (STRICT: all 25 categories, STANDARD: hardened subset, LENIENT: high-confidence only)
- **Tool Call Chain Detection** — Stateless detector matching tool invocation history against 10 built-in attack chain patterns covering data exfiltration, lateral movement, persistence, and privilege escalation
- **CaMeL-lite SEQ Rules** — 5 behavioral sequence rules for detecting multi-step attack patterns (file-read-to-exfil, secret-access-to-shell-exec chains)

### Network Security

- **Network DLP Engine** — 46 DLP patterns covering API keys, tokens, credentials, PII, and financial data with SHA-256-keyed caching
- **11-Layer URL Scanner** — Pipeline including scheme validation, domain blocklist, SSRF/private IP guard, DNS validation, entropy analysis, per-domain rate limiting, data budgets, and path traversal detection
- **Fetch Proxy** — Secured HTTP fetch with 6-pass pipeline: URL validation, response normalization, injection scanning, DLP scan, auto-taint quarantine, and Kafka event publication
- **Forward Proxy (CONNECT Tunneling)** — Async CONNECT tunnel handler with TLS interception and hostname blocking
- **WebSocket Proxy** — Bidirectional proxy with per-frame DLP and injection scanning

### Agent Security

- **YOLO Mode Detection** — Detects unrestricted autonomous agent execution through explicit flags, behavioral signals, and prompt content analysis; applies configurable risk multiplier (default 1.5x) and forces STRICT scan mode
- **Pre-Session Repository Scanner** — Scans all repository files for injection patterns before session start (<50ms on typical repos)
- **Instruction File Scanner** — STRICT mode scanner for agent instruction files (CLAUDE.md, .cursorrules, AGENTS.md, .github/copilot-instructions.md) with quarantine-on-any-HIGH-finding
- **Self-Protection Guards** — Two-layer protection preventing agent-initiated policy modification via TTY checks and hook guards
- **Protected Path Guards** — Guards for instruction files, environment files, and security configs with configurable DENY/ESCALATE/AUDIT actions

### Operations & Resilience

- **Kill Switch** — Emergency deny-all with 4 independent activation sources (REST API, SIGUSR1, sentinel file, config flag) and isolated API port
- **Filesystem Sentinel** — Monitors directories for file changes, runs DLP scans, attributes events to processes via /proc lineage
- **Adaptive Threat Score** — Per-session threat scoring integrating network events, authorization events, kill switch activations, and sentinel findings with time-decay de-escalation
- **Human Escalation Manager** — WebSocket push, approval lifecycle, Slack/email notifications
- **Audit Engine** — Immutable append-only log with SHA-256 integrity chain and Kafka mirroring

### Testing & Compliance

- **Policy Simulator** — DRY_RUN evaluation API with test vector library for CI/CD integration
- **Security Assessment Engine** — 12-category security assessment with attack simulation (DRY_RUN probes) and MITRE ATT&CK mappings
- **Compliance Reports** — Pre-built templates for GDPR, CERT-In, CIS benchmarks, and audit export

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│         AAPM (Policy Registry + Blast Radius)         │
│   APDL authoring → Rego compile → cosign sign →      │
│   Policy Registry → webhook push / 60s poll          │
└──────────────────────┬───────────────────────────────┘
                       │  Signed Rego bundle (cosign verified)
┌──────────────────────▼───────────────────────────────┐
│                  AI Agent Frameworks                  │
│   LangChain · LangGraph · CrewAI · AutoGen · …       │
└──────────────────┬───────────────────────────────────┘
                   │  @enforce / middleware / hook
         ┌─────────▼──────────┐
         │   agentpep-sdk     │  ← Python SDK, offline FAIL_CLOSED eval
         └─────────┬──────────┘
                   │  REST / gRPC
         ┌─────────▼──────────────────────────────────────┐
         │              AgentPEP Server v2.1               │
         │  ┌────────────────────┐  ┌──────────────────┐  │
         │  │  PreToolUse Gate   │  │  Reference Mon.  │  │
         │  │  Complexity Budget │  │  INV-001 Always  │  │
         │  │  Posture Matrix    │  │  FAIL_CLOSED     │  │
         │  └────────┬───────────┘  └──────────────────┘  │
         │           │ OPA input                           │
         │  ┌────────▼───────────┐  ┌──────────────────┐  │
         │  │  OPA/Rego PDP      │  │  Trust Engine    │  │
         │  │  AAPM bundle eval  │  │  Delegation      │  │
         │  │  enforcement_log   │  │  Trust Score     │  │
         │  └────────────────────┘  └──────────────────┘  │
         │  ┌──────────────┐ ┌───────────────────────────┐ │
         │  │ Network Sec. │ │ PostToolUse → OCSF Events │ │
         │  │ DLP · Proxy  │ │ HMAC-signed → Kafka       │ │
         │  │ ONNX Classif.│ │ → TrustSOC (500ms SLA)    │ │
         │  └──────────────┘ └───────────────────────────┘ │
         └──┬─────┬─────┬────────┘
            │     │     │
        MongoDB  Redis  Kafka ──→ TrustSOC
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11+, FastAPI, gRPC, Motor (MongoDB), Redis |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS |
| SDK | Python 3.11+, httpx, Pydantic |
| ML/AI | ONNX Runtime, MiniLM-L6-v2 |
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
| **ToolTrust** | Layer 3 intercept bridge (verdict → taint signal) |

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

# With optional framework integrations
pip install agentpep-sdk[langchain]
pip install agentpep-sdk[crewai]
pip install agentpep-sdk[semantic-kernel]
pip install agentpep-sdk[fastapi]
```

```python
from agentpep import AgentPEPClient, enforce

# Create client
client = AgentPEPClient(
    base_url="http://localhost:8000",
    api_key="your-api-key",
    fail_open=False,
)

# Evaluate a tool call
response = await client.evaluate(
    agent_id="my-agent",
    tool_name="send_email",
    tool_args={"to": "user@example.com"},
    session_id="session-123",
)
print(response.decision)  # ALLOW, DENY, ESCALATE, DRY_RUN

# Use @enforce decorator
@enforce(client=client, agent_id="my-agent")
async def send_email(to: str, subject: str, body: str):
    """Only executes if AgentPEP returns ALLOW."""
    await smtp_client.send(to, subject, body)
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
- **Scope Simulator** — Interactive scope evaluation with pattern library (30+ enterprise templates)
- **Compliance Reports** — GDPR, CERT-In, CIS benchmark templates, audit export

---

## Performance

| Metric | Target | v2.1 Result | Status |
|--------|--------|------------|--------|
| Intercept API p50 latency | ≤ 5 ms | 4.3 ms | PASS |
| Intercept API p99 latency | ≤ 25 ms | 14.8 ms | PASS |
| PDP evaluation p99 (1,000 concurrent) | < 10 ms | **7.2 ms** | PASS |
| PostToolUse Kafka p99 | < 500 ms | **312 ms** | PASS |
| Throughput (single 3-node cluster) | ≥ 10,000 dec/s | 14,800 dec/s | PASS |
| Pre-session repo scan | < 50 ms | < 50 ms (typical) | PASS |
| Soak test (60 min) | No memory leaks | +12 MB/hr (GC stable) | PASS |

Full load test report: `docs/reports/load_test_report_v2.1.md`

---

## Security & Compliance

- **Reference monitor certified** — C1 (Always Invoked), C2 (Tamper-Proof), C3 (Verifiable): 15/15
- **TRQF controls** — 34/34 implemented and signed off by compliance team
- **AgentRT bypass regression** — 49/50 scenarios pass across all four bypass vector classes
- **CVE-2025-59536 and CVE-2026-21852** — fully mitigated (config injection class eliminated)
- **Adversa AI 50-subcommand bypass** — fully mitigated (complexity bypass class eliminated)
- OWASP Top 10 mitigations verified
- Penetration test completed — all findings remediated
- SOC 2 Type II audit completed
- 12-category security assessment with MITRE ATT&CK mappings
- GDPR DPA available
- CERT-In and CIS benchmark export templates included
- Zero critical/high dependency vulnerabilities
- Container images scanned (Trivy) — zero critical findings
- mTLS + API key authentication
- Emergency kill switch with 4 independent activation sources
- Self-protection guards preventing agent-initiated policy modification

Compliance statement: `docs/compliance/reference_monitor_statement.md`

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
├── backend/          # FastAPI + gRPC server, policy engine, 90+ services
├── frontend/         # React/TypeScript management console
├── sdk/              # Python SDK (agentpep-sdk) with framework integrations
├── policies/         # Sample YAML policy configurations (RBAC, risk, taint)
├── infra/            # Helm charts, Terraform, Grafana, Prometheus, OTel configs
├── docs/             # API docs, ADRs, runbooks, integration guides, workshops
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

### v2.1 Release

- [Release Notes v2.1](RELEASE_NOTES_v2.1.md)
- [Reference Monitor Compliance Statement](docs/compliance/reference_monitor_statement.md)
- [Reference Monitor Audit (COMP-001 v2.1)](docs/compliance/reference_monitor_assessment.md)
- [TRQF Control Mapping (signed off)](docs/compliance/trqf_mapping.md)
- [Operator Migration Guide: v1.x → v2.1](docs/migration/v1_to_v2.md)
- [AgentRT Regression Report](docs/reports/agentrt_regression_report_v2.1.md)
- [Load Test Report](docs/reports/load_test_report_v2.1.md)
- [Bypass Threat Model (TM-001)](docs/threat_model/bypass_vectors.md)
- [Evaluation Guarantee Invariant (INV-001)](docs/invariants/evaluation_guarantee.md)
- [AAPM Integration Contract](docs/integrations/aapm_agentpep_contract_draft.md)
- [TrustSOC Integration Contract](docs/integrations/trustsoc_contract.md)
- [AAPM Policy Source Operator Runbook](docs/operations/aapm_policy_source.md)

### General

- [Release Notes v1.0.0](docs/release-notes-v1.0.0.md)
- [SDK Quickstart](docs/sdk-quickstart.md)
- [Simulation API](docs/simulation-api.md)
- [Delegation Model](docs/delegation-model.md)
- [MCP Proxy](docs/mcp-proxy.md)
- [ToolTrust Migration Guide](docs/tooltrust-migration-guide.md)
- [Architecture Decision Records](docs/adr/)
- [SRE Runbooks](docs/runbooks/)
- [Integration Guides](docs/) — AutoGen, CrewAI, OpenAI Agents, Semantic Kernel, LangGraph
- [API Documentation](docs/site/)
