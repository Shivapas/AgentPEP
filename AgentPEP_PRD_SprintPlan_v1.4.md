# AgentPEP — Agent Policy Enforcement Point

**Deterministic Authorization Engine for AI Agent Systems**

---

| Field | Value |
|---|---|
| **Document Type** | Product Requirements Document + Sprint Plan |
| **Product** | AgentPEP — Agent Policy Enforcement Point |
| **Version** | 1.0 — Initial Release |
| **Status** | DRAFT — For Internal Review |
| **Classification** | Confidential |
| **Stack** | Python · FastAPI · React · MongoDB |
| **Sprint Count** | 56 Sprints · ~28 Months |
| **Total Stories** | ~451 User Stories |

---

## Document Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | Apr 2026 | Product Team | Initial PRD draft — architecture, features, sprint plan |
| 1.1 | Apr 2026 | Product Team | **Roadmap v1** — ToolTrust enhancement analysis and sprint plan (Sprints 29–36) |
| 1.2 | Apr 2026 | Product Team | **Roadmap v2** — ToolTrust-inspired enhancement analysis and sprint plan (Sprints 37–43) |
| 1.3 | Apr 2026 | Product Team | **Roadmap v3** — TrustFabric Network: ToolTrust capabilities natively in AgentPEP stack (Sprints 44–51) |
| 1.4 | Apr 2026 | Product Team | **Roadmap v4** — ToolTrust-inspired: ML-based injection detection, pattern library, pre-session scanner (Sprints 52–56) |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Goals and Non-Goals](#3-goals-and-non-goals)
4. [User Personas and Use Cases](#4-user-personas-and-use-cases)
5. [System Architecture](#5-system-architecture)
6. [Feature Specification](#6-feature-specification)
7. [Integration Architecture](#7-integration-architecture)
8. [Non-Functional Requirements](#8-non-functional-requirements)
9. [Security Model](#9-security-model)
10. [Success Metrics](#10-success-metrics)
11. [Sprint Plan](#11-sprint-plan-36-sprints--18-months)
12. [ToolTrust Enhancement Roadmap v1](#12-ToolTrust-enhancement-roadmap-v1)
13. [ToolTrust Enhancement Roadmap v2](#13-ToolTrust-enhancement-roadmap-v2)
14. [TrustFabric Network: ToolTrust-Native Roadmap v3](#14-trustfabric-network-ToolTrust-native-roadmap-v3)
15. [ToolTrust-Inspired Roadmap v4: ML Injection Detection & Content Ingestion Security](#15-ToolTrust-inspired-roadmap-v4-ml-injection-detection--content-ingestion-security)

---

# 1. Executive Summary

AgentPEP is a deterministic, runtime authorization engine purpose-built for AI agent systems. It intercepts every tool invocation, API call, and inter-agent delegation request at the execution boundary — after the LLM has decided but before any action is taken — and evaluates it against a layered policy stack composed of role-based access control (RBAC), taint-aware data flow tracking, risk-adaptive scoring, and confused-deputy detection.

Unlike prompt inspection gateways (which operate on LLM inputs) or behavioral monitoring systems (which are reactive and post-hoc), AgentPEP enforces hard, deterministic limits in conventional verifiable code. It is the only layer in the AI agent security stack that cannot be bypassed by adversarial prompt engineering because it never processes LLM output as instructions — it evaluates structured tool-call metadata against static and risk-adaptive policies.

> **Core Design Principle:** AgentPEP is Sphinx-agnostic and stack-agnostic at the integration boundary. It exposes a single gRPC/REST interception API that any agent orchestrator, LLM gateway, or multi-agent framework can call. It does not inspect prompts, parse LLM reasoning, or require model-level instrumentation.

| Dimension | Detail |
|---|---|
| **Product Name** | AgentPEP — Agent Policy Enforcement Point |
| **Tagline** | The deterministic last line of defense for AI agent systems |
| **Primary Buyers** | Enterprise CISOs, AI Platform Teams, DevSecOps |
| **Deployment Model** | On-premises · Private Cloud · SaaS |
| **Core Stack** | Python / FastAPI / React / MongoDB |
| **Target Market** | Enterprises deploying LLM-based agentic workflows |
| **Competitive Moat** | Only product solving confused-deputy + taint tracking in one engine |

---

# 2. Problem Statement

## 2.1 The Deterministic Gap

The Perplexity/NIST RFI response (arXiv:2603.12230) identifies a layered defense stack for AI agent security across four layers: input-level detection, model-level instruction hierarchy, execution monitoring, and deterministic enforcement. The first three layers are probabilistic — their effectiveness depends on statistical properties of the model and training data. The fourth layer — deterministic enforcement — is described as the most mature and most necessary, yet no dedicated commercial product exists to fill it.

Current agent frameworks provide rudimentary safeguards: tool allowlists, basic sandboxes, guardrail filters. None provides a unified, policy-driven authorization engine that:

- Evaluates tool calls against structured RBAC policies before execution
- Tracks data taint from untrusted sources (web, email, tool output) and blocks tainted variables from influencing privileged operations
- Detects confused-deputy escalation across multi-agent chains
- Enforces risk-adaptive thresholds with user-configurable tolerance budgets
- Logs every authorization decision with full auditability for forensic replay

## 2.2 The Confused-Deputy Problem

In multi-agent architectures, a low-privilege outer agent can instruct a high-privilege inner agent to execute actions the originating user never authorized. This is the confused-deputy vulnerability transposed to AI: the high-privilege agent is "confused" about who its true principal is. No existing product evaluates delegation chains against originating principal authority.

## 2.3 Confirmation Fatigue

Existing safeguards that require human confirmation before every sensitive action create confirmation fatigue — users approve requests without careful review, defeating the intent. There is no principled risk-threshold mechanism that interrupts only when a calculated action risk score exceeds a user-defined tolerance.

> **Security Gap Summary:** Prompt inspection covers input. Behavioral monitoring covers output. Nothing covers the execution boundary deterministically. AgentPEP owns that boundary.

---

# 3. Goals and Non-Goals

## 3.1 Goals

1. Provide a deterministic, LLM-independent enforcement layer at the agent tool-call boundary
2. Implement taint-aware data flow tracking preventing untrusted data from driving privileged operations
3. Detect and block confused-deputy escalation across multi-agent delegation chains
4. Deliver an RBAC + Risk-Adaptive Access Control (RAdAC) hybrid policy engine for agent authorization
5. Implement risk-threshold-based human escalation, eliminating blanket confirmation prompts
6. Provide full audit logging of every authorization decision for forensic integration
7. Expose a universal interception API compatible with any agent orchestrator or LLM framework
8. Ship a React-based policy management console for security teams

## 3.2 Non-Goals

- AgentPEP does **not** inspect or analyze LLM prompts (that is Sphinx's domain)
- AgentPEP does **not** perform behavioral drift detection or threat hunting (that is AASM's domain)
- AgentPEP does **not** manage agent identities or credentials (that is AgentIAM's domain)
- AgentPEP does **not** perform forensic replay (that is AFRE's domain)
- AgentPEP does **not** train or fine-tune models
- AgentPEP does **not** replace network firewalls or traditional WAFs

---

# 4. User Personas and Use Cases

| Persona | Role | Primary Need | Key Workflows |
|---|---|---|---|
| **Elena** — CISO | Enterprise CISO | Proof that AI agents cannot take unauthorized actions | Policy authoring · Risk dashboards · Audit exports |
| **Dev** — AI Platform Eng. | Builds internal agentic pipelines | Simple SDK integration with minimal latency overhead | SDK integration · Policy testing · Local dev mode |
| **Rao** — SecOps Analyst | Monitors agent activity in SOC | Real-time alert stream + investigation context | Alert triage · Forensic drill-down · Escalation mgmt |
| **Priya** — Compliance Lead | DPDPA / GDPR / CERT-In owner | Audit trails proving policy enforcement | Compliance reports · Policy mapping · Export |
| **Marco** — Agent Developer | Builds multi-agent workflows | Understand why a tool call was blocked and fix it | Policy simulator · Dry-run mode · Error context |

---

# 5. System Architecture

## 5.1 High-Level Architecture

AgentPEP is structured as a sidecar enforcement plane that sits inline between the agent orchestration layer and the tool/capability execution surface. It exposes two integration points:

- **Intercept API (REST + gRPC):** synchronous hook called before any tool execution. Returns `ALLOW` / `DENY` / `ESCALATE`.
- **Event Stream API (WebSocket + Kafka):** async stream of authorization decisions consumed by audit, SIEM, and alerting systems.

```
User Intent
    │
    ▼
[Agent Orchestrator — LangChain / AutoGen / CrewAI / Custom]
    │
    │  ToolCallRequest (tool_name, args, session_id, agent_id)
    ▼
┌─────────────────────────────────────┐
│         AgentPEP Intercept API      │  ← POST /v1/intercept (REST / gRPC)
│                                     │
│  ① RBAC Policy Engine               │
│  ② Taint-Aware Data Flow Tracker    │
│  ③ Confused-Deputy Detector         │
│  ④ Risk Scoring Engine              │
│  ⑤ Arg Schema / Regex Validators   │
│  ⑥ Rate Limiter                    │
└───────────┬─────────────────────────┘
            │
     PolicyDecision
   ALLOW / DENY / ESCALATE
            │
    ┌───────┼───────────┐
    ▼       ▼           ▼
 Execute  Block    Escalation
  Tool    Call     Manager ──► Human Approver (Console / Slack / Email)
            │
            ▼
      Audit Logger ──► MongoDB (append-only) + Kafka topic
```

> **Architecture Constraint:** AgentPEP never executes tool calls itself. It is a pure policy evaluation engine. Tool execution remains with the agent framework. This separation ensures AgentPEP cannot be an attack surface for tool misuse.

## 5.2 Component Breakdown

| Component | Technology | Responsibility |
|---|---|---|
| Intercept API | FastAPI + gRPC | Receives tool-call interception requests; returns policy decision |
| Policy Engine | Python (Rego-inspired DSL) | Evaluates RBAC rules, taint tags, risk scores, delegation chains |
| Taint Tracker | Python — in-memory graph | Maintains per-session data flow graph; propagates taint labels |
| Risk Scorer | Python — configurable model | Calculates action risk score from operation type, data sensitivity, session state |
| Confused-Deputy Detector | Python — chain walker | Validates delegation authority against originating principal's grants |
| Policy Store | MongoDB | Stores RBAC roles, rules, agent profiles, risk thresholds |
| Audit Logger | MongoDB + Kafka topic | Immutable append-only decision log; feeds SIEM via Kafka |
| Escalation Manager | FastAPI + WebSocket | Routes ESCALATE decisions to human approvers; tracks responses |
| Policy Console (UI) | React + Vite + Tailwind | Policy authoring, risk dashboards, alert management, audit explorer |
| SDK / Agent Wrapper | Python package | Lightweight decorator/middleware for FastAPI and LangChain/LangGraph agents |
| Config & Secrets | MongoDB + Vault-compatible | Agent profiles, connector credentials, tenant config |

## 5.3 Data Models

### 5.3.1 Policy Rule

| Field | Type | Description |
|---|---|---|
| `rule_id` | UUID | Unique rule identifier |
| `name` | String | Human-readable rule name |
| `agent_role` | String[] | Roles this rule applies to |
| `tool_pattern` | String (glob/regex) | Tool name or pattern this rule governs |
| `action` | Enum: ALLOW/DENY/ESCALATE | Decision when rule matches |
| `taint_check` | Boolean | Whether to block if any argument is taint-tagged UNTRUSTED |
| `risk_threshold` | Float [0–1] | Escalate if action risk score exceeds this value |
| `rate_limit` | Object {count, window_s} | Max invocations per window; DENY on breach |
| `arg_validators` | Object[] | Schema / regex validators applied to tool arguments |
| `priority` | Integer | Evaluation order; lower = higher priority |
| `created_at / updated_at` | DateTime | Audit timestamps |

### 5.3.2 Taint Node (Session Graph)

| Field | Type | Description |
|---|---|---|
| `node_id` | UUID | Variable/value identifier within agent session |
| `session_id` | String | Agent session this node belongs to |
| `taint_level` | Enum: TRUSTED/UNTRUSTED/QUARANTINE | Propagated trust label |
| `source` | String | Origin: USER_PROMPT / SYSTEM_PROMPT / WEB / EMAIL / TOOL_OUTPUT / AGENT_MSG |
| `propagated_from` | UUID[] | Parent node IDs whose taint was inherited |
| `created_at` | DateTime | Timestamp of node creation |

### 5.3.3 Audit Decision Log

| Field | Type | Description |
|---|---|---|
| `decision_id` | UUID | Unique decision record |
| `session_id` | String | Agent session context |
| `agent_id` | String | Calling agent identifier |
| `agent_role` | String | Role resolved at evaluation time |
| `tool_name` | String | Tool being invoked |
| `tool_args_hash` | String | SHA-256 of sanitised argument payload |
| `taint_flags` | String[] | Taint labels present on arguments |
| `risk_score` | Float | Computed risk score [0–1] |
| `delegation_chain` | String[] | Full principal chain from user to calling agent |
| `matched_rule_id` | UUID | Policy rule that produced the decision |
| `decision` | Enum: ALLOW/DENY/ESCALATE/TIMEOUT | Final enforcement decision |
| `escalation_id` | UUID? | Human escalation ticket ID if applicable |
| `latency_ms` | Integer | Policy evaluation latency |
| `timestamp` | DateTime | UTC decision timestamp |

---

# 6. Feature Specification

## F1 — Intercept API

A synchronous REST + gRPC endpoint called by agent orchestrators before executing any tool. Accepts a structured `ToolCallRequest` and returns a `PolicyDecision` within SLA.

| Attribute | Value |
|---|---|
| **Endpoint** | `POST /v1/intercept` |
| **Protocol** | REST (JSON) and gRPC (protobuf) |
| **Auth** | mTLS + API key; per-tenant isolation |
| **Decision SLA** | < 15ms p99 for cached policy; < 50ms p99 cold |
| **Decision Values** | `ALLOW` · `DENY` · `ESCALATE` · `DRY_RUN` |
| **Timeout Behaviour** | Configurable: `FAIL_OPEN` or `FAIL_CLOSED` |
| **Idempotency** | Request IDs; safe to retry on network error |

**Request schema (JSON):**
```json
{
  "request_id": "uuid",
  "session_id": "string",
  "agent_id": "string",
  "tool_name": "string",
  "tool_args": {},
  "delegation_chain": ["agent_a", "agent_b"],
  "dry_run": false
}
```

**Response schema (JSON):**
```json
{
  "request_id": "uuid",
  "decision": "ALLOW | DENY | ESCALATE | DRY_RUN",
  "matched_rule_id": "uuid | null",
  "risk_score": 0.0,
  "taint_flags": [],
  "reason": "string",
  "escalation_id": "uuid | null",
  "latency_ms": 12
}
```

## F2 — RBAC Policy Engine

A hierarchical role-based access control engine allowing security teams to define what each agent role is permitted to do. Roles inherit from parent roles (e.g., `ReaderAgent < WriterAgent < AdminAgent`). Rules are evaluated in priority order with first-match semantics.

- Role hierarchy with multi-inheritance
- Per-tool and per-tool-pattern rules (glob and regex)
- Argument-level validators: JSON schema, regex, allowlist/blocklist
- Rate limiting per role per tool per time window
- Wildcard deny-by-default with explicit allow grants

## F3 — Taint-Aware Data Flow Tracking

Per-session in-memory directed acyclic graph tracking provenance of every data value that flows through the agent. Taint labels propagate: if a tainted variable is passed as an argument to a privileged tool, the call is blocked or escalated regardless of RBAC rules.

| Taint Level | Source Examples | Default Policy |
|---|---|---|
| `TRUSTED` | User prompt · System prompt · Internal API with cert | ALLOW (subject to RBAC) |
| `UNTRUSTED` | Web content · Email · Calendar · Unverified tool output | BLOCK on privileged tools; ALLOW on read-only tools |
| `QUARANTINE` | Known-malicious pattern detected · Injection signature | DENY always |

**SDK taint labelling:**
```python
import agentpep

async with agentpep.session(session_id="s123") as ctx:
    web_content = await fetch_url("https://example.com")
    ctx.label(web_content, taint=agentpep.UNTRUSTED, source="WEB")

    email_body = await read_email(email_id)
    ctx.label(email_body, taint=agentpep.UNTRUSTED, source="EMAIL")
```

## F4 — Confused-Deputy Detector

When Agent A delegates a task to Agent B, AgentPEP walks the full delegation chain and validates that the originating principal (the user) explicitly granted authority for the specific action being requested. If Agent A has `tool_X` permission but the user's session grants only `tool_Y` to agents, Agent B's execution of `tool_X` is blocked.

- Chain depth limit (configurable; default: 5 hops)
- Per-hop authority validation against session grants
- Implicit delegation detection: Agent B triggered by shared workspace writes from Agent A
- Alert generation on detected escalation attempts

## F5 — Risk-Adaptive Scoring Engine

Each tool invocation receives a risk score `[0.0–1.0]` computed from a weighted model:

| Risk Factor | Default Weight | Examples |
|---|---|---|
| Operation Type | 30% | File delete > File write > File read; Send email > Draft email |
| Data Sensitivity | 25% | PII fields, credentials, financial data > general data |
| Taint Level of Args | 20% | UNTRUSTED or QUARANTINE args elevate score |
| Session Accumulated Risk | 15% | Prior ALLOW decisions in session compound risk |
| Delegation Depth | 10% | Deeper chains = higher score |

Risk scores above a user-defined threshold trigger `ESCALATE` rather than `ALLOW` or `DENY`. Weights are configurable per tenant and per agent role.

## F6 — Human Escalation Manager

When the policy engine returns `ESCALATE`, the Escalation Manager opens an approval ticket routed to a designated approver via WebSocket push (console), email, or Slack webhook. The agent is suspended until approval or timeout.

| Setting | Default | Description |
|---|---|---|
| Approval timeout | 300s | Auto-DENY on timeout (configurable to ALLOW for low-risk) |
| Approver routing | Round-robin from role group | Configurable: specific user, role group, on-call |
| Context payload | Tool name, args, risk score, taint flags, delegation chain | Shown in approval UI |
| Bulk approval | Enabled for same-pattern requests | Approver can approve all similar pending requests |
| Approval memory | 7-day TTL | Repeated identical requests can be pre-approved |

## F7 — Audit Engine

Every authorization decision — `ALLOW`, `DENY`, `ESCALATE`, `TIMEOUT` — is written to an immutable append-only audit log in MongoDB with a Kafka topic mirror for SIEM integration.

- MongoDB TTL-indexed for configurable retention (default: 365 days)
- Kafka topic: `agentpep.decisions` for downstream SIEM/SOAR consumption
- SHA-256 integrity hash chain across sequential decision records
- Compliance export: CSV / JSON / PDF for DPDPA, GDPR, CERT-In audit submissions

## F8 — Policy Simulation (Dry-Run Mode)

Developers and security teams can submit tool call requests against any policy set in `DRY_RUN` mode. The engine evaluates the full policy stack and returns the decision, matched rule, risk score, and taint evaluation — but never blocks execution. Used in CI/CD pipelines to catch policy violations before deployment.

## F9 — Policy Console (React UI)

| Screen | Key Capabilities |
|---|---|
| **Policy Authoring** | Visual rule builder; RBAC role tree; import/export YAML; version history; diff view |
| **Agent Registry** | Register agents with roles, session limits, tool allowlists, risk budgets |
| **Risk Dashboard** | Real-time risk score heatmap; DENY/ESCALATE rate trends; top blocked tools |
| **Audit Explorer** | Full-text search across decision log; timeline view; correlated session replay |
| **Escalation Queue** | Pending approvals with full context; approve/deny/escalate-up; bulk actions |
| **Taint Map** | Per-session data flow graph visualization; highlight taint propagation paths |
| **Compliance Reports** | Pre-built report templates for DPDPA Art. 8, GDPR Art. 25, CERT-In BOM |

## F10 — Python SDK

`agentpep-sdk` package providing:

- `@agentpep.enforce` decorator for FastAPI route handlers and tool functions
- LangChain / LangGraph middleware integration
- Async and sync client for the Intercept API
- Session context manager for taint labeling at ingestion
- Local policy evaluation (offline mode for dev/test)

**Quickstart:**
```python
from agentpep import enforce, AgentPEPClient

client = AgentPEPClient(base_url="https://agentpep.internal", api_key="...")

@enforce(client=client, agent_id="my-agent", role="WriterAgent")
async def send_email(to: str, subject: str, body: str):
    # Only executes if AgentPEP returns ALLOW
    await smtp_client.send(to, subject, body)
```

**LangChain integration:**
```python
from agentpep.integrations.langchain import AgentPEPToolWrapper

tools = [AgentPEPToolWrapper(tool, client=client, agent_id="lc-agent") for tool in raw_tools]
agent = create_react_agent(llm, tools, prompt)
```

---

# 7. Integration Architecture

## 7.1 Agent Framework Integrations

| Framework | Integration Method | Sprint |
|---|---|---|
| LangChain / LangGraph | Tool wrapper middleware + agentpep-sdk | Sprint 4 |
| OpenAI Agents SDK | Pre-execution hook via AgentKit callback | Sprint 20 |
| AutoGen / AutoGen Studio | Custom speaker hook | Sprint 20 |
| CrewAI | Task execution interceptor | Sprint 21 |
| Semantic Kernel | Plugin filter pipeline | Sprint 21 |
| Custom FastAPI agents | SDK decorator (`@agentpep.enforce`) | Sprint 4 |
| MCP-compliant agents | MCP tool call intercept proxy | Sprint 12 |

## 7.2 Platform Integrations

| Platform | Purpose | Direction |
|---|---|---|
| AgentIAM (TrustFabric) | Resolve agent identity and session grants | Inbound — AgentPEP consumes |
| Sphinx AI Mesh Firewall | Optional prompt-level risk signals | Optional inbound feed |
| MATG (Multi-Agent Trust Graph) | Graph context for delegation chains | Optional inbound |
| AFRE (Forensic Replay) | Feed decision log for replay correlation | Outbound |
| AASM (Security Monitoring) | Provide enforcement event stream | Outbound Kafka |
| Splunk / Elastic SIEM | SIEM integration via Kafka consumer | Outbound |
| PagerDuty / OpsGenie | Escalation notification routing | Outbound webhook |
| Slack / Teams | Human approval notifications | Outbound webhook |

---

# 8. Non-Functional Requirements

| Category | Requirement | Target |
|---|---|---|
| **Performance** | Intercept API latency — cached policy | < 15ms p99 |
| **Performance** | Intercept API latency — cold (first eval) | < 50ms p99 |
| **Performance** | Throughput per node | > 5,000 decisions/second |
| **Availability** | Intercept API uptime | 99.9% (8.7 hrs/year downtime budget) |
| **Availability** | Fail mode on engine unavailability | Configurable: `FAIL_OPEN` or `FAIL_CLOSED` |
| **Scalability** | Horizontal scaling | Stateless API nodes; MongoDB sharded; Kafka partitioned |
| **Security** | API authentication | mTLS + API key per tenant; RBAC on console |
| **Security** | Data at rest | AES-256 encryption for audit log and policy store |
| **Security** | Data in transit | TLS 1.3 mandatory |
| **Compliance** | Audit log retention | 365 days default; configurable up to 7 years |
| **Compliance** | GDPR / DPDPA / CERT-In | Decision log exportable; data residency configurable |
| **Observability** | Metrics endpoint | Prometheus `/metrics`; decision rate, latency percentiles, DENY rate |
| **Observability** | Distributed tracing | OpenTelemetry spans per decision |
| **Deployability** | Container | Docker + Kubernetes Helm chart |
| **Deployability** | On-premises support | Air-gapped deployment supported; no cloud call-home |

---

# 9. Security Model

## 9.1 Threat Model

| Threat | Attack Vector | AgentPEP Control |
|---|---|---|
| Indirect prompt injection | Malicious web/email content manipulates agent tool calls | Taint tracking blocks UNTRUSTED data from privileged tools |
| Confused-deputy escalation | Low-priv agent instructs high-priv agent via delegation | Delegation chain authority validation per hop |
| Privilege escalation via agent chain | Agent chain accumulates permissions beyond user grant | Session grant enforcement at each intercept call |
| DoS via tool flooding | Attacker triggers repeated expensive tool calls | Rate limiting per role per tool per window |
| Policy bypass via model jailbreak | Jailbroken LLM generates unexpected tool call schema | Arg schema validators + blocklists applied deterministically |
| Audit log tampering | Attacker modifies decision records post-facto | SHA-256 hash chain; append-only MongoDB collection |
| Insider misconfiguration | Admin creates permissive rules bypassing intent | Policy change audit trail; mandatory peer review workflow in UI |
| Supply chain — SDK compromise | Malicious SDK version skips intercept call | Server-side enforcement only; SDK is convenience layer not trust boundary |

## 9.2 Fail-Safe Design

Two configurable modes:

- **`FAIL_CLOSED` (default for production):** If AgentPEP is unreachable or times out, the tool call is denied. This is the secure default.
- **`FAIL_OPEN` (dev/test only):** If AgentPEP is unreachable, the tool call proceeds. Must be explicitly configured; logs a `WARN`-level audit event.

---

# 10. Success Metrics

| Metric | Target | Measurement Method |
|---|---|---|
| Intercept API p99 latency | < 15ms (cached) | Prometheus histogram |
| DENY rate on known-malicious payloads | > 98% | Red-team adversarial test suite |
| False positive rate on benign agent flows | < 0.5% | Production traffic sampling |
| Confused-deputy detection rate | > 95% on test suite | Delegation chain attack simulator |
| Policy Console task completion (SUS) | > 75 (Good) | UX usability study |
| SDK integration time (new agent) | < 30 minutes | Developer onboarding measurement |
| Audit log completeness | 100% of decisions logged | Reconciliation against intercept counter |
| Time to escalation notification | < 5 seconds | Escalation timestamp delta |
| On-premises deployment time | < 2 hours from Helm install | QA checklist |

---

# 11. Sprint Plan — 36 Sprints · ~18 Months

Each sprint is 2 weeks. Story points use a Fibonacci scale (1–8). Total estimated stories: ~290.

## Sprint Summary

| Sprint | Name | Phase | Stories |
|---|---|---|---|
| 1 | Project Foundation & Repository Setup | Phase 1: Foundation | 10 |
| 2 | Intercept API — Core Decision Engine | Phase 1: Foundation | 9 |
| 3 | RBAC Policy Engine — Core | Phase 1: Foundation | 9 |
| 4 | Python SDK v1 & LangChain Integration | Phase 1: Foundation | 9 |
| 5 | Taint Tracking — Session Graph Engine | Phase 2: Taint & Confused-Deputy | 9 |
| 6 | Taint Tracking — Advanced Propagation & Quarantine | Phase 2: Taint & Confused-Deputy | 7 |
| 7 | Confused-Deputy Detector | Phase 2: Taint & Confused-Deputy | 9 |
| 8 | Risk Scoring Engine | Phase 2: Taint & Confused-Deputy | 9 |
| 9 | Human Escalation Manager | Phase 3: Escalation & Audit | 9 |
| 10 | Audit Engine & Kafka Integration | Phase 3: Escalation & Audit | 9 |
| 11 | Rate Limiting & Argument Validators | Phase 3: Escalation & Audit | 8 |
| 12 | MCP Tool Call Intercept Proxy | Phase 3: Escalation & Audit | 7 |
| 13 | Policy Console — Authentication & Shell | Phase 4: Policy Console UI | 8 |
| 14 | Policy Console — Policy Authoring | Phase 4: Policy Console UI | 8 |
| 15 | Policy Console — Agent Registry | Phase 4: Policy Console UI | 7 |
| 16 | Policy Console — Risk Dashboard | Phase 4: Policy Console UI | 8 |
| 17 | Policy Console — Audit Explorer | Phase 4: Policy Console UI | 7 |
| 18 | Policy Console — Escalation Queue & Taint Map | Phase 4: Policy Console UI | 8 |
| 19 | Policy Simulation Engine | Phase 5: Advanced Features | 7 |
| 20 | OpenAI Agents SDK & AutoGen Integration | Phase 5: Advanced Features | 7 |
| 21 | CrewAI & Semantic Kernel Integration | Phase 5: Advanced Features | 7 |
| 22 | Compliance Reports & SIEM Integration | Phase 5: Advanced Features | 8 |
| 23 | Performance Hardening | Phase 6: Hardening & Operations | 8 |
| 24 | Security Hardening | Phase 6: Hardening & Operations | 8 |
| 25 | Kubernetes Helm Chart & On-Premises Deployment | Phase 6: Hardening & Operations | 8 |
| 26 | Observability & Alerting | Phase 6: Hardening & Operations | 7 |
| 27 | Beta Programme & Developer Experience | Phase 7: Beta & GA | 7 |
| 28 | General Availability Release | Phase 7: Beta & GA | 7 |
| 29 | ToolTrust — Backend ABCs & Async Architecture | Phase 8: ToolTrust Roadmap v1 | 8 |
| 30 | ToolTrust — YAML Policy Loading & Offline Evaluation | Phase 8: ToolTrust Roadmap v1 | 8 |
| 31 | ToolTrust — Auth Providers & Redis Backend | Phase 8: ToolTrust Roadmap v1 | 9 |
| 32 | ToolTrust — Structured Logging & Notification Channels | Phase 8: ToolTrust Roadmap v1 | 8 |
| 33 | ToolTrust — Framework Integrations (OpenAI Agents, LangGraph) | Phase 8: ToolTrust Roadmap v1 | 8 |
| 34 | ToolTrust — Testing Utilities, Simulation & Enhanced CLI | Phase 8: ToolTrust Roadmap v1 | 9 |
| 35 | ToolTrust — Injection Library, Arg Validation & Risk Scoring | Phase 8: ToolTrust Roadmap v1 | 9 |
| 36 | ToolTrust — Conflict Detection, Metrics, Tamper Detection & Multi-Tenancy | Phase 8: ToolTrust Roadmap v1 | 8 |

---

## Phase 1: Foundation

### Sprint 1 — Project Foundation & Repository Setup

**Goal:** Monorepo scaffold, CI/CD, local dev environment, MongoDB schema, and project conventions established.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-001 | Set up monorepo structure (backend/, frontend/, sdk/, infra/) | 3 | Platform |
| APEP-002 | Initialise FastAPI application with health, metrics, and versioned router | 3 | Backend |
| APEP-003 | Configure MongoDB connection with motor (async driver) and index definitions | 3 | Backend |
| APEP-004 | Set up Vite + React + Tailwind + shadcn/ui scaffold for Policy Console | 3 | Frontend |
| APEP-005 | Configure GitHub Actions CI: lint, type-check, test, build for all modules | 3 | DevOps |
| APEP-006 | Set up Docker Compose for local dev (FastAPI + MongoDB + Kafka + Zookeeper) | 3 | DevOps |
| APEP-007 | Define Pydantic models for PolicyRule, TaintNode, AuditDecision, AgentProfile | 5 | Backend |
| APEP-008 | Implement MongoDB collection initialisation with TTL and uniqueness indexes | 3 | Backend |
| APEP-009 | Set up Prometheus /metrics endpoint and OpenTelemetry tracer | 3 | Observability |
| APEP-010 | Create developer docs: ADR template, API conventions, contribution guide | 2 | Platform |

### Sprint 2 — Intercept API — Core Decision Engine

**Goal:** `POST /v1/intercept` endpoint functional; returns ALLOW/DENY/DRY_RUN decisions; policy evaluation stub in place.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-011 | Design and implement ToolCallRequest and PolicyDecision protobuf + JSON schemas | 5 | Backend |
| APEP-012 | Implement POST /v1/intercept REST handler with request validation | 5 | Backend |
| APEP-013 | Implement gRPC Intercept service with proto definitions | 5 | Backend |
| APEP-014 | Build PolicyEvaluator stub: returns ALLOW by default; reads rules from MongoDB | 5 | Backend |
| APEP-015 | Implement API key authentication middleware with per-tenant isolation | 3 | Security |
| APEP-016 | Add mTLS support with certificate validation middleware | 3 | Security |
| APEP-017 | Implement DRY_RUN mode: full evaluation but no enforcement | 3 | Backend |
| APEP-018 | Write integration tests: ALLOW / DENY / DRY_RUN paths end-to-end | 5 | Testing |
| APEP-019 | Implement configurable FAIL_OPEN / FAIL_CLOSED behaviour on timeout | 3 | Backend |

### Sprint 3 — RBAC Policy Engine — Core

**Goal:** Full RBAC evaluation: role hierarchy, rule matching, first-match semantics, priority ordering.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-020 | Implement AgentRole model with multi-inheritance hierarchy in MongoDB | 5 | Backend |
| APEP-021 | Build RoleResolver: walk role hierarchy and compute effective permission set | 5 | Backend |
| APEP-022 | Implement RuleMatcher: glob + regex matching on tool_name against rules | 5 | Backend |
| APEP-023 | Implement priority-ordered first-match evaluation with deny-by-default | 5 | Backend |
| APEP-024 | Build argument-level JSON schema validator integrated into rule evaluation | 3 | Backend |
| APEP-025 | Implement regex allowlist/blocklist validators on tool arguments | 3 | Backend |
| APEP-026 | Add rule caching layer (LRU in-memory) with TTL invalidation | 3 | Performance |
| APEP-027 | Write property-based tests for role resolution and rule matching | 5 | Testing |
| APEP-028 | Implement rule conflict detection and warning logging | 3 | Backend |

### Sprint 4 — Python SDK v1 & LangChain Integration

**Goal:** `agentpep-sdk` PyPI package; `@enforce` decorator; LangChain tool wrapper; local dev mode.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-029 | Scaffold agentpep-sdk Python package with pyproject.toml and GitHub release workflow | 3 | SDK |
| APEP-030 | Implement AgentPEPClient (async + sync) wrapping Intercept API | 5 | SDK |
| APEP-031 | Implement @agentpep.enforce decorator for plain Python tool functions | 5 | SDK |
| APEP-032 | Build FastAPI middleware integration: intercept before route handler execution | 5 | SDK |
| APEP-033 | Build LangChain BaseTool wrapper that calls intercept before tool._run() | 5 | SDK |
| APEP-034 | Implement LangGraph node pre-execution hook | 3 | SDK |
| APEP-035 | Implement local offline policy evaluation mode for dev/test | 5 | SDK |
| APEP-036 | Write SDK unit and integration tests with mocked Intercept API | 3 | Testing |
| APEP-037 | Publish SDK documentation: quickstart, decorator API, LangChain guide | 3 | Docs |

---

## Phase 2: Taint & Confused-Deputy

### Sprint 5 — Taint Tracking — Session Graph Engine

**Goal:** Per-session in-memory DAG tracking provenance and taint propagation for all data entering agent loops.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-038 | Design TaintGraph data structure: directed acyclic graph of TaintNodes per session | 5 | Backend |
| APEP-039 | Implement session lifecycle management: create, update, destroy taint graphs | 5 | Backend |
| APEP-040 | Build taint propagation engine: when tainted node is input to operation, output inherits taint | 8 | Backend |
| APEP-041 | Implement taint source labelling API: SDK method to label ingested external data | 3 | SDK |
| APEP-042 | Implement UNTRUSTED source declarations: web fetch, email read, tool output | 3 | SDK |
| APEP-043 | Integrate taint check into PolicyEvaluator: escalate if UNTRUSTED arg on privileged tool | 5 | Backend |
| APEP-044 | Implement QUARANTINE level: assign on known injection signature detection | 5 | Security |
| APEP-045 | Build session graph persistence to MongoDB for forensic inspection | 3 | Backend |
| APEP-046 | Write simulation tests: indirect prompt injection scenario blocked by taint tracking | 5 | Testing |

### Sprint 6 — Taint Tracking — Advanced Propagation & Quarantine

**Goal:** Multi-hop propagation, sanitisation gates, taint downgrade workflows, and injection signature library.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-047 | Implement multi-hop taint propagation across tool call chains within session | 8 | Backend |
| APEP-048 | Build sanitisation gate API: allow security team to declare sanitisation functions that downgrade taint | 5 | Backend |
| APEP-049 | Implement injection signature library (prompt injection patterns → QUARANTINE) | 5 | Security |
| APEP-050 | Add taint visualisation data endpoint: return graph structure for UI rendering | 3 | Backend |
| APEP-051 | Implement cross-agent taint propagation: taint persists when data crosses agent boundary | 8 | Backend |
| APEP-052 | Build taint audit events: log every taint assignment and propagation to audit log | 3 | Backend |
| APEP-053 | Write adversarial tests: multi-hop injection, cross-agent taint leak, quarantine bypass attempts | 5 | Testing |

### Sprint 7 — Confused-Deputy Detector

**Goal:** Full delegation chain authority validation; implicit delegation detection; chain depth enforcement.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-054 | Design delegation chain data model: DelegationHop with agent_id, granted_tools, authority_source | 5 | Backend |
| APEP-055 | Implement DelegationChainWalker: traverse agent-to-agent call chain from tool call to origin | 8 | Backend |
| APEP-056 | Build authority validator: per-hop check that originating user granted action to chain | 8 | Backend |
| APEP-057 | Implement chain depth limit enforcement (configurable; default 5 hops) | 3 | Backend |
| APEP-058 | Implement implicit delegation detection: shared workspace write triggering downstream agent action | 8 | Backend |
| APEP-059 | Generate SECURITY_ALERT events on detected escalation attempts | 3 | Backend |
| APEP-060 | Integrate confused-deputy detector into PolicyEvaluator pipeline | 5 | Backend |
| APEP-061 | Write attack simulation tests: privilege escalation via agent chain | 5 | Testing |
| APEP-062 | Document delegation model and configuration guide | 3 | Docs |

### Sprint 8 — Risk Scoring Engine

**Goal:** Configurable risk model producing [0–1] scores per tool call; ESCALATE on threshold breach.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-063 | Design risk model schema: factors, weights, per-role overrides stored in MongoDB | 5 | Backend |
| APEP-064 | Implement OperationTypeScorer: classify tool call risk by verb (delete > write > read) | 5 | Backend |
| APEP-065 | Implement DataSensitivityScorer: detect PII, credential, financial patterns in args | 5 | Backend |
| APEP-066 | Implement TaintScorer: elevate risk score based on argument taint levels | 3 | Backend |
| APEP-067 | Implement SessionAccumulatedRiskScorer: cumulative score from session history | 5 | Backend |
| APEP-068 | Implement DelegationDepthScorer: higher risk for deeper chains | 3 | Backend |
| APEP-069 | Build RiskAggregator: weighted sum with configurable weights per tenant/role | 5 | Backend |
| APEP-070 | Integrate risk score into PolicyEvaluator: ESCALATE when score > threshold | 3 | Backend |
| APEP-071 | Write calibration tests: verify score ranges for known-benign and known-malicious payloads | 5 | Testing |

---

## Phase 3: Escalation & Audit

### Sprint 9 — Human Escalation Manager

**Goal:** Full escalation lifecycle: ticket creation, WebSocket push to console, timeout handling, approval memory.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-072 | Design EscalationTicket model and state machine (PENDING → APPROVED/DENIED/TIMEOUT) | 5 | Backend |
| APEP-073 | Implement EscalationManager service: create ticket, block agent, await response | 8 | Backend |
| APEP-074 | Build WebSocket server: push ESCALATE events to connected Policy Console sessions | 5 | Backend |
| APEP-075 | Implement configurable timeout: auto-DENY or auto-ALLOW on expiry per risk level | 3 | Backend |
| APEP-076 | Implement approver routing: round-robin from role group; specific user; on-call | 5 | Backend |
| APEP-077 | Build approval memory: 7-day TTL cache of approved patterns; skip re-escalation | 5 | Backend |
| APEP-078 | Implement email notification webhook on ESCALATE event | 3 | Backend |
| APEP-079 | Implement Slack webhook notification on ESCALATE event | 3 | Backend |
| APEP-080 | Write integration tests: escalation flow end-to-end with WebSocket client | 5 | Testing |

### Sprint 10 — Audit Engine & Kafka Integration

**Goal:** Immutable append-only audit log; Kafka topic mirror; SHA-256 hash chain; compliance export.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-081 | Implement AuditLogger service: append AuditDecision to MongoDB capped collection | 5 | Backend |
| APEP-082 | Implement SHA-256 hash chain across sequential audit records | 5 | Security |
| APEP-083 | Configure Kafka producer: publish every decision to agentpep.decisions topic | 3 | Backend |
| APEP-084 | Implement MongoDB TTL index with configurable retention (default 365d) | 3 | Backend |
| APEP-085 | Build audit query API: filter by agent_id, tool, decision, time range, risk score | 5 | Backend |
| APEP-086 | Implement compliance export: CSV and JSON for DPDPA, GDPR, CERT-In templates | 5 | Backend |
| APEP-087 | Implement PDF audit report generation (reportlab) | 3 | Backend |
| APEP-088 | Write audit integrity verification utility: replay hash chain and detect tampering | 5 | Security |
| APEP-089 | Write load test: 5,000 decisions/sec throughput validation | 5 | Testing |

### Sprint 11 — Rate Limiting & Argument Validators

**Goal:** Per-role per-tool rate limits; schema/regex/blocklist argument validation; DoS protection.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-090 | Implement sliding window rate limiter: per agent_role per tool per time window in MongoDB | 5 | Backend |
| APEP-091 | Implement fixed window rate limiter as alternative; configurable per rule | 3 | Backend |
| APEP-092 | Build global rate limit: per-tenant total decisions/second ceiling | 3 | Backend |
| APEP-093 | Implement JSON schema argument validator: validate tool args against schema in rule | 5 | Backend |
| APEP-094 | Implement regex validator: apply per-arg regex patterns before execution | 3 | Backend |
| APEP-095 | Implement allowlist/blocklist string validator: per-arg value matching | 3 | Backend |
| APEP-096 | Build validator pipeline: all configured validators run in sequence; any FAIL → DENY | 3 | Backend |
| APEP-097 | Write adversarial tests: schema bypass, regex evasion, rate limit exhaustion | 5 | Testing |

### Sprint 12 — MCP Tool Call Intercept Proxy

**Goal:** Transparent MCP proxy that intercepts tool calls from any MCP-compliant agent before forwarding.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-098 | Build MCP proxy server: forward MCP tool call messages to target MCP server post-approval | 8 | Backend |
| APEP-099 | Implement MCP message parsing: extract tool name and arguments from MCP JSON-RPC envelope | 5 | Backend |
| APEP-100 | Integrate MCP proxy with Intercept API: DENY → return MCP error; ALLOW → forward | 5 | Backend |
| APEP-101 | Implement MCP session tracking: maintain taint graph per MCP session | 5 | Backend |
| APEP-102 | Add MCP proxy configuration to AgentProfile in MongoDB | 3 | Backend |
| APEP-103 | Write integration tests with MCP-compliant test server | 5 | Testing |
| APEP-104 | Document MCP proxy setup and configuration | 3 | Docs |

---

## Phase 4: Policy Console UI

### Sprint 13 — Policy Console — Authentication & Shell

**Goal:** Authenticated React shell with tenant context, sidebar navigation, and dark/light theme.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-105 | Implement JWT authentication backend: login, refresh, logout endpoints | 3 | Backend |
| APEP-106 | Build React authentication flow: login page, token storage, auto-refresh | 5 | Frontend |
| APEP-107 | Implement RBAC for console users: Admin, PolicyAuthor, Analyst, Approver roles | 5 | Frontend |
| APEP-108 | Build app shell: sidebar navigation, breadcrumbs, tenant switcher, user menu | 5 | Frontend |
| APEP-109 | Implement dark/light theme toggle with Tailwind dark mode | 2 | Frontend |
| APEP-110 | Build homepage dashboard: KPI cards (decisions/hr, DENY rate, pending escalations) | 5 | Frontend |
| APEP-111 | Implement toast notification system for real-time alerts | 3 | Frontend |
| APEP-112 | Write Playwright E2E tests for authentication flow | 3 | Testing |

### Sprint 14 — Policy Console — Policy Authoring

**Goal:** Full policy CRUD: role tree editor, rule builder, YAML import/export, version history, diff view.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-113 | Build role hierarchy tree editor: visual drag-and-drop role inheritance management | 8 | Frontend |
| APEP-114 | Build rule builder form: tool pattern, action, taint check, risk threshold, validators | 8 | Frontend |
| APEP-115 | Implement rule priority drag-and-drop reordering | 5 | Frontend |
| APEP-116 | Implement YAML import/export for policy sets | 3 | Frontend |
| APEP-117 | Build policy version history: list versions; restore; diff two versions side-by-side | 8 | Frontend |
| APEP-118 | Implement peer review workflow: draft → submitted → approved → active | 5 | Frontend |
| APEP-119 | Build policy conflict detector: highlight rules that may conflict or shadow each other | 5 | Frontend |
| APEP-120 | Write unit tests for rule builder validation logic | 3 | Testing |

### Sprint 15 — Policy Console — Agent Registry

**Goal:** Register and manage agents with roles, session limits, tool allowlists, and risk budgets.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-121 | Build agent registry list view: sortable table with role, status, decision counts | 5 | Frontend |
| APEP-122 | Build agent profile form: name, role assignment, session limits, risk budget, tool allowlist | 5 | Frontend |
| APEP-123 | Implement API key management UI: generate, rotate, revoke per-agent keys | 5 | Frontend |
| APEP-124 | Build agent activity timeline: last 100 decisions for selected agent | 5 | Frontend |
| APEP-125 | Implement agent bulk role assignment for fleet management | 3 | Frontend |
| APEP-126 | Build delegation chain viewer: visualise configured delegation grants per agent | 5 | Frontend |
| APEP-127 | Write E2E tests for agent registration and key rotation flows | 3 | Testing |

### Sprint 16 — Policy Console — Risk Dashboard

**Goal:** Real-time risk heatmap, DENY/ESCALATE trend charts, top blocked tools, risk score distribution.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-128 | Build real-time risk heatmap: agent × tool matrix coloured by average risk score | 8 | Frontend |
| APEP-129 | Build decision trend chart: ALLOW/DENY/ESCALATE rates over time (Recharts) | 5 | Frontend |
| APEP-130 | Build top blocked tools table: ranked by DENY count with drill-down | 3 | Frontend |
| APEP-131 | Build risk score distribution histogram: across all decisions in time window | 3 | Frontend |
| APEP-132 | Implement time window selector: 1h / 6h / 24h / 7d / 30d | 3 | Frontend |
| APEP-133 | Implement WebSocket subscription for real-time dashboard updates | 5 | Frontend |
| APEP-134 | Build anomaly highlight: agents with DENY rate > 2σ from baseline flagged in red | 5 | Frontend |
| APEP-135 | Write unit tests for dashboard data transformation logic | 3 | Testing |

### Sprint 17 — Policy Console — Audit Explorer

**Goal:** Full-text audit search, timeline view, session drill-down, decision detail panel.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-136 | Build audit explorer main view: paginated decision table with column filters | 5 | Frontend |
| APEP-137 | Implement full-text search across audit records (agent, tool, decision, risk range) | 5 | Frontend |
| APEP-138 | Build decision detail side panel: full context including args hash, taint flags, chain | 5 | Frontend |
| APEP-139 | Build session timeline view: all decisions in a session in chronological order | 5 | Frontend |
| APEP-140 | Implement audit export from UI: CSV / JSON / PDF for selected time range | 3 | Frontend |
| APEP-141 | Build hash chain integrity indicator: UI shows VERIFIED / TAMPERED per record range | 3 | Frontend |
| APEP-142 | Write E2E tests for audit search and export flows | 3 | Testing |

### Sprint 18 — Policy Console — Escalation Queue & Taint Map

**Goal:** Real-time escalation approval queue; taint flow graph visualisation per session.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-143 | Build escalation queue view: real-time list of PENDING tickets via WebSocket | 5 | Frontend |
| APEP-144 | Build escalation detail panel: tool, args, risk score, taint flags, delegation chain | 5 | Frontend |
| APEP-145 | Implement approve / deny / escalate-up actions with comment field | 3 | Frontend |
| APEP-146 | Implement bulk approve for same-pattern pending escalations | 3 | Frontend |
| APEP-147 | Build escalation SLA timer: show time remaining before auto-decision | 3 | Frontend |
| APEP-148 | Build taint map graph view: D3.js DAG visualising taint propagation for a session | 8 | Frontend |
| APEP-149 | Implement node click drill-down: show source, propagation path, taint level | 3 | Frontend |
| APEP-150 | Write E2E tests for escalation approval workflow | 3 | Testing |

---

## Phase 5: Advanced Features

### Sprint 19 — Policy Simulation Engine

**Goal:** Full DRY_RUN evaluation API for CI/CD integration; simulation UI in console; test vector library.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-151 | Implement POST /v1/simulate endpoint: evaluate full policy stack without enforcement | 5 | Backend |
| APEP-152 | Return full simulation result: decision, matched rule, risk score, taint eval, chain result | 5 | Backend |
| APEP-153 | Build simulation request builder UI: construct tool call requests and run against any policy version | 8 | Frontend |
| APEP-154 | Implement simulation comparison: run same request against two policy versions; diff results | 5 | Frontend |
| APEP-155 | Build test vector library: curated library of benign and adversarial tool call payloads | 8 | Backend |
| APEP-156 | Implement CI/CD integration: GitHub Action that runs simulation suite against PR policy changes | 5 | DevOps |
| APEP-157 | Write documentation: simulation API, CI/CD guide, test vector format | 3 | Docs |

### Sprint 20 — OpenAI Agents SDK & AutoGen Integration

**Goal:** AgentPEP SDK support for OpenAI Agents SDK hook and AutoGen/AutoGen Studio speaker hook.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-158 | Implement OpenAI Agents SDK pre-execution callback hook in agentpep-sdk | 5 | SDK |
| APEP-159 | Map OpenAI tool call schema to ToolCallRequest model | 3 | SDK |
| APEP-160 | Write integration test: OpenAI agent tool call intercepted and denied by RBAC rule | 5 | Testing |
| APEP-161 | Implement AutoGen speaker hook: intercept before each speaker produces output with tool calls | 5 | SDK |
| APEP-162 | Implement AutoGen Studio plugin wrapper | 5 | SDK |
| APEP-163 | Write integration tests for AutoGen multi-agent confused-deputy scenario | 5 | Testing |
| APEP-164 | Publish integration guides for OpenAI Agents SDK and AutoGen | 3 | Docs |

### Sprint 21 — CrewAI & Semantic Kernel Integration

**Goal:** AgentPEP integration for CrewAI task executor and Semantic Kernel plugin filter pipeline.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-165 | Implement CrewAI task execution interceptor: wrap BaseTool.run() with enforce call | 5 | SDK |
| APEP-166 | Handle CrewAI multi-agent role → AgentPEP role mapping configuration | 3 | SDK |
| APEP-167 | Write CrewAI integration test: multi-agent workflow with confused-deputy detection | 5 | Testing |
| APEP-168 | Implement Semantic Kernel IFunctionFilter integration: call intercept in InvokingAsync | 5 | SDK |
| APEP-169 | Handle Semantic Kernel plugin metadata → tool schema mapping | 3 | SDK |
| APEP-170 | Write Semantic Kernel integration tests | 3 | Testing |
| APEP-171 | Publish integration guides for CrewAI and Semantic Kernel | 3 | Docs |

### Sprint 22 — Compliance Reports & SIEM Integration

**Goal:** Pre-built compliance report templates; Splunk/Elastic SIEM Kafka consumer; CERT-In export.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-172 | Build DPDPA compliance report: data processing decisions, taint events, DENY log | 5 | Backend |
| APEP-173 | Build GDPR Art. 25 (Privacy by Design) compliance report template | 5 | Backend |
| APEP-174 | Build CERT-In BOM-aligned agent activity report | 5 | Backend |
| APEP-175 | Implement Splunk HEC forwarder: forward Kafka decisions to Splunk HTTP Event Collector | 5 | Backend |
| APEP-176 | Implement Elasticsearch index writer: write decisions to configurable ES index | 5 | Backend |
| APEP-177 | Build compliance report scheduler: auto-generate and email weekly/monthly reports | 3 | Backend |
| APEP-178 | Build compliance report UI: list, preview, download generated reports | 5 | Frontend |
| APEP-179 | Write compliance report validation tests against regulatory checklist | 3 | Testing |

---

## Phase 6: Hardening & Operations

### Sprint 23 — Performance Hardening

**Goal:** Achieve < 15ms p99 cached and < 50ms p99 cold intercept latency; 5,000 decisions/sec throughput.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-180 | Profile intercept API hot path; identify and eliminate unnecessary serialisation | 5 | Performance |
| APEP-181 | Implement Redis-backed policy cache for sub-millisecond rule retrieval | 5 | Performance |
| APEP-182 | Implement connection pooling for MongoDB motor client | 3 | Performance |
| APEP-183 | Optimise taint graph: bounded per-session node limit with LRU eviction | 5 | Performance |
| APEP-184 | Implement async audit log write: decouple from intercept API response path | 5 | Performance |
| APEP-185 | Run k6 load test: 5,000 RPS sustained; capture p50/p95/p99 metrics | 5 | Testing |
| APEP-186 | Implement adaptive timeouts: dynamic timeout based on cached vs cold policy path | 3 | Performance |
| APEP-187 | Profile and optimise risk scorer hot path | 3 | Performance |

### Sprint 24 — Security Hardening

**Goal:** Red-team adversarial testing; injection signature updates; supply chain hardening; pen-test remediation.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-188 | Run internal red-team: 20 adversarial tool call scenarios against deployed engine | 8 | Security |
| APEP-189 | Update injection signature library based on red-team findings | 5 | Security |
| APEP-190 | Implement SDK tamper detection: log warning if intercept call is skipped (no-op SDK use) | 5 | Security |
| APEP-191 | Implement audit log integrity auto-verification job: daily hash chain validation | 5 | Security |
| APEP-192 | Harden MongoDB: enable auth, encrypt at rest, restrict network access in Helm chart | 3 | Security |
| APEP-193 | Implement OWASP Top 10 mitigations on Policy Console (XSS, CSRF, injection) | 5 | Security |
| APEP-194 | Third-party dependency audit: run pip-audit and npm audit; remediate criticals | 3 | Security |
| APEP-195 | Implement rate limiting on Policy Console API endpoints | 3 | Security |

### Sprint 25 — Kubernetes Helm Chart & On-Premises Deployment

**Goal:** Production-ready Helm chart; air-gapped deployment support; < 2 hour installation SLA.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-196 | Create Helm chart: agentpep-api, agentpep-console, MongoDB, Kafka subcharts | 8 | DevOps |
| APEP-197 | Implement horizontal pod autoscaler for agentpep-api based on RPS | 3 | DevOps |
| APEP-198 | Implement air-gapped deployment: bundle all images; no external call-home | 5 | DevOps |
| APEP-199 | Build installation validation script: checks all services healthy post-install | 3 | DevOps |
| APEP-200 | Write operations runbook: upgrade, backup, restore, scaling, disaster recovery | 5 | Docs |
| APEP-201 | Implement backup job: scheduled MongoDB dump to configurable S3-compatible store | 3 | DevOps |
| APEP-202 | Write Helm chart unit tests with helm unittest | 3 | Testing |
| APEP-203 | Conduct end-to-end on-premises deployment test: measure install time against 2hr SLA | 5 | Testing |

### Sprint 26 — Observability & Alerting

**Goal:** Full Prometheus metrics, Grafana dashboards, alerting rules, and distributed tracing.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-204 | Publish Prometheus metrics: decision_total (by decision/agent/tool), latency histograms, taint_event_total | 5 | Observability |
| APEP-205 | Build Grafana dashboard: decision rates, latency percentiles, DENY heatmap, escalation SLA | 5 | Observability |
| APEP-206 | Configure alerting rules: DENY rate spike > 5x baseline; p99 latency > 100ms; escalation backlog > 10 | 3 | Observability |
| APEP-207 | Implement OpenTelemetry distributed tracing: trace from SDK call to audit log write | 5 | Observability |
| APEP-208 | Integrate traces with Jaeger/Tempo in Helm chart | 3 | Observability |
| APEP-209 | Build structured logging: JSON logs with decision_id correlation for log aggregation | 3 | Observability |
| APEP-210 | Write runbook for each alert: symptoms, diagnosis steps, remediation | 3 | Docs |

---

## Phase 7: Beta & GA

### Sprint 27 — Beta Programme & Developer Experience

**Goal:** Onboard 3–5 beta customers; resolve integration friction; finalise developer documentation.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-211 | Deploy beta environment on cloud (GCP or AWS); configure beta tenant isolation | 3 | DevOps |
| APEP-212 | Onboard beta customer 1: integration support, policy authoring workshop | 8 | Customer |
| APEP-213 | Onboard beta customers 2 and 3: repeat and document friction points | 8 | Customer |
| APEP-214 | Conduct UX study for Policy Console: measure SUS score; target > 75 | 5 | UX |
| APEP-215 | Resolve top 10 beta friction issues from onboarding feedback | 8 | Backend |
| APEP-216 | Publish comprehensive documentation site: quickstart, API reference, integration guides | 5 | Docs |
| APEP-217 | Record SDK quickstart video tutorial (< 10 min integration demo) | 3 | Docs |

### Sprint 28 — General Availability Release

**Goal:** GA release: changelog, SLA commitment, licensing, marketplace listings, press release.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-218 | Complete GA readiness checklist: security, performance, compliance, documentation | 5 | Platform |
| APEP-219 | Publish changelog and GA release notes | 3 | Platform |
| APEP-220 | Configure production SRE runbook and on-call rotation | 3 | DevOps |
| APEP-221 | Finalise licensing model: per-agent decision volume tiers | 3 | Business |
| APEP-222 | Submit to AWS Marketplace and GCP Marketplace | 5 | Business |
| APEP-223 | Coordinate press release and product launch blog post | 3 | Marketing |
| APEP-224 | Conduct GA go/no-go review: all P0 issues resolved; SLA targets met | 3 | Platform |

---

# 12. ToolTrust Enhancement Roadmap v1

## 12.1 Overview

This section documents enhancements to AgentPEP inspired by analysis of [ToolTrust](https://github.com/webpro255/ToolTrust) — an open-source authorization security framework for AI agent systems. ToolTrust implements an infrastructure-level authorization layer between agents and their tools, using a three-layer enforcement architecture (Conversation → Authorization Gate → Tool Execution). While AgentPEP already provides a robust deterministic authorization engine, ToolTrust introduces several architectural patterns and security mechanisms that would meaningfully strengthen AgentPEP's capabilities.

**Analysis Date:** April 2026
**Scope:** 8 sprints (Sprints 29–36) · 67 stories · ~16 weeks

## 12.2 Gap Analysis: ToolTrust vs AgentPEP

The following table summarises capabilities present in ToolTrust that are absent or under-developed in AgentPEP, along with their assessed enhancement priority.

| # | ToolTrust Capability | AgentPEP Current State | Gap | Priority |
|---|---|---|---|---|
| 1 | **Pluggable backend ABCs** — Abstract base classes for storage, auth, and audit backends with plugin architecture | Hardcoded MongoDB + Kafka; no plugin abstraction | Major | P0 |
| 2 | **YAML-first policy loading** — Declarative policy-as-code with GitOps workflow support | YAML import/export in UI only; no native YAML-first pipeline | Major | P0 |
| 3 | **Offline SDK evaluation** — Full policy stack evaluation locally without server round-trip | SDK has limited offline mode; DRY_RUN is server-side only | Moderate | P1 |
| 4 | **Pluggable auth providers** — OAuth2, OIDC, SAML, and custom authentication backends | mTLS + API key only | Major | P0 |
| 5 | **Redis-backed session store** — Redis as first-class session, taint, and rate-limit backend | Redis used for caching only; not a persistence backend | Moderate | P1 |
| 6 | **Single-use execution tokens** — Tokens passed directly to execution layer; never exposed to agents | No per-execution token mechanism | Major | P0 |
| 7 | **Trust degradation** — Session trust ceiling that degrades irreversibly when untrusted content enters context | No trust ceiling or degradation tracking | Major | P0 |
| 8 | **Context authority tracking** — Classifies source trustworthiness (authoritative, derived, untrusted) | Taint tracking labels sources but no authority hierarchy | Moderate | P1 |
| 9 | **Hash-chained context** — Tamper-evident context entries with per-entry hash chains | Audit log has hash chain; context does not | Moderate | P1 |
| 10 | **Adaptive prompt hardening** — Dynamically generates targeted defensive instructions on suspicious activity | No equivalent mechanism | Major | P0 |
| 11 | **Step-up authentication** — Dynamic human approval triggered by suspicious activity patterns | ESCALATE exists but is static (rule-based); no dynamic pattern detection | Moderate | P1 |
| 12 | **DEFER decision type** — Suspends authorisation pending human review with configurable timeout-to-deny | Only ALLOW/DENY/ESCALATE/DRY_RUN; no DEFER semantics | Moderate | P1 |
| 13 | **MODIFY decision type** — Adjusts tool call arguments before allowing execution | No argument modification; only allow/deny binary | Moderate | P1 |
| 14 | **Memory access control** — Governs what agents can persist to and read from memory stores | No agent memory governance | Major | P0 |
| 15 | **PII redaction engine** — Automatic PII detection and redaction on tool outputs | PII detection in risk scoring only; no output redaction | Major | P0 |
| 16 | **Data classification hierarchy** — Sensitivity levels from public to PHI/financial with boundary enforcement | Basic PII detection; no formal classification taxonomy | Moderate | P1 |
| 17 | **Tool combination detection** — Detects suspicious tool sequences (16+ suspicious pairs, 5+ problematic sequences) | No tool-sequence analysis | Major | P0 |
| 18 | **Velocity anomaly detection** — Identifies unusual call frequency patterns beyond simple rate limits | Sliding-window rate limits only; no anomaly-based detection | Moderate | P1 |
| 19 | **Echo detection** — Identifies repeated patterns in prompts suggesting manipulation | No prompt pattern analysis | Moderate | P1 |
| 20 | **Signed receipts** — Cryptographically verifiable authorisation records (Ed25519 / HMAC-SHA256) | SHA-256 hash chain on audit log; no individual signed receipts | Major | P0 |
| 21 | **Offline receipt verification** — Verify authorisation decisions without server access | No offline verification capability | Moderate | P1 |
| 22 | **Pluggable audit backends** — CloudWatch, Datadog, Loki, and custom SIEM targets | MongoDB + Kafka only | Moderate | P1 |
| 23 | **Structured logging** — JSON-structured logs with configurable verbosity (minimal/standard/full) | Basic structured logging; no configurable verbosity levels | Minor | P2 |
| 24 | **11-stage policy engine** — Comprehensive sequential evaluation with independent filter chains | Multi-stage engine exists but lacks injection/PII filter stages as independent chains | Minor | P2 |

## 12.3 Enhancement Architecture

The enhancements are organised into a plugin-based extensibility layer that preserves AgentPEP's existing architecture while introducing new capabilities:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Enhanced PolicyEvaluator                      │
│                                                                 │
│  Existing Stages              New Stages (ToolTrust-inspired)   │
│  ┌──────────────┐             ┌──────────────────────┐          │
│  │ RBAC Engine  │             │ Trust Degradation     │          │
│  │ Taint Track  │             │ Context Authority     │          │
│  │ Deputy Detect│             │ Tool Combo Detection  │          │
│  │ Risk Scoring │             │ Velocity Anomaly      │          │
│  │ Rate Limiting│             │ Echo Detection        │          │
│  │ Arg Validate │             │ PII Redaction         │          │
│  └──────────────┘             │ Adaptive Hardening    │          │
│                               │ Step-Up Auth          │          │
│                               │ DEFER / MODIFY        │          │
│                               └──────────────────────┘          │
│                                                                 │
│  ┌─────────────────────────────────────────────────────┐        │
│  │          Plugin Backend Layer (New ABCs)             │        │
│  │  StorageBackend · AuthProvider · AuditBackend ·     │        │
│  │  NotificationChannel · ReceiptSigner                │        │
│  └─────────────────────────────────────────────────────┘        │
│                                                                 │
│  ┌────────────────────────┐  ┌────────────────────────┐         │
│  │  Execution Token Mgr   │  │  Memory Access Gate    │         │
│  └────────────────────────┘  └────────────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

## 12.4 New Decision Types

ToolTrust introduces two decision types beyond AgentPEP's current `ALLOW / DENY / ESCALATE / DRY_RUN`:

| Decision | Semantics | Use Case |
|---|---|---|
| **DEFER** | Suspend authorisation; timeout defaults to DENY after configurable period (default 60s) | Uncertain decisions requiring async human review; lower urgency than ESCALATE |
| **MODIFY** | Allow execution but with modified arguments (e.g., redacted PII, sanitised inputs) | Output filtering, PII redaction, argument sanitisation before execution |

The Intercept API response schema will be extended:

```json
{
  "decision": "ALLOW | DENY | ESCALATE | DEFER | MODIFY | DRY_RUN",
  "modified_args": {},
  "deferral_id": "uuid | null",
  "deferral_timeout_s": 60,
  "execution_token": "single-use-token | null",
  "receipt": { "signature": "base64", "algorithm": "ed25519" }
}
```

## 12.5 Detailed Sprint Plans — Phase 8: ToolTrust Roadmap v1

### Sprint 29 — ToolTrust: Backend ABCs & Async Architecture

**Goal:** Introduce abstract base classes for storage, authentication, and audit backends; refactor existing MongoDB/Kafka backends as reference implementations of the new plugin interface; add execution token infrastructure.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-225 | Design and implement `StorageBackend` ABC with async methods: get, put, delete, query, health_check | 5 | Backend |
| APEP-226 | Refactor MongoDB policy store to implement `StorageBackend` ABC as `MongoDBStorageBackend` | 5 | Backend |
| APEP-227 | Design and implement `AuthProvider` ABC with methods: authenticate, validate_token, get_roles | 5 | Backend |
| APEP-228 | Refactor existing mTLS + API key auth to implement `AuthProvider` as `MTLSAuthProvider` and `APIKeyAuthProvider` | 5 | Backend |
| APEP-229 | Design and implement `AuditBackend` ABC with methods: write_decision, query, verify_integrity | 3 | Backend |
| APEP-230 | Refactor MongoDB audit logger and Kafka producer to implement `AuditBackend` ABC | 5 | Backend |
| APEP-231 | Implement `ExecutionTokenManager`: generate single-use cryptographic tokens per ALLOW decision; validate and invalidate on use | 8 | Security |
| APEP-232 | Integrate execution tokens into Intercept API response; SDK validates token before tool execution | 5 | SDK |

### Sprint 30 — ToolTrust: YAML Policy Loading & Offline Evaluation

**Goal:** Native YAML-first policy definition format with JSON Schema validation; GitOps workflow support; enhanced offline SDK evaluation with full policy stack.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-233 | Design YAML policy schema: roles, rules, risk thresholds, taint policies, data classifications in declarative format | 5 | Backend |
| APEP-234 | Implement YAML policy loader: parse, validate (JSON Schema), and hydrate policy objects from YAML files | 5 | Backend |
| APEP-235 | Implement policy-as-code directory convention: `policies/roles.yaml`, `policies/rules.yaml`, `policies/risk.yaml` | 3 | Backend |
| APEP-236 | Build GitOps sync endpoint: `POST /v1/policies/sync` — accepts YAML payload, validates, and applies atomically | 5 | Backend |
| APEP-237 | Implement policy diff engine: compare two YAML policy sets and return structured diff (added/removed/changed rules) | 5 | Backend |
| APEP-238 | Enhance SDK offline evaluation: bundle full policy stack (RBAC + taint + risk + injection) for local eval without server | 8 | SDK |
| APEP-239 | Implement GitHub Action for policy-as-code: validate YAML, run simulation suite, diff against current on PR | 5 | DevOps |
| APEP-240 | Write integration tests: YAML load → evaluate → diff → sync lifecycle | 3 | Testing |

### Sprint 31 — ToolTrust: Auth Providers & Redis Backend

**Goal:** Pluggable authentication with OAuth2/OIDC and SAML providers; Redis as first-class session, taint, and rate-limit backend; data classification hierarchy with boundary enforcement.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-241 | Implement `OAuth2OIDCAuthProvider`: JWT validation, JWKS discovery, role mapping from claims | 8 | Security |
| APEP-242 | Implement `SAMLAuthProvider`: SAML assertion parsing, role extraction, SSO redirect flow | 5 | Security |
| APEP-243 | Build auth provider registry: configurable per-tenant provider selection with fallback chain | 3 | Backend |
| APEP-244 | Implement `RedisStorageBackend`: Redis-backed policy cache, session store, and taint graph persistence | 8 | Backend |
| APEP-245 | Implement Redis-backed sliding window rate limiter replacing MongoDB-based implementation | 5 | Performance |
| APEP-246 | Design data classification hierarchy: PUBLIC → INTERNAL → CONFIDENTIAL → PII → PHI → FINANCIAL with configurable levels | 5 | Backend |
| APEP-247 | Implement data boundary enforcement: restrict tool call data access scope (user-only → team → organisation) based on classification | 5 | Backend |
| APEP-248 | Implement clearance-level checking: agent roles mapped to max data classification they can access | 3 | Backend |
| APEP-249 | Write integration tests: OAuth2 login flow, Redis failover, data classification enforcement | 5 | Testing |

### Sprint 32 — ToolTrust: Structured Logging & Notification Channels

**Goal:** Pluggable audit backends (CloudWatch, Datadog, Loki); configurable log verbosity; notification channel abstraction; cryptographically signed receipts with offline verification.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-250 | Implement `CloudWatchAuditBackend`: write decision records to AWS CloudWatch Logs | 5 | Backend |
| APEP-251 | Implement `DatadogAuditBackend`: write decision records to Datadog Log Management API | 5 | Backend |
| APEP-252 | Implement `LokiAuditBackend`: write decision records to Grafana Loki push API | 3 | Backend |
| APEP-253 | Implement configurable audit verbosity: MINIMAL (outcome only) → STANDARD (identity + scope) → FULL (all fields including args hash) | 3 | Backend |
| APEP-254 | Design and implement `NotificationChannel` ABC with methods: send_alert, send_approval_request, send_resolution | 3 | Backend |
| APEP-255 | Implement `PagerDutyChannel` and `MicrosoftTeamsChannel` notification backends | 5 | Backend |
| APEP-256 | Implement `ReceiptSigner`: Ed25519 (PyNaCl) and HMAC-SHA256 (fallback) signed receipts per authorisation decision | 8 | Security |
| APEP-257 | Implement `ReceiptVerifier`: offline verification of signed receipts without server access; CLI tool for batch verification | 5 | Security |
| APEP-258 | Write integration tests: multi-backend audit routing, receipt sign/verify round-trip, notification delivery | 3 | Testing |

### Sprint 33 — ToolTrust: Framework Integrations (OpenAI Agents, LangGraph)

**Goal:** Deep integration with OpenAI Agents SDK function hooks and LangGraph guardrail nodes; memory access control middleware; context authority tracking for enriched taint decisions.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-259 | Enhance OpenAI Agents SDK integration: execution token validation, receipt attachment, DEFER/MODIFY handling | 5 | SDK |
| APEP-260 | Enhance LangGraph guardrail node: inject trust degradation context, support MODIFY decision with arg rewriting | 5 | SDK |
| APEP-261 | Implement `MemoryAccessGate`: govern agent persist/read operations on memory stores (vector DBs, key-value stores) | 8 | Backend |
| APEP-262 | Implement memory write authorisation: validate allowed writers, prohibited content patterns, entry count limits per session | 5 | Backend |
| APEP-263 | Implement memory read authorisation: lazy retention enforcement with `max_age` purging at read time | 3 | Backend |
| APEP-264 | Implement `ContextAuthorityTracker`: classify each context entry as AUTHORITATIVE / DERIVED / UNTRUSTED based on source | 5 | Backend |
| APEP-265 | Integrate context authority into policy evaluation: downweight derived sources in risk scoring; block untrusted sources from privileged decisions | 5 | Backend |
| APEP-266 | Write integration tests: memory gate CRUD authorisation, context authority scoring, framework-specific DEFER/MODIFY handling | 3 | Testing |

### Sprint 34 — ToolTrust: Testing Utilities, Simulation & Enhanced CLI

**Goal:** CLI-driven policy testing and simulation harness; red-team test generation; trust degradation simulation; policy migration utilities.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-267 | Build `agentpep-cli` command-line tool: `agentpep policy validate`, `agentpep policy diff`, `agentpep simulate` | 8 | SDK |
| APEP-268 | Implement `agentpep redteam generate`: auto-generate adversarial tool call payloads from policy definitions | 8 | Backend |
| APEP-269 | Implement `agentpep redteam run`: execute adversarial suite against live or offline policy stack; produce pass/fail report | 5 | Backend |
| APEP-270 | Implement trust degradation simulation: model session trust ceiling decay across configurable interaction sequences | 5 | Backend |
| APEP-271 | Build policy migration utility: `agentpep policy migrate` — upgrade policy YAML between schema versions with backward compatibility | 3 | SDK |
| APEP-272 | Implement simulation result comparison: diff two simulation runs (before/after policy change) with visual output | 3 | SDK |
| APEP-273 | Implement `agentpep receipt verify` CLI command: batch-verify signed receipts from audit export files | 3 | SDK |
| APEP-274 | Implement `agentpep health` CLI: check server connectivity, policy sync status, backend health for all registered backends | 3 | SDK |
| APEP-275 | Write CLI integration tests: end-to-end validate → simulate → redteam → verify workflow | 3 | Testing |

### Sprint 35 — ToolTrust: Injection Library, Arg Validation & Risk Scoring

**Goal:** Tool combination detection engine; velocity anomaly detection; echo detection; adaptive prompt hardening; PII redaction engine with MODIFY decision support.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-276 | Implement `ToolCombinationDetector`: maintain configurable library of suspicious tool pairs (16+) and problematic sequences (5+) | 8 | Security |
| APEP-277 | Integrate tool combination signals into risk scoring: detect multi-tool attack patterns across session history | 5 | Backend |
| APEP-278 | Implement `VelocityAnomalyDetector`: statistical anomaly detection on per-agent call frequency using sliding-window z-score | 5 | Security |
| APEP-279 | Implement `EchoDetector`: identify repeated or near-duplicate patterns in tool call arguments suggesting prompt manipulation | 5 | Security |
| APEP-280 | Implement `AdaptiveHardeningEngine`: accumulate risk signals per session and generate targeted defensive instructions for agent system prompts | 8 | Security |
| APEP-281 | Implement `PIIRedactionEngine`: detect and redact PII (names, emails, SSNs, phone numbers, addresses) in tool call outputs | 5 | Backend |
| APEP-282 | Integrate PII redaction with MODIFY decision: return redacted arguments when PII detected in outputs to agents with insufficient clearance | 5 | Backend |
| APEP-283 | Enhance injection signature library: add social engineering patterns, encoding attack patterns, and reconnaissance signatures from ToolTrust findings | 3 | Security |
| APEP-284 | Write adversarial tests: tool combo evasion, velocity gaming, echo bypass, hardening effectiveness validation | 5 | Testing |

### Sprint 36 — ToolTrust: Conflict Detection, Metrics, Tamper Detection & Multi-Tenancy

**Goal:** Hash-chained context tamper detection; DEFER and STEP_UP decision types; policy conflict resolution engine; enhanced multi-tenancy isolation; comprehensive enhancement metrics.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-285 | Implement `HashChainedContext`: per-session tamper-evident context entries with SHA-256 hash linking; detect unauthorised historical modifications | 8 | Security |
| APEP-286 | Implement `TrustDegradationEngine`: per-session trust ceiling that degrades irreversibly when untrusted or derived content contaminates context | 5 | Backend |
| APEP-287 | Implement DEFER decision type: suspend authorisation, create deferral ticket, enforce configurable timeout-to-deny (default 60s) | 5 | Backend |
| APEP-288 | Implement STEP_UP decision type: dynamic human approval triggered by pattern detection (hardening escalation, PII accumulation, post-denial retry) | 5 | Backend |
| APEP-289 | Enhance policy conflict detection: identify not just shadowed rules but circular dependencies, permission gaps, and over-broad grants | 5 | Backend |
| APEP-290 | Implement multi-tenancy data isolation: per-tenant encryption keys, tenant-scoped backend instances, cross-tenant access prevention | 5 | Security |
| APEP-291 | Publish Prometheus metrics for all new capabilities: trust_degradation_events, tool_combo_alerts, pii_redactions, defer_count, stepup_count, receipt_verifications | 3 | Observability |

---

## 12.6 Enhancement Summary

| Dimension | Before (v1.0 GA) | After (v1.1 with ToolTrust Enhancements) |
|---|---|---|
| **Decision types** | ALLOW / DENY / ESCALATE / DRY_RUN | + DEFER / MODIFY / STEP_UP |
| **Backend extensibility** | Hardcoded MongoDB + Kafka | Plugin ABCs: StorageBackend, AuthProvider, AuditBackend, NotificationChannel |
| **Authentication** | mTLS + API key | + OAuth2/OIDC, SAML, pluggable providers |
| **Policy management** | UI-based YAML import/export | YAML-first policy-as-code with GitOps sync, CLI tools, schema validation |
| **Threat detection** | Injection signatures, rate limiting | + Tool combination detection, velocity anomaly, echo detection, adaptive hardening |
| **Data protection** | PII detection in risk scoring | + PII redaction engine, data classification hierarchy, clearance-level enforcement |
| **Trust model** | Binary taint (TRUSTED/UNTRUSTED/QUARANTINE) | + Trust degradation, context authority tracking, hash-chained context |
| **Execution security** | No per-execution tokens | Single-use execution tokens, signed receipts, offline verification |
| **Agent memory** | No memory governance | Memory access control gate: write/read authorisation with retention enforcement |
| **Audit backends** | MongoDB + Kafka | + CloudWatch, Datadog, Loki, configurable verbosity |
| **Developer experience** | SDK + DRY_RUN API | + CLI tool (validate, diff, simulate, redteam, verify), offline evaluation |
| **Total stories** | ~224 (Sprints 1–28) | ~291 (+ 67 ToolTrust enhancement stories) |

## 12.7 Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| Backend ABC refactoring introduces regressions in MongoDB path | High | Medium | Feature-flag new plugin layer; existing MongoDB code remains default until stabilised |
| Redis backend latency differs from MongoDB under load | Medium | Low | Benchmark in Sprint 31 load tests; maintain MongoDB as fallback |
| DEFER/MODIFY decisions increase API surface complexity | Medium | Medium | Implement behind feature flags; opt-in per tenant |
| Signed receipts add latency to intercept API hot path | Medium | Medium | Ed25519 signing is ~100μs; benchmark in Sprint 32; async receipt signing option |
| Tool combination detection false positives on benign workflows | High | Medium | Curate initial library conservatively; configurable sensitivity per tenant; simulation mode |
| Trust degradation irreversibility frustrates legitimate users | Medium | Medium | Provide trust-reset API for security admins; log all degradation events for review |

## 12.8 Success Metrics — Phase 8

| Metric | Target | Measurement Method |
|---|---|---|
| Plugin backend switch time | < 1 hour to swap storage/auth/audit backend | Developer integration test |
| YAML policy-as-code adoption | > 60% of policies managed via YAML within 3 months of release | Policy API analytics |
| Tool combination detection rate | > 90% detection of known suspicious sequences | Red-team adversarial suite |
| PII redaction accuracy | > 95% recall, < 2% false positive rate | PII test corpus evaluation |
| Signed receipt verification | 100% of ALLOW decisions have verifiable receipts | Audit reconciliation job |
| CLI adoption | > 50% of developers using CLI for policy validation in CI/CD | SDK telemetry |
| Intercept API p99 latency (with enhancements) | < 20ms cached (≤ 5ms regression budget from new stages) | Prometheus histogram |
| Trust degradation accuracy | > 95% correct degradation on untrusted content injection | Adversarial simulation suite |

---

*AgentPEP · TrustFabric Portfolio · Confidential · © 2026*

---

# 13. ToolTrust Enhancement Roadmap v2

## 13.1 Overview

This section documents enhancements to AgentPEP inspired by analysis of [ToolTrust-python](https://github.com/aniketh-maddipati/ToolTrust-python) — a lightweight, human-in-the-loop cryptographic authorization library for AI agents. ToolTrust implements a three-primitive model: **Plans** (human-approved scoped authorization roots), **Delegation** (pattern-matched authorization before every action), and **Receipts** (Ed25519-signed, parent-chained proof records). While AgentPEP provides a far more comprehensive enforcement engine, ToolTrust introduces several architectural patterns around *human-intent anchoring* and *verifiable authorization provenance* that would meaningfully strengthen AgentPEP's trust model.

**Analysis Date:** April 2026
**Repository Analyzed:** https://github.com/aniketh-maddipati/ToolTrust-python
**Scope:** 7 sprints (Sprints 37–43) · 56 stories · ~14 weeks

---

## 13.2 ToolTrust Codebase Analysis

### 13.2.1 Architecture

ToolTrust is structured around three core primitives exposed via a single `ToolTrust` class:

```
ToolTrust
├── issue_plan(action, user, scope, delegates_to, requires_checkpoint)
│       → Plan (signed root authorization artifact)
│
├── delegate(plan, agent_id, action)
│       → DelegationResult(ok, reason, receipt)
│           receipt.parent_id → plan.id (or prior receipt)
│           receipt.signature → Ed25519 signed
│
└── audit(plan)
        → Iterator[Receipt]  (full chain from plan root)
```

**Plan fields:**
- `action` — top-level intent label (human-readable description)
- `user` / `sub` — identity of the human authorizing the plan
- `scope` — list of allowed action glob patterns (e.g. `read:public:*`, `write:summary:*`)
- `delegates_to` — list of agent IDs permitted to receive delegation under this plan
- `requires_checkpoint` — list of patterns that trigger blocking for human approval (e.g. `read:secret:*`, `delete:*`)

**Scope notation:** `verb:namespace:resource` triple with glob support:
- `read:public:*` → allow any read on public namespace
- `write:summary:*` → allow any write to summary resources
- `read:secret:*` → checkpoint (blocked unless approved)
- `delete:*` → checkpoint (blocked always)

**Receipt chain structure:**
```
plan (root)
├── id:         4388f437-...
├── sub:        manager@company.com
├── signature:  f1958df5... (Ed25519 over plan fields)
│
└── delegation receipt
    ├── id:         15ac1666-...
    ├── parent_id:  4388f437-...  ← links to plan
    ├── sub:        claude-sonnet-4-20250514
    ├── action:     read:public:report.txt
    └── signature:  e2aa114c... (Ed25519 over delegation fields)
```

**MCP server:** ToolTrust ships an MCP server (`mcp_server/server.py`) that intercepts MCP tool calls and runs them through the ToolTrust delegation check, returning structured approval/denial responses to MCP clients.

### 13.2.2 Gap Analysis: ToolTrust Patterns vs AgentPEP

| # | ToolTrust Pattern | AgentPEP Current State | Gap | Priority |
|---|---|---|---|---|
| 1 | **Mission Plan** — Human-issued root authorization artifact binding scope, delegates, checkpoints, and budget to a single signed document | No equivalent; sessions are implicit and policy-driven; no human-issued authorization root | **Major** | P0 |
| 2 | **Scope Pattern Language** — `verb:namespace:resource` triple notation with glob support; ergonomic shorthand readable by humans and auditors | RBAC uses glob patterns on tool_name only; no semantic verb/namespace/resource decomposition | **Major** | P0 |
| 3 | **Checkpoint-Declared Escalation** — Plans explicitly declare which action patterns require human approval as part of plan issuance, not as a post-hoc risk threshold | Escalation is triggered by risk score threshold or static RBAC rules; no plan-level checkpoint declaration | **Major** | P0 |
| 4 | **Declarative Delegates-To** — Plans proactively whitelist which agent IDs may receive delegation; any other agent is blocked outright | Confused-deputy detection is reactive; no proactive per-plan agent whitelist | **Major** | P0 |
| 5 | **Receipt Parent-Chaining** — Every delegation receipt carries a `parent_id` linking it to the root plan or prior receipt, creating an independently traversable authorization tree | Hash chain exists across audit log records (sequential); no per-receipt `parent_id` linking to root plan | **Moderate** | P1 |
| 6 | **Plan Budget & TTL** — Plans expire by time (TTL), usage count (max delegations), or accumulated risk total; exhausted plans DENY further delegation | No per-session or per-plan budget concept; policies are stateless | **Moderate** | P1 |
| 7 | **Plan-Scoped Audit Tree** — `mint.audit(plan)` returns all receipts hierarchically under a plan, enabling plan-centric forensic analysis | Audit log is flat; no plan-centric hierarchical view; receipts not organized by authorization root | **Moderate** | P1 |
| 8 | **Independent Receipt Verification** — Any receipt chain verifiable offline with just the issuer's public key; no server dependency for compliance audits | Receipt verification requires AgentPEP server access for hash chain validation | **Moderate** | P1 |
| 9 | **Plan Console UI** — First-class plan management screen: issue, view, revoke, and inspect plans with receipt trees | Policy Console has no plan concept; authorization roots are not visible to security teams | **Moderate** | P1 |
| 10 | **Scope Pattern Library** — Pre-built scope patterns for common enterprise scenarios (file, email, database, Slack, calendar, code execution) | No curated scope pattern library; security teams author rules from scratch | **Minor** | P2 |
| 11 | **Plan-Level SDK API** — `client.issue_plan()`, `client.delegate()` calls wrap the Intercept API with plan-aware session management | SDK has `@enforce` decorator and session taint labeling, but no plan-aware session initialization | **Minor** | P2 |
| 12 | **Human Intent Anchor** — Plan's `action` field captures human-readable intent ("analyze Q3 reports"), making audit records interpretable without technical knowledge | Audit records are technical (tool names, args hashes); no human-readable intent field | **Minor** | P2 |

---

## 13.3 Enhancement Architecture

The enhancements add a **Mission Plan layer** above AgentPEP's existing session/policy model. Plans are human-issued authorization roots that bind scope, delegates, checkpoints, and budget into a single signed document. Sessions are optionally bound to plans; when bound, plan-level constraints layer on top of (and can further restrict) the existing RBAC and risk engine decisions.

```
┌──────────────────────────────────────────────────────────────────────┐
│                     Human Authorization Layer (NEW)                  │
│                                                                      │
│  POST /v1/plans           GET /v1/plans/{id}     DELETE /v1/plans/{id}
│  ┌────────────────────────────────────────────────────────────┐      │
│  │                     MissionPlan                            │      │
│  │  action (intent)  ·  scope patterns  ·  requires_checkpoint│      │
│  │  delegates_to     ·  budget (TTL, max_delegations, max_risk)│     │
│  │  issuer (sub)     ·  Ed25519 signature over plan fields    │      │
│  └─────────────────────────┬──────────────────────────────────┘      │
│                             │ plan_id bound to session               │
│                             ▼                                        │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │              Existing PolicyEvaluator Pipeline               │    │
│  │  RBAC · Taint Tracking · Confused-Deputy · Risk Scoring     │    │
│  │  Rate Limiting · Arg Validation · ToolTrust Enhancements    │    │
│  │                                                              │    │
│  │  NEW: PlanCheckpointFilter (pre-RBAC stage)                 │    │
│  │    — if action matches requires_checkpoint → ESCALATE       │    │
│  │  NEW: PlanDelegatesToFilter (pre-confused-deputy stage)     │    │
│  │    — if agent_id not in delegates_to → DENY                 │    │
│  │  NEW: PlanBudgetGate (pre-evaluation stage)                 │    │
│  │    — if plan expired or budget exhausted → DENY             │    │
│  └──────────────────────────┬───────────────────────────────────┘   │
│                              │ decision                              │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │               Receipt Chain Manager (Enhanced)               │    │
│  │  ALLOW → Receipt(id, parent_id=plan.id or prior_receipt.id) │    │
│  │           Ed25519 signed · stored in receipts collection     │    │
│  │  GET /v1/plans/{id}/receipts → hierarchical tree            │    │
│  │  CLI: agentpep receipt verify-chain --plan plan_id          │    │
│  └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 13.4 New Data Models

### MissionPlan

| Field | Type | Description |
|---|---|---|
| `plan_id` | UUID | Unique plan identifier; root of receipt chain |
| `action` | String | Human-readable intent label (e.g. "Analyze Q3 finance reports") |
| `issuer` | String | Identity of the human issuing the plan (email / SSO subject) |
| `scope` | String[] | Allowed action patterns in `verb:namespace:resource` notation |
| `requires_checkpoint` | String[] | Action patterns that trigger ESCALATE regardless of RBAC |
| `delegates_to` | String[] | Agent IDs permitted to receive delegation; `[]` = no sub-delegation |
| `budget.max_delegations` | Integer? | Plan expires after N total ALLOW decisions; `null` = unlimited |
| `budget.max_risk_total` | Float? | Plan expires when accumulated risk score exceeds this; `null` = unlimited |
| `budget.ttl_seconds` | Integer? | Plan expires N seconds after issuance; `null` = no expiry |
| `status` | Enum: ACTIVE/EXPIRED/REVOKED | Current plan lifecycle state |
| `signature` | String | Ed25519 signature over canonical plan fields |
| `issued_at` | DateTime | UTC issuance timestamp |
| `expires_at` | DateTime? | Computed from `issued_at + ttl_seconds`; null if no TTL |

### Receipt (Extended from existing AuditDecision)

New fields added to the existing `AuditDecision` model:

| Field | Type | Description |
|---|---|---|
| `plan_id` | UUID? | Plan this receipt belongs to; null for plan-unbound sessions |
| `parent_receipt_id` | UUID? | Prior receipt in session under this plan; null for first delegation |
| `receipt_signature` | String? | Ed25519 signature over receipt fields (distinct from audit hash chain) |
| `human_intent` | String? | Copied from plan's `action` field for human-readable audit context |

### ScopePattern (New)

| Field | Type | Description |
|---|---|---|
| `pattern` | String | `verb:namespace:resource` glob (e.g. `read:public:*`) |
| `verb` | String? | Parsed verb component (read/write/delete/execute/send) |
| `namespace` | String? | Parsed namespace (public/secret/internal/external) |
| `resource_glob` | String? | Parsed resource glob (*.txt, report.*, *) |
| `mapped_rbac_patterns` | String[] | Computed RBAC tool_name globs this scope pattern covers |

---

## 13.5 New Decision: `PLAN_DENIED`

A new sub-reason for `DENY` decisions when a plan-level constraint blocks execution (distinct from RBAC DENY):

| Reason Code | Trigger |
|---|---|
| `PLAN_BUDGET_EXHAUSTED` | Plan's `max_delegations` or `max_risk_total` exceeded |
| `PLAN_EXPIRED` | Plan's TTL elapsed |
| `PLAN_REVOKED` | Plan manually revoked by security team |
| `PLAN_AGENT_NOT_AUTHORIZED` | Calling `agent_id` not in plan's `delegates_to` |
| `PLAN_NOT_BOUND` | Session requires a plan but none is bound |

---

## 13.6 Detailed Sprint Plans — Phase 9: ToolTrust Roadmap v2

### Sprint 37 — Mission Plan: Model, API & Lifecycle

**Goal:** Introduce `MissionPlan` as a first-class data model; implement plan issuance, retrieval, revocation, and Ed25519 signing; bind plans to sessions.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-292 | Design `MissionPlan` Pydantic model with all fields; add MongoDB collection `mission_plans` with compound indexes on `issuer`, `status`, and `expires_at` | 5 | Backend |
| APEP-293 | Implement Ed25519 plan signing using PyNaCl: sign canonical JSON of `(plan_id, issuer, scope, delegates_to, requires_checkpoint, budget, issued_at)`; store public key in tenant config | 8 | Security |
| APEP-294 | Implement `POST /v1/plans` — create and issue a signed plan; validate scope patterns and budget fields; return plan with signature | 5 | Backend |
| APEP-295 | Implement `GET /v1/plans/{plan_id}` — retrieve plan with budget status (delegations_used, risk_accumulated, time_remaining) | 3 | Backend |
| APEP-296 | Implement `DELETE /v1/plans/{plan_id}` — revoke plan (sets status=REVOKED); propagates DENY to any active sessions bound to plan | 5 | Backend |
| APEP-297 | Implement plan-session binding: `POST /v1/sessions/{session_id}/bind-plan` — associate plan with session; validates agent_id in delegates_to | 5 | Backend |
| APEP-298 | Implement plan TTL expiry background job: every 60s, scan `mission_plans` for expired plans and update status; emit Kafka event | 3 | Backend |
| APEP-299 | Write integration tests: plan issuance → session binding → expiry → revocation lifecycle | 5 | Testing |

### Sprint 38 — Scope Pattern Language & DSL Compiler

**Goal:** Implement `verb:namespace:resource` scope notation; build pattern compiler that maps scope patterns to RBAC tool-name globs; integrate scope matching into PolicyEvaluator.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-300 | Design and document scope pattern syntax: verb (read/write/delete/execute/send/list), namespace (public/internal/secret/external/any), resource (glob); define escaping and wildcard rules | 3 | Backend |
| APEP-301 | Implement `ScopePatternParser`: parse `verb:namespace:resource` string into structured `ScopePattern` object; validate all components | 5 | Backend |
| APEP-302 | Implement `ScopePatternCompiler`: translate parsed scope pattern to equivalent RBAC tool_name glob(s) and arg constraints for PolicyEvaluator consumption | 8 | Backend |
| APEP-303 | Implement scope matching in `PlanCheckpointFilter`: check if incoming tool_call action matches any `requires_checkpoint` pattern; return ESCALATE if matched | 5 | Backend |
| APEP-304 | Implement scope allow-check in `PlanScopeFilter`: check if action matches any `scope` pattern; DENY with `PLAN_AGENT_NOT_AUTHORIZED` if no match (plan-aware sessions only) | 5 | Backend |
| APEP-305 | Add `agentpep scope compile <pattern>` CLI command: shows mapped RBAC globs and arg constraints | 3 | SDK |
| APEP-306 | Add `agentpep scope validate <plan.yaml>` CLI command: validates all scope patterns in a plan file and reports any unsupported or conflicting patterns | 3 | SDK |
| APEP-307 | Write unit tests: scope pattern parsing, compilation edge cases, checkpoint matching, allow-check matching | 5 | Testing |

### Sprint 39 — Receipt Chaining with Plan Root

**Goal:** Extend `AuditDecision` with `plan_id` and `parent_receipt_id`; implement per-receipt Ed25519 signing; add plan-scoped receipt retrieval API; implement independent offline verifier.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-308 | Extend `AuditDecision` Pydantic model with `plan_id`, `parent_receipt_id`, `receipt_signature`, and `human_intent` fields; add MongoDB index on `plan_id` | 3 | Backend |
| APEP-309 | Implement per-receipt Ed25519 signing in `AuditLogger`: sign canonical `(decision_id, plan_id, parent_receipt_id, agent_id, tool_name, decision, timestamp)` for every ALLOW decision | 8 | Security |
| APEP-310 | Implement `ReceiptChainManager`: tracks latest receipt per session per plan in Redis; sets `parent_receipt_id` on each new receipt to prior receipt in chain | 5 | Backend |
| APEP-311 | Implement `GET /v1/plans/{plan_id}/receipts` — return full receipt tree as nested JSON; parent nodes contain list of child receipts | 5 | Backend |
| APEP-312 | Implement `GET /v1/plans/{plan_id}/receipts/summary` — return counts, total risk accumulated, ALLOW/DENY/ESCALATE breakdown, budget remaining | 3 | Backend |
| APEP-313 | Implement `OfflineReceiptVerifier`: given a list of receipts and the tenant's Ed25519 public key, verify the full chain without server access; report VERIFIED / BROKEN / TAMPERED per node | 8 | Security |
| APEP-314 | Add `agentpep receipt verify-chain --plan <plan_id> --export receipts.json` CLI command: exports chain and verifies locally | 3 | SDK |
| APEP-315 | Write adversarial tests: tampered receipt detection, broken parent chain, out-of-order receipts, cross-plan receipt injection | 5 | Testing |

### Sprint 40 — Declarative Delegates-To & Plan Budget Gate

**Goal:** Implement `PlanDelegatesToFilter` as pre-stage in PolicyEvaluator; implement `PlanBudgetGate` with Redis-backed budget state tracking; enforce TTL, delegation count, and risk budget.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-316 | Implement `PlanDelegatesToFilter`: fast-path check before confused-deputy detector — if `agent_id` not in plan's `delegates_to` list, return DENY with `PLAN_AGENT_NOT_AUTHORIZED` immediately | 5 | Backend |
| APEP-317 | Implement `delegates_to: []` enforcement: plans with empty `delegates_to` block all sub-agent delegation, enforcing leaf-agent constraint | 3 | Backend |
| APEP-318 | Implement `PlanBudgetGate`: Redis-backed budget state per plan — tracks `delegations_used` (inc on ALLOW), `risk_accumulated` (add risk_score on ALLOW), `elapsed_seconds` | 8 | Backend |
| APEP-319 | Implement budget exhaustion enforcement: check all three budget dimensions before PolicyEvaluator stages; return DENY with appropriate `PLAN_*` reason code | 5 | Backend |
| APEP-320 | Implement budget status API: `GET /v1/plans/{plan_id}/budget` returns current usage vs limits with percentage and time-remaining | 3 | Backend |
| APEP-321 | Implement budget alert events: Kafka event `agentpep.plan_budget` when plan reaches 80% of any budget dimension; console warning badge | 3 | Backend |
| APEP-322 | Implement plan budget reset: `POST /v1/plans/{plan_id}/budget/reset` for security admins; requires peer approval via console review workflow | 3 | Backend |
| APEP-323 | Write integration tests: delegation count exhaustion, risk budget exhaustion, TTL expiry, delegates_to block, simultaneous budget races | 5 | Testing |

### Sprint 41 — Checkpoint-Declared Escalation & Human Intent

**Goal:** Integrate `requires_checkpoint` as a pre-RBAC PolicyEvaluator stage that unconditionally triggers ESCALATE for matched actions; add `human_intent` field propagation through the evaluation pipeline.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-324 | Implement `PlanCheckpointFilter` as the first stage in PolicyEvaluator (before RBAC): match incoming action against plan's `requires_checkpoint` patterns; return ESCALATE if matched | 5 | Backend |
| APEP-325 | Propagate checkpoint match reason to Escalation Manager: escalation ticket includes checkpoint pattern matched, plan action (human intent), issuer identity, and budget remaining | 5 | Backend |
| APEP-326 | Implement checkpoint approval memory scoped to plan: if approver approves a checkpoint-triggered action, subsequent identical actions within the plan's remaining TTL are auto-approved | 5 | Backend |
| APEP-327 | Add `human_intent` field propagation: copy plan's `action` string into every audit record, escalation ticket, and Kafka event emitted under that plan | 3 | Backend |
| APEP-328 | Add checkpoint pattern testing to policy simulation: `POST /v1/simulate` with `plan_id` shows whether action hits checkpoint before RBAC evaluation | 3 | Backend |
| APEP-329 | Build Checkpoint History view in Escalation Queue console screen: filter escalations by plan; show checkpoint pattern matched; display human intent from plan | 5 | Frontend |
| APEP-330 | Update compliance reports (DPDPA / CERT-In): include plan-level intent field and checkpoint audit records in exported reports | 3 | Backend |
| APEP-331 | Write integration tests: checkpoint matched before RBAC; checkpoint with approval memory; no-plan session not affected by checkpoint logic | 3 | Testing |

### Sprint 42 — Plan Console UI & Plan-Scoped Audit Tree

**Goal:** Add Plan Management and Plan Explorer screens to Policy Console; implement plan-centric audit tree visualisation; add plan budget dashboard widget.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-332 | Build Plan Management list screen: table of plans with status badge (ACTIVE/EXPIRED/REVOKED), issuer, human intent, budget utilisation bars, time remaining | 5 | Frontend |
| APEP-333 | Build Plan Issuance form: scope pattern builder with live validation, delegates_to agent picker from registry, requires_checkpoint pattern builder, budget fields | 8 | Frontend |
| APEP-334 | Build Plan Detail screen: full plan fields, signature verification status, budget gauges, receipt count, quick-revoke button with confirmation | 5 | Frontend |
| APEP-335 | Build Plan Explorer — receipt tree view: collapsible nested tree of all receipts under a plan; each node shows agent_id, action, decision, risk_score, timestamp | 8 | Frontend |
| APEP-336 | Implement receipt node drill-down: click receipt to see full AuditDecision detail including taint flags, matched rule, delegation chain, and receipt signature | 3 | Frontend |
| APEP-337 | Add plan budget widget to Risk Dashboard: top-N plans by budget consumption; plans approaching expiry or exhaustion highlighted in amber/red | 3 | Frontend |
| APEP-338 | Add plan filter to Audit Explorer: filter all audit records by plan_id; display human_intent as contextual header | 3 | Frontend |
| APEP-339 | Write Playwright E2E tests: plan issuance form, receipt tree drill-down, revocation flow | 3 | Testing |

### Sprint 43 — Scope Simulator, Pattern Library & SDK Plan API

**Goal:** Build interactive scope simulator in console and CLI; publish curated enterprise scope pattern library; add plan-aware session API to SDK.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-340 | Build scope simulator UI: paste a `verb:namespace:resource` pattern, select a plan, submit an action — shows checkpoint check → scope check → RBAC evaluation → final decision with stage-by-stage trace | 8 | Frontend |
| APEP-341 | Add `agentpep scope simulate --plan plan.yaml --action "delete:finance:report.pdf"` CLI command: runs full evaluation pipeline offline and outputs decision with stage trace | 5 | SDK |
| APEP-342 | Build enterprise scope pattern library: 30+ curated scope patterns for file access, email, database, Slack/Teams, calendar, code execution, and API calls; stored as importable YAML templates | 8 | Backend |
| APEP-343 | Implement pattern library UI: browse, search, and import scope patterns into new plan; preview what each pattern allows/blocks with example actions | 5 | Frontend |
| APEP-344 | Implement `ToolTrustSession` SDK class: wraps `AgentPEPClient` with plan-aware `issue_plan()`, `delegate()`, and `audit()` methods mirroring ToolTrust's API surface for easy migration | 8 | SDK |
| APEP-345 | Implement SDK `delegate()` method: calls `POST /v1/intercept` with plan context; returns `DelegationResult(ok, reason, receipt)` matching ToolTrust's response shape | 3 | SDK |
| APEP-346 | Write ToolTrust migration guide: document how to convert an ToolTrust `issue_plan()` / `delegate()` / `audit()` workflow to use AgentPEP's plan-aware SDK | 3 | Docs |
| APEP-347 | Write integration tests: `ToolTrustSession` full lifecycle — issue plan → bind session → delegate → receipt chain → audit tree → revoke | 3 | Testing |

---

## 13.7 Sprint Summary — Phase 9

| Sprint | Name | Phase | Stories |
|---|---|---|---|
| 37 | Mission Plan: Model, API & Lifecycle | Phase 9: ToolTrust Roadmap v2 | 8 |
| 38 | Scope Pattern Language & DSL Compiler | Phase 9: ToolTrust Roadmap v2 | 8 |
| 39 | Receipt Chaining with Plan Root | Phase 9: ToolTrust Roadmap v2 | 8 |
| 40 | Declarative Delegates-To & Plan Budget Gate | Phase 9: ToolTrust Roadmap v2 | 8 |
| 41 | Checkpoint-Declared Escalation & Human Intent | Phase 9: ToolTrust Roadmap v2 | 8 |
| 42 | Plan Console UI & Plan-Scoped Audit Tree | Phase 9: ToolTrust Roadmap v2 | 8 |
| 43 | Scope Simulator, Pattern Library & SDK Plan API | Phase 9: ToolTrust Roadmap v2 | 8 |

---

## 13.8 Enhancement Summary

| Dimension | Before (v1.1 with ToolTrust) | After (v1.2 with ToolTrust Enhancements) |
|---|---|---|
| **Authorization root** | Implicit sessions bound by RBAC policies | **Mission Plan**: human-issued, signed, scoped authorization artifact |
| **Action notation** | Glob/regex patterns on tool_name | + `verb:namespace:resource` scope pattern DSL |
| **Escalation triggers** | Risk threshold + RBAC ESCALATE rule | + Plan-declared checkpoint patterns (pre-RBAC, declarative) |
| **Agent delegation whitelist** | Reactive confused-deputy detection | + Proactive `delegates_to` whitelist per plan |
| **Authorization budget** | No per-session budget concept | Plan budget: TTL, max_delegations, max_risk_total |
| **Receipt model** | Hash chain on sequential audit log | + Per-receipt Ed25519 signing + parent_id chain back to plan root |
| **Audit view** | Flat audit log with filters | + Plan-scoped receipt tree: hierarchical view from plan root |
| **Independent verification** | Server-dependent hash chain validation | Offline Ed25519 chain verification with public key only |
| **Human context** | Technical audit records (tool names, arg hashes) | + `human_intent` field from plan in every audit record |
| **SDK surface** | `@enforce` decorator, session taint labeling | + `ToolTrustSession` plan-aware API (`issue_plan`, `delegate`, `audit`) |
| **Scope tooling** | YAML policy authoring, CLI validation | + Scope simulator, pattern library (30+ templates), DSL compiler |
| **Total stories** | ~291 (Sprints 1–36) | **~347** (+ 56 ToolTrust enhancement stories, Sprints 37–43) |

---

## 13.9 Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| Mission Plan concept adds ceremony for simple agent workflows | Medium | Medium | Plan binding is optional; existing plan-free sessions continue to work unchanged |
| Scope DSL introduces mapping ambiguity between patterns and RBAC rules | High | Medium | Compiler produces explicit mapping output; policy simulator validates before deployment |
| Receipt chaining increases write latency on ALLOW decisions | Low | Low | `parent_receipt_id` lookup from Redis (sub-millisecond); signing is async (PyNaCl Ed25519 ~100μs) |
| Plan budget races under concurrent delegation | Medium | Medium | Redis atomic increment + compare; budget check uses Lua script for atomicity |
| Checkpoint approval memory could be abused to pre-approve risky actions | High | Low | Approval memory scoped to plan; TTL configurable (default 1 hour); admin can clear |
| `ToolTrustSession` SDK API surface confusion with existing `@enforce` decorator | Low | Low | Both APIs documented; migration guide explicit; `ToolTrustSession` is additive, not replacement |

---

## 13.10 Success Metrics — Phase 9

| Metric | Target | Measurement Method |
|---|---|---|
| Plan issuance to first delegation time | < 2 minutes (human + API) | Developer usability study |
| Scope DSL pattern validation accuracy | 100% of syntactically valid patterns compile without error | Pattern test corpus |
| Checkpoint escalation latency | < 100ms additional over base ESCALATE path | Prometheus histogram delta |
| Receipt chain verification (offline) | 100% of ALLOW decisions independently verifiable | Audit reconciliation job |
| Plan budget enforcement accuracy | Zero budget overruns under concurrent load | Redis Lua script stress test |
| Plan Console task completion (SUS) | > 75 (Good) — plan issuance and receipt tree drill-down tasks | UX usability study |
| `ToolTrustSession` SDK migration time | Existing ToolTrust users migrate in < 1 hour | Beta migration partner measurement |
| Human intent field coverage | 100% of plan-bound audit records carry `human_intent` | Audit completeness check |

---

*AgentPEP · TrustFabric Portfolio · Confidential · © 2026*

---

# 14. TrustFabric Network: ToolTrust-Native Roadmap v3

## 14.1 Overview

This section specifies the work required to build ToolTrust's network egress security capabilities natively within the AgentPEP Python/FastAPI/MongoDB stack — eliminating the Go dependency while gaining deep integration with AgentPEP's taint engine, risk scorer, audit logger, and Kafka event stream.

**Reference:** [Shivapas/ToolTrust](https://github.com/Shivapas/ToolTrust) — an agent firewall providing DLP scanning, SSRF protection, bidirectional MCP scanning, tool poisoning detection, and prompt injection blocking.

**Analysis Date:** April 2026
**Scope:** 8 sprints (Sprints 44–51) · 64 stories · ~16 weeks

The resulting module is named **TrustFabric Network (TFN)** — a network egress security layer embedded within AgentPEP, operating as a sidecar proxy alongside the existing tool-call enforcement engine.

---

## 14.2 Feasibility Assessment: Python vs Go

ToolTrust is written in Go and achieves ~32μs per URL scan as a single binary. Building equivalent functionality in Python introduces trade-offs that must be understood before committing to the sprint plan.

### 14.2.1 Capability-by-Capability Build Assessment

| ToolTrust Capability | Python Feasibility | Approach | Estimated Sprint Cost |
|---|---|---|---|
| **11-layer URL scanner** | ✅ Full | `re`, `socket`, `urllib.parse`, existing `rate_limiter.py`, Redis | 1 sprint |
| **DLP patterns (46 built-in)** | ✅ Full | Extend existing `injection_signatures.py`; compiled regex | 0.5 sprint (within URL scanner sprint) |
| **Entropy analysis** | ✅ Full | Shannon entropy is ~5 lines of Python; no dependencies | Included above |
| **SSRF / DNS rebinding prevention** | ✅ Full | `socket.getaddrinfo()` + RFC 1918/loopback/link-local range checks; async DNS with `aiodns` | Included above |
| **Fetch proxy** | ✅ Full | `httpx.AsyncClient` already used in `mcp_proxy.py`; add `/v1/fetch` endpoint | 0.5 sprint |
| **Response injection scanner** | ✅ Full | Extend `injection_signatures.py`; add `unicodedata.normalize`, zero-width strip, base64 unwrap, homoglyph map | 1 sprint |
| **Forward proxy (CONNECT tunneling)** | ✅ Full | `asyncio.StreamReader/StreamWriter` CONNECT tunneling; FastAPI background task | 1.5 sprints |
| **TLS interception (optional)** | ⚠️ Partial | `cryptography` library for ECDSA P-256 CA; MITM via CONNECT intercept; complex but achievable | 1 sprint (optional, deferred to end) |
| **WebSocket proxy** | ✅ Full | `websockets` library; bidirectional frame proxying; fragment reassembly | 1 sprint |
| **MCP proxy — bidirectional DLP** | ✅ Full | Extend existing `mcp_proxy.py` (Sprint 12); add DLP scan on both request args and server response | 0.5 sprint (enhancement) |
| **MCP tool poisoning detection** | ✅ Full | Scan `tools/list` descriptions against injection signatures; track description changes between calls | 0.5 sprint |
| **Tool call chain detection** | ✅ Full | Subsequence matching with gap tolerance in Python stdlib; session history already in taint graph | 1 sprint |
| **Kill switch (4 sources)** | ✅ Full | FastAPI endpoint; `signal.signal(SIGUSR1)`; `asyncio` file watcher; config flag; secondary port via uvicorn | 1 sprint |
| **Filesystem sentinel** | ✅ Full | `watchdog` library (inotify on Linux, FSEvents on macOS); DLP scan on file writes; `/proc` for process lineage | 1 sprint |
| **Process sandbox (Landlock/seccomp)** | ⚠️ Partial | `python-prctl` for seccomp; Landlock Python bindings exist but immature; network namespaces require `CAP_SYS_ADMIN` — not viable in standard containers | Helm NetworkPolicy preferred; 0.5 sprint for what's feasible |
| **Adaptive threat score / session profiling** | ✅ Full | Extend existing session accumulated risk scorer (APEP-067) with network event signals | 0.5 sprint |
| **Rule bundles (Ed25519-signed YAML)** | ✅ Full | Ed25519 already in stack (Phase 8, Sprint 32); YAML bundle loader mirrors existing `injection_signatures.py` | 0.5 sprint |
| **Security assessment (attack simulation)** | ✅ Full | Extend existing simulation engine (Sprint 19); add 12-category config audit; deployment probe | 1 sprint |
| **MITRE ATT&CK tagging on events** | ✅ Full | Add `mitre_technique_id` field to Kafka events; maintain ATT&CK technique map | 0.25 sprint |
| **Ed25519 signed audit reports** | ✅ Full | Already in stack (Phase 8, Sprint 32) | 0 (reuse) |
| **Prometheus metrics** | ✅ Full | Extend existing `/metrics` endpoint (Sprint 9, 26) | 0 (reuse) |
| **BIP-39 seed phrase detection** | ❌ Out of scope | Enterprise AI security focus; out of scope for TrustFabric | — |
| **Blockchain address protection** | ❌ Out of scope | Out of scope for TrustFabric | — |

### 14.2.2 Performance Expectations

| Operation | ToolTrust (Go) | TFN Python Estimate | Impact on AgentPEP p99 |
|---|---|---|---|
| URL scan (11 layers) | ~32μs | ~300–500μs | +0.5ms on intercept path |
| DLP pattern match (46 patterns, compiled) | ~15μs | ~100–200μs | Negligible |
| Response injection scan (6-pass normalization) | ~80μs | ~500μs–1ms | Acceptable (async, non-blocking) |
| Shannon entropy calculation | ~5μs | ~20μs | Negligible |
| SSRF DNS resolution check | ~200μs | ~500μs | Async, non-blocking |
| CONNECT tunnel overhead | ~50μs | ~300–500μs | I/O bound; asyncio performs well |

**Verdict:** Python is 10–15× slower than Go on CPU-bound scan operations. However, all TFN scanning runs **asynchronously and outside the critical intercept response path**. The intercept API returns its ALLOW/DENY decision from AgentPEP's existing pipeline. TFN scanning runs as a parallel async task or as a pre-intercept filter — it never blocks the <15ms p99 SLA unless a scan result is required to make the authorization decision (DLP pre-scan of tool args). Even then, adding 0.5–1ms is within the 5ms regression budget established in Phase 8.

### 14.2.3 What TFN Does That ToolTrust Cannot

The native Python build gains capabilities that a Go sidecar cannot offer:

| Capability | TFN Advantage Over Standalone ToolTrust |
|---|---|
| **Taint auto-labeling from response scan** | When TFN injection scanner flags a fetched URL response, it directly calls `session_graph_manager.label()` to mark the content `QUARANTINE` — no IPC, no API call, same process |
| **DLP risk signal in AgentPEP risk scorer** | `DataSensitivityScorer` (APEP-065) is enriched with TFN's DLP verdict on tool args in the same evaluation pipeline |
| **Kill switch triggers AgentPEP FAIL_CLOSED** | When TFN kill switch activates, AgentPEP's `FAIL_CLOSED` mode engages simultaneously — the authorization and network layers act as one |
| **Unified Kafka event stream** | TFN network events publish to `agentpep.network` topic with the same `session_id`, `agent_id`, and `decision_id` correlation IDs — NEXUS sees a unified timeline |
| **Shared injection signature library** | TFN response scanner and AgentPEP taint engine share the same `injection_signatures.py` singleton — one update hardens both layers |
| **Shared rate limiter** | TFN per-domain rate limiting reuses AgentPEP's existing Redis-backed `rate_limiter.py` — no duplicate infrastructure |
| **Plan-aware fetch budgets** | TFN fetch proxy enforces per-plan data budgets (Phase 9 MissionPlan) — a plan's network budget tracks alongside its authorization budget |

---

## 14.3 Architecture: TrustFabric Network (TFN)

TFN is a new module within the AgentPEP backend, deployed as a second FastAPI application or as additional routes on the existing API, listening on a dedicated port (default: 8889).

```
┌────────────────────────────────────────────────────────────────────────┐
│                    AgentPEP Backend Process                            │
│                                                                        │
│  Port 8888 — Intercept API (existing)                                  │
│  ┌──────────────────────────────────────────────────────────────┐      │
│  │  PolicyEvaluator → RBAC, Taint, Deputy, Risk, Rate Limit    │      │
│  │  + TFN DLP Pre-Scan hook (new): scan tool args before eval  │      │
│  └──────────────────────────────────────────────────────────────┘      │
│                                                                        │
│  Port 8889 — TrustFabric Network (new)                                 │
│  ┌──────────────────────────────────────────────────────────────┐      │
│  │  /v1/fetch          Fetch proxy + response injection scan    │      │
│  │  /v1/scan           Programmatic scan API (URL/DLP/injection)│      │
│  │  HTTPS_PROXY        Forward proxy (CONNECT tunneling)        │      │
│  │  /v1/ws             WebSocket proxy with DLP scanning        │      │
│  │  /v1/mcp (enhanced) MCP proxy with bidirectional DLP        │      │
│  │  /v1/killswitch     Emergency deny-all (4 activation sources)│      │
│  └───────────────────────────┬──────────────────────────────────┘      │
│                              │ shared in-process                       │
│  ┌───────────────────────────▼──────────────────────────────────┐      │
│  │              Shared Services (existing + new)                │      │
│  │  NetworkDLPScanner  ·  ResponseInjectionScanner              │      │
│  │  URLScanner (11 layers)  ·  SSRFGuard  ·  EntropyAnalyzer   │      │
│  │  ToolCallChainDetector  ·  FilesystemSentinel                │      │
│  │  session_graph_manager (taint — existing)                    │      │
│  │  rate_limiter (existing)  ·  kafka_producer (existing)      │      │
│  │  injection_signatures (existing, extended)                   │      │
│  └──────────────────────────────────────────────────────────────┘      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 14.4 New Data Models

### NetworkScanRequest

| Field | Type | Description |
|---|---|---|
| `scan_kind` | Enum: url/dlp/injection/tool_call | What to scan |
| `url` | String? | URL to scan (for `url` and `dlp` kinds) |
| `text` | String? | Text content to scan (for `injection` and `dlp` kinds) |
| `tool_call` | ToolCallRequest? | Tool call to scan (for `tool_call` kind) |
| `session_id` | String? | Associate scan result with a session for taint propagation |
| `agent_id` | String? | Agent context for per-agent filtering |

### NetworkScanResult

| Field | Type | Description |
|---|---|---|
| `allowed` | Boolean | Whether request/content passed all scans |
| `blocked` | Boolean | Whether any scanner returned a block verdict |
| `findings` | Finding[] | List of findings from all scanners |
| `scanners_run` | String[] | Names of scanners executed |
| `taint_assigned` | TaintLevel? | Taint level assigned to session if `session_id` provided |
| `mitre_technique_ids` | String[] | MITRE ATT&CK technique IDs from matched findings |
| `latency_ms` | Integer | Total scan latency |

### NetworkEvent (Kafka: `agentpep.network`)

| Field | Type | Description |
|---|---|---|
| `event_id` | UUID | Unique event identifier |
| `session_id` | String? | AgentPEP session correlation |
| `agent_id` | String? | Agent correlation |
| `decision_id` | UUID? | Correlated AgentPEP intercept decision |
| `event_type` | Enum | DLP_HIT / INJECTION_DETECTED / SSRF_BLOCKED / CHAIN_DETECTED / KILL_SWITCH / SENTINEL_HIT |
| `scanner` | String | Scanner that produced the finding |
| `finding_rule_id` | String | Rule ID matched |
| `severity` | Enum | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `mitre_technique_id` | String? | MITRE ATT&CK technique ID |
| `url` | String? | URL involved (sanitized) |
| `blocked` | Boolean | Whether the event resulted in a block |
| `timestamp` | DateTime | UTC event timestamp |

---

## 14.5 New Scan Modes and Actions

TFN mirrors ToolTrust's three security modes but integrates with AgentPEP's existing FAIL_CLOSED/FAIL_OPEN configuration:

| Mode | Behavior | Maps To AgentPEP |
|---|---|---|
| **strict** | Allowlist-only egress; any unlisted domain → block | FAIL_CLOSED + DENY-by-default on all network requests |
| **balanced** | Block known-bad + detect sophisticated; default | AgentPEP's current enforcement posture |
| **audit** | Log-only; never block; visibility mode | DRY_RUN equivalent for network scanning |

---

## 14.6 Detailed Sprint Plans — Phase 10: TrustFabric Network

### Sprint 44 — Network DLP Engine & 11-Layer URL Scanner

**Goal:** Build the `NetworkDLPScanner` and `URLScanner` service with all 11 layers; extend `injection_signatures.py` to 46 DLP patterns covering API keys, tokens, and credentials; add entropy and SSRF analysis.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-348 | Design `NetworkDLPScanner` service: extend `injection_signatures.py` with 46 DLP patterns (API keys for all major providers, OAuth tokens, private keys, database connection strings, financial identifiers) | 8 | Backend |
| APEP-349 | Implement `URLScanner` pipeline: scheme validation (block `file://`, `ftp://`, `gopher://`), CRLF injection detection, path traversal blocking (`../`, `%2F..`) | 3 | Backend |
| APEP-350 | Implement domain blocklist lookup: configurable YAML blocklist; fast `frozenset` lookup; `GET /v1/network/blocklist` management API | 3 | Backend |
| APEP-351 | Implement DLP pattern matching stage in URLScanner: run all 46 patterns against full URL string; return finding with matched pattern ID and severity | 5 | Backend |
| APEP-352 | Implement `EntropyAnalyzer`: Shannon entropy of URL path segments and subdomains; configurable thresholds; flag high-entropy strings as potential exfiltration | 5 | Backend |
| APEP-353 | Implement `SSRFGuard`: resolve hostname via `aiodns`, validate against RFC 1918, loopback, link-local, IANA reserved ranges; block DNS rebinding by re-resolving before connection | 5 | Security |
| APEP-354 | Implement per-domain rate limiting and per-domain data budget in URLScanner: reuse existing Redis-backed `rate_limiter.py`; add `data_budget_bytes` counter per domain per session | 3 | Backend |
| APEP-355 | Implement `POST /v1/scan` endpoint: accepts `NetworkScanRequest`; runs appropriate scanner(s); returns `NetworkScanResult` with findings and MITRE ATT&CK IDs | 5 | Backend |

### Sprint 45 — DLP Pre-Scan Hook in Intercept Pipeline

**Goal:** Integrate `NetworkDLPScanner` into the existing `PolicyEvaluator` pipeline as a pre-evaluation stage; auto-elevate risk score when DLP hits are found in tool arguments; auto-taint tool arg values containing credentials.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-356 | Implement `DLPPreScanStage` in `PolicyEvaluator`: serialize tool args to string; run `NetworkDLPScanner`; inject DLP findings as additional risk signals before `DataSensitivityScorer` | 8 | Backend |
| APEP-357 | Implement DLP-to-risk mapping: CRITICAL DLP hit → risk score += 0.3; HIGH → += 0.2; MEDIUM → += 0.1; cumulative cap at 0.95 | 3 | Backend |
| APEP-358 | Implement DLP-to-taint assignment: if a tool arg value matches a credential pattern, auto-assign `QUARANTINE` taint to that arg's taint node in the session graph | 5 | Security |
| APEP-359 | Add DLP findings to `PolicyDecisionResponse`: new `dlp_findings` field listing matched patterns and severities; include in audit decision record | 3 | Backend |
| APEP-360 | Add DLP metrics to Prometheus: `dlp_hits_total` by pattern_id and severity; `dlp_quarantine_assignments_total` | 2 | Observability |
| APEP-361 | Implement DLP pre-scan caching: hash tool args + pattern version; cache scan result in Redis with 60s TTL to avoid redundant scans on identical args | 3 | Performance |
| APEP-362 | Write adversarial tests: API key in URL arg → QUARANTINE taint; credential in file path → risk elevation; DLP cache hit returns same result | 5 | Testing |
| APEP-363 | Implement DLP pattern hot-reload: pattern updates loaded without restart via existing config watcher | 3 | Backend |

### Sprint 46 — Fetch Proxy & Multi-Pass Response Injection Scanner

**Goal:** Build `/v1/fetch` fetch proxy endpoint; implement `ResponseInjectionScanner` with 6-pass Unicode normalization; auto-taint QUARANTINE when injection detected; integrate with session graph.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-364 | Implement `GET /v1/fetch?url=...` fetch proxy: use `httpx.AsyncClient`; run `URLScanner` before fetch; extract text content from HTML via `html.parser`; return `FetchResult` | 5 | Backend |
| APEP-365 | Implement 6-pass `ResponseNormalizer`: (1) NFKC Unicode normalization via `unicodedata`; (2) zero-width char stripping (`\u200b`–`\u200f`, `\uFEFF`); (3) homoglyph substitution (custom 400-entry map); (4) leetspeak substitution; (5) base64 unwrap and re-scan; (6) HTML entity decode | 8 | Security |
| APEP-366 | Implement `ResponseInjectionScanner`: run normalized text through `injection_signatures.py`; add 23 response-specific patterns (jailbreak phrases, credential solicitation, memory persistence, CJK instruction overrides) | 8 | Security |
| APEP-367 | Implement auto-taint on injection detection: when `ResponseInjectionScanner` finds a match, call `session_graph_manager.label(content, taint=QUARANTINE, source=WEB)` directly; no manual SDK call required | 5 | Security |
| APEP-368 | Implement fetch proxy DLP scan on response body: run `NetworkDLPScanner` on response text; flag any credential patterns in server responses (exfiltration canary detection) | 3 | Security |
| APEP-369 | Implement configurable response actions: `block` (return error, do not deliver content), `strip` (remove injection pattern match, deliver remainder), `warn` (deliver with warning header), `ask` (ESCALATE to human approval queue) | 5 | Backend |
| APEP-370 | Implement SDK `fetch_safe()` method: wraps `GET /v1/fetch`; auto-labels returned content with taint level from scan result; drop-in replacement for raw `httpx.get()` | 3 | SDK |
| APEP-371 | Write adversarial tests: prompt injection in web response → QUARANTINE; base64-encoded injection → normalized and caught; homoglyph evasion → normalized and caught | 5 | Testing |

### Sprint 47 — Forward Proxy (CONNECT Tunneling) & WebSocket Proxy

**Goal:** Implement HTTPS_PROXY-compatible forward proxy using asyncio CONNECT tunneling; implement bidirectional WebSocket proxy with DLP and injection frame scanning.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-372 | Implement `asyncio` CONNECT tunnel handler: accept `CONNECT host:port HTTP/1.1`, resolve via `SSRFGuard`, open upstream TCP connection, bridge bidirectionally via `asyncio.StreamReader/StreamWriter` | 8 | Backend |
| APEP-373 | Implement request body DLP scan in forward proxy: buffer POST bodies up to configurable limit; run `NetworkDLPScanner`; block or warn on hits before forwarding | 5 | Security |
| APEP-374 | Implement hostname-level blocking in forward proxy: check hostname against blocklist before opening CONNECT tunnel; return `403 Forbidden` with reason code | 3 | Backend |
| APEP-375 | Implement optional TLS interception (MITM): generate per-domain leaf certificates signed by AgentPEP CA (using `cryptography` library ECDSA P-256); decrypt CONNECT tunnel for full body/header DLP scan; re-encrypt to upstream | 8 | Security |
| APEP-376 | Implement `ToolTrust tls init` equivalent: `POST /v1/network/tls/init` generates AgentPEP CA keypair; `GET /v1/network/tls/ca.crt` exports the CA certificate for client trust installation | 3 | Backend |
| APEP-377 | Implement WebSocket proxy: `GET /v1/ws?url=ws://...`; use `websockets` library; proxy bidirectional frames; reassemble fragmented messages before scanning | 5 | Backend |
| APEP-378 | Implement WebSocket frame DLP + injection scanning: run `NetworkDLPScanner` and `ResponseInjectionScanner` on text frames in both directions; binary frames pass through with size limit enforcement | 5 | Security |
| APEP-379 | Write integration tests: CONNECT tunnel through forward proxy; DLP hit on POST body → block; WebSocket frame injection → quarantine; SSRF attempt → 403 | 5 | Testing |

### Sprint 48 — MCP Proxy Enhancement: Bidirectional DLP & Tool Poisoning Detection

**Goal:** Enhance existing `mcp_proxy.py` (Sprint 12) with bidirectional DLP scanning; add tool poisoning detection on `tools/list` responses; detect mid-session tool description rug-pulls.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-380 | Enhance `MCPProxy` outbound scan: run `NetworkDLPScanner` on `tool_args` before forwarding to upstream (in addition to existing AgentPEP RBAC check); DENY if CRITICAL DLP hit | 5 | Backend |
| APEP-381 | Implement MCP response scan: run `ResponseInjectionScanner` on MCP tool call results before delivering to agent; auto-taint result content based on scan outcome | 5 | Security |
| APEP-382 | Implement `tools/list` poisoning detection: scan each tool's `description` field against `injection_signatures.py` and DLP patterns; block tool registration if poisoned description detected | 5 | Security |
| APEP-383 | Implement rug-pull detection: cache `tools/list` response hash per upstream server per session; if `tools/list` response changes mid-session, emit `TOOL_LIST_CHANGED` security alert and optionally escalate | 5 | Security |
| APEP-384 | Implement MCP HTTP reverse proxy mode: `POST /v1/mcp/proxy` accepts Streamable HTTP MCP messages; scans bidirectionally; forwards to configured upstream; supports both stdio subprocess wrapping and HTTP upstream | 5 | Backend |
| APEP-385 | Implement MCP session DLP budget: per-MCP-session data volume tracker; alert and optionally block when session exceeds configured data transfer budget | 3 | Backend |
| APEP-386 | Write adversarial MCP tests: poisoned tool description blocked; rug-pull mid-session detected; credential in tool result → QUARANTINE taint; CRITICAL DLP in tool args → DENY | 5 | Testing |
| APEP-387 | Update MCP proxy documentation and integration guides for LangGraph and OpenAI Agents SDK with bidirectional scanning | 3 | Docs |

### Sprint 49 — Tool Call Chain Detection Engine

**Goal:** Implement `ToolCallChainDetector` with configurable attack sequence patterns; integrate with session history from the taint graph and audit log; emit Kafka security alerts on chain detection.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-388 | Design `ToolCallChain` pattern model: sequence of tool name patterns (glob) with configurable gap tolerance (N innocent calls between steps); MITRE ATT&CK technique mapping per pattern | 5 | Backend |
| APEP-389 | Implement subsequence matching engine: given session tool call history and a chain pattern, detect if pattern appears as a subsequence with gap ≤ `max_gap`; O(n) sliding window algorithm | 8 | Backend |
| APEP-390 | Implement built-in chain pattern library (10 patterns): reconnaissance (list_files + read_env + get_credentials), credential theft (read_file matching `*secret*` + `*token*` + send_*), data staging (read_* → write_temp → compress → upload), persistence (create_cron + create_startup + write_config), exfiltration (read_sensitive + encode + http_post to external domain) | 8 | Security |
| APEP-391 | Integrate chain detector into `PolicyEvaluator` post-decision stage: after ALLOW, append tool call to session chain history; check all patterns against updated history; emit `CHAIN_DETECTED` security alert if match | 5 | Backend |
| APEP-392 | Implement chain detection escalation: configurable action per pattern — `alert` (Kafka event only), `escalate` (trigger human approval via Escalation Manager), `deny_next` (DENY the next tool call in session) | 5 | Backend |
| APEP-393 | Expose chain pattern management API: `GET/POST/DELETE /v1/network/chains`; YAML import/export; pattern simulation against session replay | 3 | Backend |
| APEP-394 | Add chain detection metrics: `chain_detection_total` by pattern_id; `chain_alert_latency` histogram | 2 | Observability |
| APEP-395 | Write adversarial tests: recon chain detected with 2-hop gap tolerance; exfiltration chain triggers DENY_NEXT; benign sequence not flagged; chain simulation in dry-run mode | 5 | Testing |

### Sprint 50 — Kill Switch, Filesystem Sentinel & Adaptive Threat Score

**Goal:** Implement kill switch with 4 independent activation sources; filesystem sentinel for secret monitoring; adaptive per-session threat score integrating network events with authorization events.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-396 | Implement `KillSwitch` service: `activate()` and `deactivate()` methods; when active, all TFN proxy requests return 403 and AgentPEP intercept returns DENY (FAIL_CLOSED override) | 5 | Backend |
| APEP-397 | Implement kill switch activation sources: (1) config flag `kill_switch.active: true`; (2) `SIGUSR1` signal handler via `signal.signal()`; (3) sentinel file watcher via `watchdog`; (4) `POST /v1/network/killswitch` API on isolated port | 5 | Security |
| APEP-398 | Implement kill switch isolated API port: secondary uvicorn server on configurable port (default 9090); `Authorization: Bearer` token auth; agents cannot reach their own kill switch | 3 | Security |
| APEP-399 | Implement `FilesystemSentinel` service: `watchdog` `Observer` monitoring configured directories; scan new/modified files against `NetworkDLPScanner`; emit `SENTINEL_HIT` Kafka event on credential detection | 8 | Security |
| APEP-400 | Implement process lineage attribution on Linux: read `/proc/{pid}/status` for `PPid`; walk process tree from watchdog file event PID to find agent ancestor; include agent_id in SENTINEL_HIT event | 5 | Security |
| APEP-401 | Implement `AdaptiveThreatScore`: per-session score aggregating AgentPEP risk decisions + TFN network events; domain burst detection (N requests to same domain in window); auto-escalation when score crosses configurable threshold | 5 | Backend |
| APEP-402 | Implement de-escalation timer: adaptive threat score decays over time when no new signals arrive; configurable half-life; score resets on session end | 3 | Backend |
| APEP-403 | Write integration tests: kill switch blocks all proxy requests; SIGUSR1 activates in-process; file with API key triggers SENTINEL_HIT; domain burst → adaptive escalation | 5 | Testing |

### Sprint 51 — Rule Bundles, Security Assessment & Network Audit Events

**Goal:** Implement Ed25519-signed community rule bundles; build `ToolTrust assess`-equivalent security assessment; finalize MITRE ATT&CK event tagging; publish TFN documentation.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-404 | Implement rule bundle format: YAML bundle with `patterns`, `chains`, `blocklist_entries`, `version`, `publisher`; Ed25519 signature over canonical bundle content; reuse existing signing infrastructure (Phase 8, Sprint 32) | 5 | Backend |
| APEP-405 | Implement rule bundle loader: `POST /v1/network/rules/install` accepts bundle YAML; verify Ed25519 signature against trusted keyring; merge patterns into `injection_signatures.py` at runtime | 5 | Backend |
| APEP-406 | Implement security assessment engine: (1) attack simulation — 20 test scenarios against TFN scanner pipeline (DLP, injection, SSRF, tool poisoning, chain detection); (2) config audit — 12 security categories scored 0–100 with letter grade; (3) deployment verification — live probe of all TFN endpoints | 8 | Backend |
| APEP-407 | Implement `GET /v1/network/assess` assessment endpoint: run all 3 assessment stages; return structured report with grade, section scores, top findings, and remediation suggestions | 5 | Backend |
| APEP-408 | Implement MITRE ATT&CK technique mapping: maintain mapping from TFN finding types to ATT&CK technique IDs (T1048 exfiltration, T1059 injection, T1195.002 supply chain, T1071 application layer protocol, T1041 exfil over C2); include in all `NetworkEvent` Kafka messages | 3 | Backend |
| APEP-409 | Add TFN events to Policy Console — Network Events tab: timeline of `NetworkEvent` records by session; filterable by event_type, severity, MITRE technique; correlated with AgentPEP intercept decisions by `decision_id` | 5 | Frontend |
| APEP-410 | Add TFN Prometheus metrics: `tfn_url_scan_total` by result; `tfn_dlp_hits_total` by pattern; `tfn_injection_detections_total`; `tfn_chain_detections_total`; `tfn_kill_switch_activations_total`; Grafana dashboard additions | 3 | Observability |
| APEP-411 | Publish TFN documentation: architecture guide, proxy mode comparison, integration guide for Claude Code / LangGraph / CrewAI, OWASP Agentic AI Top 10 coverage mapping, rule bundle authoring guide | 5 | Docs |

---

## 14.7 Sprint Summary — Phase 10

| Sprint | Name | Phase | Stories |
|---|---|---|---|
| 44 | Network DLP Engine & 11-Layer URL Scanner | Phase 10: TrustFabric Network | 8 |
| 45 | DLP Pre-Scan Hook in Intercept Pipeline | Phase 10: TrustFabric Network | 8 |
| 46 | Fetch Proxy & Multi-Pass Response Injection Scanner | Phase 10: TrustFabric Network | 8 |
| 47 | Forward Proxy (CONNECT Tunneling) & WebSocket Proxy | Phase 10: TrustFabric Network | 8 |
| 48 | MCP Proxy Enhancement: Bidirectional DLP & Tool Poisoning | Phase 10: TrustFabric Network | 8 |
| 49 | Tool Call Chain Detection Engine | Phase 10: TrustFabric Network | 8 |
| 50 | Kill Switch, Filesystem Sentinel & Adaptive Threat Score | Phase 10: TrustFabric Network | 8 |
| 51 | Rule Bundles, Security Assessment & Network Audit Events | Phase 10: TrustFabric Network | 8 |

---

## 14.8 What TFN Builds vs What It Defers

### Built Natively (Sprints 44–51)
11-layer URL scanner · 46 DLP patterns · entropy analysis · SSRF/DNS rebinding protection · fetch proxy · multi-pass response injection scanner (6 normalization passes, 23 patterns) · forward proxy (CONNECT tunneling) · optional TLS interception · WebSocket proxy with DLP/injection scanning · MCP proxy bidirectional enhancement · tool poisoning detection · rug-pull detection · tool call chain detection (10 built-in patterns, gap-tolerant) · kill switch (4 sources, isolated API port) · filesystem sentinel · adaptive per-session threat score · Ed25519-signed rule bundles · security assessment engine (attack simulation + config audit + deployment verification) · MITRE ATT&CK event tagging · Prometheus metrics

### Deferred / Out of Scope
| Capability | Decision |
|---|---|
| **OS-level process sandbox (Landlock/seccomp/namespaces)** | Deferred — Helm NetworkPolicy + container isolation provides equivalent enforcement for enterprise deployments. Python kernel bindings are immature and require `CAP_SYS_ADMIN` which is rarely available in production containers. |
| **Single-binary zero-dependency distribution** | Not applicable — AgentPEP deploys via Docker/Helm; no binary distribution requirement. |
| **BIP-39 seed phrase detection** | Out of scope — cryptocurrency-specific; not relevant to enterprise AI security use cases. |
| **Blockchain address poisoning protection** | Out of scope — DeFi-specific threat model; not in TrustFabric's enterprise focus. |

---

## 14.9 Build vs Integrate Decision

**Recommendation: Build natively (TFN) rather than integrate ToolTrust as a Go sidecar.**

| Factor | TFN (Native Python) | ToolTrust (Go Sidecar) |
|---|---|---|
| **Taint integration** | Direct in-process call to `session_graph_manager` — zero IPC | Requires REST/gRPC call + session correlation over API |
| **Risk scoring enrichment** | DLP findings injected directly into `PolicyEvaluator` pipeline | Requires two-phase evaluation: ToolTrust scan → AgentPEP decision |
| **Kill switch coherence** | Single `activate()` call locks both auth and network layers | Two separate kill switch APIs to coordinate |
| **Deployment complexity** | One Docker image, one Helm chart | Two images, two services, mTLS between them |
| **Injection pattern sync** | One `injection_signatures.py` singleton; zero drift | Two separate pattern libraries that can diverge |
| **Performance overhead** | ~0.5–1ms added to intercept path for DLP pre-scan | ~2–5ms IPC round-trip + deserialization |
| **Scan speed (per URL)** | ~300–500μs (Python asyncio) | ~32μs (Go) — 10–15× faster |
| **Binary scan / entropy** | Full parity | Full parity |
| **Enterprise deployment** | Existing Helm chart extended | Second Helm subchart required |
| **Language boundary** | Eliminated | Permanent Go dependency in Python stack |

**The scan speed difference (300μs vs 32μs) is the only meaningful advantage of keeping ToolTrust as a sidecar.** Given that TFN scanning runs asynchronously outside the intercept critical path, and the existing p99 budget has 5ms headroom from Phase 8, this trade-off strongly favors native Python.

---

## 14.10 Enhancement Summary

| Dimension | Before (v1.2) | After (v1.3 with TrustFabric Network) |
|---|---|---|
| **Security boundary coverage** | Tool-call authorization only | + Network egress: DLP, SSRF, injection, chain detection |
| **DLP patterns** | DataSensitivityScorer: PII/credential heuristics | + 46 named patterns: all major API key formats, OAuth tokens, private keys |
| **Response inspection** | None — developers must manually label external content | Auto-scan every `/v1/fetch` response; auto-taint QUARANTINE on injection |
| **Taint auto-labeling** | SDK `ctx.label()` call required at every ingestion point | Automatic via TFN fetch proxy and DLP pre-scan hook |
| **MCP security** | Authorization check (RBAC + taint) on tool calls | + Bidirectional DLP + tool poisoning + rug-pull detection |
| **Attack sequence detection** | Confused-deputy (per-call) | + Tool call chain detection (session-level, gap-tolerant, 10 patterns) |
| **Emergency response** | Risk-threshold escalation (human approval) | + Kill switch (all-or-nothing network denial, 4 activation sources) |
| **Filesystem monitoring** | None | Filesystem sentinel: DLP scan on agent file writes |
| **Adaptive enforcement** | Static risk thresholds | Session threat score integrating auth + network signals |
| **OWASP Agentic Top 10** | Partial (ASI01, ASI03, ASI07 strong) | Strong coverage across all 10 vectors |
| **Total stories** | ~347 (Sprints 1–43) | **~411** (+ 64 TrustFabric Network stories, Sprints 44–51) |

---

## 14.11 Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| Python scan throughput insufficient at high agent density | High | Low | Async pipeline; DLP result cache (Sprint 45, APEP-361); scan runs outside p99 critical path |
| Forward proxy CONNECT implementation complexity | Medium | Medium | Prototype CONNECT tunnel in Sprint 47 early; asyncio StreamReader/StreamWriter is well-documented |
| TLS interception CA trust installation in enterprise | Medium | Medium | TLS interception is optional; default is hostname-level scanning; CA install guide in docs |
| Kill switch isolated port blocked by enterprise firewall | Low | Medium | Kill switch also activates via SIGUSR1 and sentinel file — network-independent paths |
| Filesystem sentinel `watchdog` performance on large codebases | Medium | Low | Configure watched paths explicitly; DLP scan only on new/modified files, not full tree rescans |
| Tool call chain detection false positives on legitimate workflows | High | Medium | Conservative default gap tolerance (2); configurable per pattern; audit mode available; simulation before enforcement |

---

## 14.12 Success Metrics — Phase 10

| Metric | Target | Measurement Method |
|---|---|---|
| URL scanner latency (11 layers, Python) | < 1ms p99 | Prometheus histogram |
| DLP pre-scan intercept latency impact | ≤ 2ms additional on p99 | Prometheus histogram delta |
| Response injection detection rate | > 95% against ToolTrust's published test matrix | Adversarial test suite (APEP-371) |
| Tool call chain detection false positive rate | < 1% on benign agent workflows | Production traffic sampling |
| Fetch proxy throughput | > 500 concurrent fetches/sec | k6 load test |
| Kill switch activation to full block latency | < 100ms | Activation timestamp delta |
| TFN auto-taint coverage | 100% of `/v1/fetch` responses taint-labeled | Audit completeness check |
| OWASP Agentic Top 10 coverage (post-TFN) | ≥ 8/10 Strong or Moderate | docs/owasp-mapping.md assessment |
| Security assessment accuracy | > 90% finding agreement with manual audit | Beta security review |

---

*AgentPEP · TrustFabric Portfolio · Confidential · © 2026*

---

# 15. ToolTrust-Inspired Roadmap v4: ML Injection Detection & Content Ingestion Security

## 15.1 Overview

This section documents enhancements to AgentPEP inspired by analysis of [Shivapas/ToolTrust](https://github.com/Shivapas/ToolTrust) — a Python library that guards AI coding agents from prompt injection attacks in untrusted content (cloned repositories, PRs, tool output, MCP responses). ToolTrust introduces two capabilities uniquely absent from the entire TrustFabric stack: a **pre-session repository scanner** (checks content before the agent starts) and an **ONNX semantic injection classifier** (fine-tuned MiniLM-L6-v2, 94.3% F1) that detects injection evasions that regex cannot touch.

**Reference:** [Shivapas/ToolTrust](https://github.com/Shivapas/ToolTrust) — forked from prodnull/ToolTrust. Python 3.11+, Apache 2.0.
**Analysis Date:** April 2026
**Scope:** 5 sprints (Sprints 52-56) · 40 stories · ~10 weeks

---

## 15.2 ToolTrust Architecture Summary

ToolTrust operates across four hook layers and three detection tiers:

```
Layer 0  Pre-execution wrapper    Scans entire repo before agent starts (~50ms)
Layer 1  InstructionsLoaded       Scans CLAUDE.md / .cursorrules / AGENTS.md on load
Layer 2  PostToolUse              Scans every tool output for injection after execution
Layer 3  PreToolUse               Gates writes, builds, and config changes before execution

Tier 0   204 compiled regex       25 categories, ~50ms total, 91% precision / 23% recall
Tier 1.5 ONNX MiniLM-L6-v2       94.3% F1 (5-fold CV), 16ms/sample, no external deps
Tier 2   Ollama LLM fallback      General-purpose; slower; used only without ONNX
```

**Combined pipeline performance (185 adversarial + 234 benign):**

| Metric | Tier 0 (regex) | Tier 1.5 (ONNX) | Combined |
|---|---|---|---|
| Recall | 31.9% | 78.4% | **80.5%** |
| False block rate | — | — | **3.8%** |
| F1 | 37.1% | **94.3%** | — |

**CaMeL-lite behavioural monitor:** 5 SEQ rules using session-wide typed markers. SEQ-001/002 enforce (file read to external exfil); SEQ-003-005 advisory or config-write enforcement. Gap-tolerant: padding with benign events does not evade detection.

---

## 15.3 Gap Analysis: ToolTrust Capabilities vs AgentPEP

| # | ToolTrust Capability | AgentPEP Current State | Gap | Priority |
|---|---|---|---|---|
| 1 | **ONNX semantic injection classifier** — fine-tuned MiniLM-L6-v2, 94.3% F1, catches synonym substitution, homoglyphs, encoding evasion | injection_signatures.py: regex only, ~37% F1 on adversarial payloads | **Critical** | P0 |
| 2 | **204 injection patterns across 25 categories** — validated against Mindgard AI IDE vulnerability taxonomy (20/22 patterns) | ~30 patterns in injection_signatures.py across 5 categories | **Major** | P0 |
| 3 | **Pre-session repository scanner (Layer 0)** — scans all repo files in <50ms before agent launches | No pre-session content scan; scanning begins only at tool-call time | **Major** | P0 |
| 4 | **Agent instruction file scanner (Layer 1)** — dedicated STRICT-mode scanner for CLAUDE.md, .cursorrules, AGENTS.md | No dedicated scanner for agent instruction files | **Major** | P0 |
| 5 | **PostToolUse auto-scan (Layer 2)** — scans all tool output for injection after execution; auto-escalates if detected | Taint labeling requires developer ctx.label() call; no automatic post-tool scan | **Major** | P0 |
| 6 | **CaMeL-lite SEQ rules** — 5 behavioural sequence rules including enforcing (file read to exfil); session-wide typed markers; gap-tolerant | Tool call chain detection (Phase 10) lacks coding-agent-specific patterns | **Moderate** | P1 |
| 7 | **YOLO mode detection and risk escalation** — detects --dangerously-skip-permissions; escalates MEDIUM to HIGH findings | No session-level agent operating-mode awareness; risk thresholds are static | **Moderate** | P1 |
| 8 | **Scan modes (STRICT / STANDARD / LENIENT)** — per-file-type detection thresholds with mode-restricted patterns | No per-context scan mode; all evaluation uses same thresholds | **Moderate** | P1 |
| 9 | **Trust cache** — SHA-256 file hash cache outside repo; skip re-scanning unchanged files; tamper-proof | DLP pre-scan cache (APEP-361) covers tool args; no file-level trust cache | **Moderate** | P1 |
| 10 | **Self-protection against agent-initiated policy modification** — CLI guard (TTY check) + hook guard (blocks ToolTrust allow commands) | Policy immutability via audit trail; no active block on agent-initiated modification | **Moderate** | P1 |
| 11 | **Allowlist by content hash** — reviewed false-positive files allowlisted by SHA-256 hash; invalidated by any content change | No content-hash-based allowlisting for injection scan results | **Minor** | P2 |
| 12 | **Layer 3 to Intercept API bridge** — ToolTrust Layer 3 PreToolUse calling AgentPEP Intercept API; scan verdict passed as taint signal | No integration bridge; the two tools operate independently | **Minor** | P2 |

---

## 15.4 Architecture: Content Ingestion Security Layer

The ToolTrust-inspired enhancements add a **Content Ingestion Security (CIS)** layer operating before and during agent sessions to inspect content entering the agent context.

```
External repo / PR / MCP response / tool output
         |
         v
[Content Ingestion Security Layer - NEW Phase 11]
  Pre-Session Scanner    POST /v1/cis/scan-repo
  File Scanner           POST /v1/cis/scan-file
  Text Scanner           POST /v1/cis/scan-text
         |
  Multi-Tier Scanner Pipeline:
    Tier 0: InjectionSignatureLibrary (204 patterns, 25 categories)
    Tier 1: ONNXSemanticClassifier (MiniLM-L6-v2, 94.3% F1)
    Tier 2: LLM fallback (optional)
         |
  Auto-Taint Bridge
    scan result -> session_graph_manager.label(QUARANTINE)
    No developer ctx.label() call required
         |
         v
[Existing PolicyEvaluator - Phases 1-10]
  RBAC, Taint, Confused-Deputy, Risk Scoring, TFN DLP
```

---

## 15.5 New Data Models

### CISScanRequest

| Field | Type | Description |
|---|---|---|
| scan_target | Enum: file/directory/text/tool_output | What to scan |
| path | String? | File or directory path |
| content | String? | Text content to scan |
| session_id | String? | Associate result with session for auto-taint |
| agent_id | String? | Agent context for scan mode selection |
| scan_mode | Enum: STRICT/STANDARD/LENIENT | Override default mode |
| tiers | Integer[] | Which tiers to run: [0], [0,1], [0,1,2] |
| use_cache | Boolean | Whether to use trust cache (default: true) |

### CISScanResult

| Field | Type | Description |
|---|---|---|
| allowed | Boolean | Whether content passed all active tiers |
| findings | CISFinding[] | Ordered list of findings from all tiers |
| tier_results | TierResult[] | Per-tier outcome: CLEAN/SUSPICIOUS/MALICIOUS |
| scan_mode | Enum | Mode applied to this scan |
| taint_assigned | TaintLevel? | Taint level assigned if session_id provided |
| cache_hit | Boolean | Whether result came from trust cache |
| files_scanned | Integer | Number of files scanned (for directory scans) |
| latency_ms | Integer | Total scan latency |

### New Scan Modes

| Mode | Applied To | ONNX Suspicious Threshold | ONNX Malicious Threshold | Enforcement |
|---|---|---|---|---|
| **STRICT** | CLAUDE.md, .cursorrules, AGENTS.md, MCP tool descriptions | 0.50 | 0.80 | QUARANTINE on any HIGH finding |
| **STANDARD** | README.md, package.json, Makefile, tool output | 0.65 | 0.88 | QUARANTINE on CRITICAL; UNTRUSTED on HIGH |
| **LENIENT** | Test files, fixtures, documentation | 0.75 | 0.92 | UNTRUSTED on CRITICAL only |

---

## 15.6 Detailed Sprint Plans - Phase 11: ToolTrust-Inspired Roadmap v4

### Sprint 52 - Extended Pattern Library & Scan Mode Router

**Goal:** Expand injection_signatures.py from ~30 to 204 patterns across 25 categories; implement ScanModeRouter with per-category mode restrictions; add content-hash trust cache and allowlist.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-412 | Expand injection_signatures.py with 204 patterns across all 25 ToolTrust categories: instruction override (IO), authority impersonation (AI), behavioral manipulation (BM), privilege escalation (PE), encoding obfuscation (EO), unicode anomalies (UA), exfiltration (EX), credential harvesting (CH), environment variable hijacking (EV), build script attacks (BS) | 8 | Security |
| APEP-413 | Add remaining 15 pattern categories: CI/CD poisoning (CI), config file injection (CF), git hook exploitation (GH), MCP tool poisoning (MCP), reasoning hijack (RH), markdown/SVG injection (MS), terminal escape (TE), memory poisoning (MP), viral propagation (VP), dangerous agent flags (DF), symlink/path traversal (ST), process environment (PR), WSL cross-boundary (WSL), workspace config execution (WC), dedicated config file scanners (.claude/settings.json, .env, devcontainer.json) | 8 | Security |
| APEP-414 | Implement ScanModeRouter: given file path and extension, determine STRICT/STANDARD/LENIENT mode; apply per-category mode restrictions (CI-001, CI-004, CI-006, SC-001, MCP-005 restricted to STRICT); expose mode override via CISScanRequest.scan_mode | 5 | Backend |
| APEP-415 | Implement CISTrustCache: SHA-256 content hash cache stored in MongoDB collection cis_trust_cache outside agent-writable paths; TTL-indexed; keyed by {repo_root}:{relative_path}:{pattern_version}; skip rescan on cache hit | 5 | Backend |
| APEP-416 | Implement CISAllowlist: content-hash-based false-positive allowlist; POST /v1/cis/allowlist requires authenticated console user (not agent API key); agent-initiated allowlist modification blocked at middleware level | 5 | Security |
| APEP-417 | Implement YOLO mode detector: inspect AgentProfile.session_flags for dangerously_skip_permissions; when active, apply risk score multiplier (1.5x) in PolicyEvaluator and lower ESCALATE threshold by 0.15; CIS scanner automatically upgrades to STRICT mode | 5 | Security |
| APEP-418 | Write pattern validation tests: all 204 patterns tested against known-malicious payloads from ToolTrust test suite; false-positive rate measured against benign corpus of 1,000 real repo files | 5 | Testing |
| APEP-419 | Update injection_signatures.py hot-reload to support 204-pattern corpus without restart; version-stamp pattern set for trust cache invalidation | 3 | Backend |

### Sprint 53 - ONNX Semantic Injection Classifier (Tier 1)

**Goal:** Integrate ONNX MiniLM-L6-v2 classifier as ONNXSemanticClassifier; wire as Tier 1 in CIS scanner pipeline; benchmark against ToolTrust published F1 metrics; implement graceful fallback.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-420 | Implement ONNXSemanticClassifier service: load fine-tuned MiniLM-L6-v2 ONNX model (onnxruntime dependency); tokenize with tokenizers library; run inference; return (suspicious_score, malicious_score) float pair | 8 | Backend |
| APEP-421 | Implement model download and SHA-256 verification: POST /v1/cis/model/install downloads model from configurable registry URL; verifies SHA-256 before loading; air-gapped deployments can mount model at /opt/agentpep/models/ | 5 | Backend |
| APEP-422 | Implement per-mode ONNX classification thresholds: STRICT (0.50/0.80), STANDARD (0.65/0.88), LENIENT (0.75/0.92); classify text chunk as CLEAN/SUSPICIOUS/MALICIOUS based on mode thresholds | 5 | Backend |
| APEP-423 | Implement text chunking for long content: split content into overlapping 512-token windows (MiniLM context limit); aggregate scores via max-pool; handles large files without truncation | 5 | Backend |
| APEP-424 | Implement model-absent graceful fallback: when ONNX model not installed, CIS pipeline runs Tier 0 only; log TIER1_UNAVAILABLE warning metric; never fail closed due to missing model | 3 | Backend |
| APEP-425 | Implement async batch inference: queue text chunks for batched ONNX inference (batch size 16); asyncio task pool; avoid blocking intercept API path | 5 | Performance |
| APEP-426 | Benchmark ONNX classifier against ToolTrust published metrics: reproduce 5-fold CV on prodnull/prompt-injection-repo-dataset; verify >=94% F1; document results in docs/cis-benchmark.md | 5 | Testing |
| APEP-427 | Add ONNX inference Prometheus metrics: cis_tier1_latency_ms histogram; cis_tier1_malicious_total; cis_tier1_unavailable_total; model version in /metrics info gauge | 2 | Observability |

### Sprint 54 - Pre-Session Repository Scanner & Agent Instruction File Scanner

**Goal:** Build POST /v1/cis/scan-repo pre-session scanner; implement agent instruction file scanner with STRICT mode defaults; wire scan results to taint auto-labeling; build CIS findings screen in Policy Console.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-428 | Implement POST /v1/cis/scan-repo: accepts directory path or archive upload; walks all files; applies ScanModeRouter per file; runs Tier 0 + Tier 1 pipeline; returns aggregated CISScanResult with per-file findings; streams progress via WebSocket | 8 | Backend |
| APEP-429 | Implement agent instruction file scanner: dedicated STRICT-mode scan for CLAUDE.md, .cursorrules, AGENTS.md, .junie/guidelines.md, .claude/settings.json, codex.json, .gemini/settings.json, devcontainer.json; run on InstructionsLoaded event equivalent | 5 | Security |
| APEP-430 | Implement scan-on-session-start hook: when new AgentPEP session created, optionally trigger async CIS repo scan of configured working_directory; block session activation until scan completes if require_clean_repo: true in AgentProfile | 5 | Backend |
| APEP-431 | Implement PostToolUse auto-scan: after any tool call returns ALLOW, extract tool result content from audit record; submit to CISScanRequest with scan_target=tool_output; if MALICIOUS finding -> auto-label QUARANTINE in session taint graph (no developer action required) | 8 | Security |
| APEP-432 | Implement POST /v1/cis/scan-file and POST /v1/cis/scan-text: single-file and arbitrary-text variants; same pipeline; returns CISScanResult; used by SDK cis_scan() helper | 3 | Backend |
| APEP-433 | Build CIS Findings screen in Policy Console: list of CIS scan results by session; per-file finding tree; severity heat-map; trust cache status; allowlist management UI (requires console admin role) | 8 | Frontend |
| APEP-434 | Add SDK cis_scan(path_or_text) helper: wraps POST /v1/cis/scan-file and POST /v1/cis/scan-text; returns CISScanResult; auto-registers taint label on current session if session_id provided | 3 | SDK |
| APEP-435 | Write adversarial tests: base64-encoded injection in repo file caught by Tier 0; synonym-substituted injection caught only by Tier 1; CLAUDE.md with privilege escalation blocked in STRICT mode; clean README passes LENIENT mode | 5 | Testing |

### Sprint 55 - CaMeL SEQ Rules, Layer 3 Bridge & Self-Protection

**Goal:** Import ToolTrust CaMeL-lite SEQ rules into Phase 10 tool call chain detector; build ToolTrust Layer 3 to AgentPEP Intercept bridge; implement agent-initiated policy modification self-protection.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-436 | Import ToolTrust CaMeL-lite SEQ rules as named chain patterns in Phase 10 ToolCallChainDetector (APEP-388): SEQ-001 (read sensitive file -> WebFetch external), SEQ-002 (read sensitive file -> Bash curl/wget external), SEQ-005 (write agent/IDE config file) as enforcing; SEQ-003 (MCP frequency spike) and SEQ-004 (write build target -> build) as advisory | 5 | Security |
| APEP-437 | Implement session-wide typed marker system for SEQ-001/002: marker set when any read_file tool operates on sensitive path patterns (.env, *secret*, *credential*, *.pem, .npmrc); marker persists across arbitrary intervening tool calls; gap-tolerant | 5 | Backend |
| APEP-438 | Implement ToolTrust -> AgentPEP Intercept bridge: agentpep-sdk module ToolTrustBridge that ToolTrust Layer 3 hook calls instead of making its own block decision; bridge submits ToolCallRequest to AgentPEP Intercept API; passes ToolTrust CIS scan verdict as taint signal; returns exit code 0/2 based on AgentPEP decision | 8 | SDK |
| APEP-439 | Implement CIS scan verdict as taint input: extend ToolCallRequest with optional cis_pre_scan_result: CISScanResult; PolicyEvaluator reads this field; if MALICIOUS finding present, auto-assign QUARANTINE to all tool args; if SUSPICIOUS, assign UNTRUSTED | 5 | Backend |
| APEP-440 | Implement agent-initiated policy modification self-protection: add PolicyModificationGuard middleware; detect tool calls targeting AgentPEP API endpoints (/v1/policies, /v1/cis/allowlist, /v1/plans, /v1/network/killswitch); require console user JWT (not agent API key) for any modification; return DENY with SELF_MODIFICATION_BLOCKED | 5 | Security |
| APEP-441 | Implement protected path patterns for PreToolUse: configure set of protected paths (~/.claude/settings.json, AgentPEP config files, CIS allowlist location); any tool call writing to protected paths -> DENY with PROTECTED_PATH_WRITE | 3 | Security |
| APEP-442 | Write self-protection adversarial tests: agent attempts ToolTrust allow equivalent via Bash tool -> blocked; agent attempts to call AgentPEP policy modification API with agent key -> blocked; agent attempts to write to .claude/settings.json -> DENY | 5 | Testing |
| APEP-443 | Write ToolTrust bridge integration test: simulate ToolTrust Layer 3 hook calling AgentPEP Intercept API; verify CIS scan verdict propagated as taint; verify exit code matches AgentPEP decision | 3 | Testing |

### Sprint 56 - YOLO Mode, Session Risk Multiplier & Developer Experience

**Goal:** Finalise YOLO mode session risk escalation; build per-session scan mode configuration; publish CIS documentation and integration guides; add CIS metrics to Grafana dashboard.

| Story ID | Description | Points | Area |
|---|---|---|---|
| APEP-444 | Implement per-session scan mode configuration: AgentProfile.default_scan_mode sets baseline; session-level override via POST /v1/sessions/{id}/scan-mode; scan mode inherited by all CIS scans in session | 3 | Backend |
| APEP-445 | Implement YOLO mode session flag propagation: when SDK detects --dangerously-skip-permissions in agent launch args, set session.yolo_mode=true; PolicyEvaluator applies 1.5x risk multiplier and -0.15 ESCALATE threshold reduction; CIS scanner automatically upgrades to STRICT mode | 5 | Security |
| APEP-446 | Implement YOLO mode detection via environment probe: SDK @enforce decorator checks os.environ for YOLO indicators at session init; also detectable by parsing AgentProfile.launch_args if provided | 3 | SDK |
| APEP-447 | Build CIS Dashboard widget in Policy Console: repo scan history timeline; Tier 0/1/2 finding breakdown; trust cache hit rate; top attack categories detected; YOLO-mode sessions highlighted | 5 | Frontend |
| APEP-448 | Add CIS scan results to compliance exports: DPDPA and CERT-In compliance reports include CIS scan history, QUARANTINE assignments from PostToolUse auto-scan, and pre-session scan results per agent session | 3 | Backend |
| APEP-449 | Add CIS Prometheus metrics: cis_repo_scans_total; cis_files_scanned_total; cis_findings_total by tier/category/severity; cis_auto_quarantine_total; cis_trust_cache_hits_total; cis_yolo_sessions_total; extend Grafana dashboard | 3 | Observability |
| APEP-450 | Publish CIS documentation: architecture guide, scan mode reference, ONNX model installation guide (online + air-gapped), ToolTrust bridge integration guide for Claude Code / Cursor / Gemini CLI, false-positive management guide | 3 | Docs |
| APEP-451 | Write CIS end-to-end integration test: clone repo containing injected CLAUDE.md -> pre-session scan blocks session; clean repo -> session allowed; PostToolUse auto-QUARANTINE propagates to subsequent tool call DENY | 5 | Testing |

---

## 15.7 Sprint Summary - Phase 11

| Sprint | Name | Phase | Stories |
|---|---|---|---|
| 52 | Extended Pattern Library & Scan Mode Router | Phase 11: ToolTrust-Inspired v4 | 8 |
| 53 | ONNX Semantic Injection Classifier (Tier 1) | Phase 11: ToolTrust-Inspired v4 | 8 |
| 54 | Pre-Session Repository Scanner & Instruction File Scanner | Phase 11: ToolTrust-Inspired v4 | 8 |
| 55 | CaMeL SEQ Rules, Layer 3 Bridge & Self-Protection | Phase 11: ToolTrust-Inspired v4 | 8 |
| 56 | YOLO Mode, Session Risk Multiplier & Developer Experience | Phase 11: ToolTrust-Inspired v4 | 8 |

---

## 15.8 Enhancement Summary

| Dimension | Before (v1.3) | After (v1.4 with ToolTrust Enhancements) |
|---|---|---|
| **Injection pattern coverage** | ~30 patterns, 5 categories, regex only | 204 patterns, 25 categories — validated against Mindgard AI IDE taxonomy |
| **Injection detection accuracy** | ~37% F1 on adversarial payloads (regex) | **94.3% F1** — ONNX semantic classifier |
| **Pre-session scanning** | None — scanning starts at first tool call | Pre-session repo scan: all files checked before agent launches |
| **Agent instruction file security** | Injection signatures applied uniformly | Dedicated STRICT-mode scanner for CLAUDE.md, .cursorrules, .claude/settings.json |
| **PostToolUse auto-taint** | Developer must call ctx.label() at every ingestion point | Automatic: every tool output scanned; QUARANTINE assigned without developer action |
| **Tool call chain patterns** | 10 enterprise patterns (Phase 10) | + 5 CaMeL-lite SEQ rules (coding-agent-specific) |
| **Agent operating mode awareness** | Static risk thresholds | YOLO mode detection: 1.5x risk multiplier + STRICT scan mode auto-applied |
| **Self-protection** | Policy audit trail | Active block: agent API key cannot modify policies, allowlists, or protected paths |
| **Developer integration** | SDK @enforce decorator, taint labeling | + cis_scan() helper, ToolTrust bridge adapter, pre-session scan hook |
| **Total stories** | ~411 (Sprints 1-51) | **~451** (+ 40 ToolTrust stories, Sprints 52-56) |

---

## 15.9 Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| ONNX model 87MB increases Docker image significantly | Low | High | Optional install via POST /v1/cis/model/install; base image ships Tier 0 only; model mountable at /opt/agentpep/models/ |
| False positive rate on security documentation READMEs | High | High | CISAllowlist by content hash; LENIENT mode for documentation paths; ToolTrust validates 3.8% false block rate |
| ONNX inference latency adds to PostToolUse path | Medium | Medium | Async batch inference (APEP-425); PostToolUse scan decoupled via background queue |
| require_clean_repo: true blocks legitimate sessions | Medium | Medium | Default false; audit mode available; per-path scan mode exceptions configurable |
| YOLO mode 1.5x multiplier produces excessive ESCALATE volume | Medium | Medium | Multiplier configurable per tenant; approval memory (Phase 9) reduces repeat escalations |
| CaMeL SEQ-001/002 enforcing rules false-positive on legitimate workflows | High | Medium | Domain-level allowlisting for SEQ-001/002; dry-run simulation before enabling enforcement |

---

## 15.10 Success Metrics - Phase 11

| Metric | Target | Measurement Method |
|---|---|---|
| Injection pattern coverage (Tier 0) | >=204 patterns, >=20/22 Mindgard taxonomy patterns | Pattern inventory audit |
| ONNX classifier F1 (cross-validated) | >=94% F1 on prodnull/prompt-injection-repo-dataset | Benchmark reproduction (APEP-426) |
| Pre-session repo scan latency | <100ms for repos <=1,000 files (Tier 0 only) | k6 benchmark |
| PostToolUse auto-QUARANTINE coverage | 100% of tool results containing injection patterns auto-tagged | Audit completeness check |
| False block rate (benign repo files) | <=5% (ToolTrust validated 3.8%) | Benign corpus evaluation |
| YOLO mode risk multiplier accuracy | 0 YOLO-mode sessions escape STRICT scan mode | Session flag audit |
| Self-protection bypass rate | 0 agent-initiated policy modifications succeed with agent API key | Adversarial test suite (APEP-442) |
| ToolTrust bridge integration latency | <50ms additional over standalone Layer 3 hook decision | SDK benchmark |

---

*AgentPEP · TrustFabric Portfolio · Confidential · © 2026*
