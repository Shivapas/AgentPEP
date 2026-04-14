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
| **Sprint Count** | 56 Sprints (Sprints 36–56 decomposed into 231 sub-sprints) · ~28 Months |
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
| 36 | ToolTrust — Conflict Detection, Metrics, Tamper Detection & Multi-Tenancy | Phase 8: ToolTrust Roadmap v1 | 7 stories → 11 sub-sprints |

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

#### Sub-Sprint 36.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 36 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-285.a | APEP-285 | Design security architecture and threat model for HashChainedContext | 1 | Security |
| APEP-286.a | APEP-286 | Design data model and interface for TrustDegradationEngine | 1 | Backend |
| APEP-287.a | APEP-287 | Design data model and interface for DEFER decision type | 1 | Backend |
| APEP-288.a | APEP-288 | Design data model and interface for STEP_UP decision type | 1 | Backend |
| APEP-289.a | APEP-289 | Design data model and interface for policy conflict detection | 1 | Backend |
| APEP-290.a | APEP-290 | Design security model and threat surface for multi-tenancy data isolation | 1 | Security |
| APEP-291.a | APEP-291 | Design metrics schema and dashboard layout for Prometheus metrics for all new capabilities | 1 | Observability |

#### Sub-Sprint 36.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 36 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-285.b | APEP-285 | Define data model and schema for HashChainedContext | 1 | Backend |
| APEP-286.b | APEP-286 | Implement Pydantic model and MongoDB schema for TrustDegradationEngine | 1 | Backend |
| APEP-287.b | APEP-287 | Implement Pydantic model and MongoDB schema for DEFER decision type | 1 | Backend |
| APEP-288.b | APEP-288 | Implement Pydantic model and MongoDB schema for STEP_UP decision type | 1 | Backend |
| APEP-289.b | APEP-289 | Implement Pydantic model and MongoDB schema for policy conflict detection | 1 | Backend |

#### Sub-Sprint 36.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for HashChainedContext; TrustDegradationEngine; DEFER decision type.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-285.c | APEP-285 | Implement core security logic: HashChainedContext | 2 | Security |
| APEP-286.c | APEP-286 | Implement core business logic: TrustDegradationEngine | 1 | Backend |
| APEP-287.c | APEP-287 | Implement core business logic: DEFER decision type | 1 | Backend |

#### Sub-Sprint 36.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for STEP_UP decision type; policy conflict detection; multi-tenancy data isolation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-288.c | APEP-288 | Implement core business logic: STEP_UP decision type | 1 | Backend |
| APEP-289.c | APEP-289 | Implement core business logic: policy conflict detection | 1 | Backend |
| APEP-290.b | APEP-290 | Implement core security logic: multi-tenancy data isolation | 1 | Security |

#### Sub-Sprint 36.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 36 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-286.d | APEP-286 | Wire API endpoint and service layer for TrustDegradationEngine | 1 | Backend |
| APEP-287.d | APEP-287 | Wire API endpoint and service layer for DEFER decision type | 1 | Backend |
| APEP-288.d | APEP-288 | Wire API endpoint and service layer for STEP_UP decision type | 1 | Backend |
| APEP-289.d | APEP-289 | Wire API endpoint and service layer for policy conflict detection | 1 | Backend |

#### Sub-Sprint 36.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 36.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-285.d | APEP-285 | Implement security guards and crypto: HashChainedContext | 1 | Security |
| APEP-290.c | APEP-290 | Implement security guards and validation: multi-tenancy data isolation | 1 | Security |

#### Sub-Sprint 36.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 36 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-285.e | APEP-285 | Integrate into enforcement pipeline: HashChainedContext | 1 | Security |
| APEP-290.d | APEP-290 | Integrate into enforcement pipeline: multi-tenancy data isolation | 1 | Security |

#### Sub-Sprint 36.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 36 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S36.8 | — | Update SDK documentation and CLI help text for Sprint 36 | 0 | SDK |

#### Sub-Sprint 36.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 36 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-285.f | APEP-285 | Write unit tests for HashChainedContext | 1 | Testing |
| APEP-286.e | APEP-286 | Write unit tests for TrustDegradationEngine | 1 | Testing |
| APEP-287.e | APEP-287 | Write unit tests for DEFER decision type | 1 | Testing |
| APEP-288.e | APEP-288 | Write unit tests for STEP_UP decision type | 1 | Testing |
| APEP-289.e | APEP-289 | Write unit tests for policy conflict detection | 1 | Testing |
| APEP-290.e | APEP-290 | Write security validation tests for multi-tenancy data isolation | 1 | Testing |

#### Sub-Sprint 36.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 36.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-285.g | APEP-285 | Write adversarial tests for HashChainedContext | 1 | Testing |

#### Sub-Sprint 36.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 36 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-291.b | APEP-291 | Implement Prometheus metrics and Grafana dashboards: Prometheus metrics for all new capabilities | 2 | Observability |


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
| **Total stories** | ~224 (Sprints 1–28) | ~291 (+ 67 ToolTrust enhancement stories; Sprint 36 decomposed into 11 sub-sprints) |

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

#### Sub-Sprint 37.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 37 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-292.a | APEP-292 | Design data model and interface for MissionPlan Pydantic model with all fields; add Mon | 1 | Backend |
| APEP-293.a | APEP-293 | Design security architecture and threat model for Ed25519 plan signing using PyNaCl | 1 | Security |
| APEP-294.a | APEP-294 | Design data model and interface for POST /v1/plans — create and issue a signed plan; | 1 | Backend |
| APEP-295.a | APEP-295 | Design data model and interface for GET /v1/plans/{plan_id} — retrieve plan with bud | 1 | Backend |
| APEP-296.a | APEP-296 | Design data model and interface for DELETE /v1/plans/{plan_id} — revoke plan (sets s | 1 | Backend |
| APEP-297.a | APEP-297 | Design data model and interface for plan-session binding | 1 | Backend |
| APEP-298.a | APEP-298 | Design data model and interface for plan TTL expiry background job | 1 | Backend |

#### Sub-Sprint 37.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 37 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-292.b | APEP-292 | Implement Pydantic model and MongoDB schema for MissionPlan Pydantic model with all fields; add Mon | 1 | Backend |
| APEP-293.b | APEP-293 | Define data model and schema for Ed25519 plan signing using PyNaCl | 1 | Backend |
| APEP-294.b | APEP-294 | Implement Pydantic model and MongoDB schema for POST /v1/plans — create and issue a signed plan; | 1 | Backend |
| APEP-296.b | APEP-296 | Implement Pydantic model and MongoDB schema for DELETE /v1/plans/{plan_id} — revoke plan (sets s | 1 | Backend |
| APEP-297.b | APEP-297 | Implement Pydantic model and MongoDB schema for plan-session binding | 1 | Backend |

#### Sub-Sprint 37.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for MissionPlan Pydantic model with all field; Ed25519 plan signing using PyNaCl; POST /v1/plans — create and issue a si.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-292.c | APEP-292 | Implement core business logic: MissionPlan Pydantic model with all fields; add Mon | 1 | Backend |
| APEP-293.c | APEP-293 | Implement core security logic: Ed25519 plan signing using PyNaCl | 2 | Security |
| APEP-294.c | APEP-294 | Implement core business logic: POST /v1/plans — create and issue a signed plan; | 1 | Backend |
| APEP-295.b | APEP-295 | Implement core logic: GET /v1/plans/{plan_id} — retrieve plan with bud | 1 | Backend |

#### Sub-Sprint 37.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for DELETE /v1/plans/{plan_id} — revoke pl; plan-session binding; plan TTL expiry background job.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-296.c | APEP-296 | Implement core business logic: DELETE /v1/plans/{plan_id} — revoke plan (sets s | 1 | Backend |
| APEP-297.c | APEP-297 | Implement core business logic: plan-session binding | 1 | Backend |
| APEP-298.b | APEP-298 | Implement core logic: plan TTL expiry background job | 1 | Backend |

#### Sub-Sprint 37.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 37 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-292.d | APEP-292 | Wire API endpoint and service layer for MissionPlan Pydantic model with all fields; add Mon | 1 | Backend |
| APEP-294.d | APEP-294 | Wire API endpoint and service layer for POST /v1/plans — create and issue a signed plan; | 1 | Backend |
| APEP-296.d | APEP-296 | Wire API endpoint and service layer for DELETE /v1/plans/{plan_id} — revoke plan (sets s | 1 | Backend |
| APEP-297.d | APEP-297 | Wire API endpoint and service layer for plan-session binding | 1 | Backend |

#### Sub-Sprint 37.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 37.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-293.d | APEP-293 | Implement security guards and crypto: Ed25519 plan signing using PyNaCl | 1 | Security |

#### Sub-Sprint 37.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 37 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-293.e | APEP-293 | Integrate into enforcement pipeline: Ed25519 plan signing using PyNaCl | 1 | Security |

#### Sub-Sprint 37.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 37 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S37.8 | — | Update SDK documentation and CLI help text for Sprint 37 | 0 | SDK |

#### Sub-Sprint 37.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 37 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-292.e | APEP-292 | Write unit tests for MissionPlan Pydantic model with all fields; add Mon | 1 | Testing |
| APEP-293.f | APEP-293 | Write unit tests for Ed25519 plan signing using PyNaCl | 1 | Testing |
| APEP-294.e | APEP-294 | Write unit tests for POST /v1/plans — create and issue a signed plan; | 1 | Testing |
| APEP-295.c | APEP-295 | Write unit tests for GET /v1/plans/{plan_id} — retrieve plan with bud | 1 | Testing |
| APEP-296.e | APEP-296 | Write unit tests for DELETE /v1/plans/{plan_id} — revoke plan (sets s | 1 | Testing |
| APEP-297.e | APEP-297 | Write unit tests for plan-session binding | 1 | Testing |
| APEP-298.c | APEP-298 | Write unit tests for plan TTL expiry background job | 1 | Testing |
| APEP-299.a | APEP-299 | Write unit and component tests: integration tests | 2 | Testing |

#### Sub-Sprint 37.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 37.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-293.g | APEP-293 | Write adversarial tests for Ed25519 plan signing using PyNaCl | 1 | Testing |
| APEP-299.b | APEP-299 | Write integration and adversarial tests: integration tests | 3 | Testing |

#### Sub-Sprint 37.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 37 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S37.11 | — | Sprint 37 documentation and deliverable validation | 0 | Docs |

---

### Sprint 38 — Scope Pattern Language & DSL Compiler

**Goal:** Implement `verb:namespace:resource` scope notation; build pattern compiler that maps scope patterns to RBAC tool-name globs; integrate scope matching into PolicyEvaluator.

#### Sub-Sprint 38.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 38 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-300.a | APEP-300 | Design data model and interface for and document scope pattern syntax | 1 | Backend |
| APEP-301.a | APEP-301 | Design data model and interface for ScopePatternParser | 1 | Backend |
| APEP-302.a | APEP-302 | Design architecture and interfaces for ScopePatternCompiler | 1 | Backend |
| APEP-303.a | APEP-303 | Design data model and interface for scope matching in PlanCheckpointFilter | 1 | Backend |
| APEP-304.a | APEP-304 | Design data model and interface for scope allow-check in PlanScopeFilter | 1 | Backend |
| APEP-305.a | APEP-305 | Design SDK/CLI interface for agentpep scope compile <pattern> CLI command | 1 | SDK |
| APEP-306.a | APEP-306 | Design SDK/CLI interface for agentpep scope validate <plan.yaml> CLI command | 1 | SDK |

#### Sub-Sprint 38.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 38 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-301.b | APEP-301 | Implement Pydantic model and MongoDB schema for ScopePatternParser | 1 | Backend |
| APEP-302.b | APEP-302 | Implement Pydantic model and MongoDB schema for ScopePatternCompiler | 1 | Backend |
| APEP-303.b | APEP-303 | Implement Pydantic model and MongoDB schema for scope matching in PlanCheckpointFilter | 1 | Backend |
| APEP-304.b | APEP-304 | Implement Pydantic model and MongoDB schema for scope allow-check in PlanScopeFilter | 1 | Backend |

#### Sub-Sprint 38.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for and document scope pattern syntax; ScopePatternParser; ScopePatternCompiler.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-300.b | APEP-300 | Implement core logic: and document scope pattern syntax | 1 | Backend |
| APEP-301.c | APEP-301 | Implement core business logic: ScopePatternParser | 1 | Backend |
| APEP-302.c | APEP-302 | Implement core logic: ScopePatternCompiler | 2 | Backend |
| APEP-303.c | APEP-303 | Implement core business logic: scope matching in PlanCheckpointFilter | 1 | Backend |

#### Sub-Sprint 38.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for scope allow-check in PlanScopeFilter; agentpep scope compile <pattern> CLI command; agentpep scope validate <plan.yaml> CLI command.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-304.c | APEP-304 | Implement core business logic: scope allow-check in PlanScopeFilter | 1 | Backend |

#### Sub-Sprint 38.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 38 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-301.d | APEP-301 | Wire API endpoint and service layer for ScopePatternParser | 1 | Backend |
| APEP-302.d | APEP-302 | Wire API endpoint and service layer for ScopePatternCompiler | 1 | Backend |
| APEP-303.d | APEP-303 | Wire API endpoint and service layer for scope matching in PlanCheckpointFilter | 1 | Backend |
| APEP-304.d | APEP-304 | Wire API endpoint and service layer for scope allow-check in PlanScopeFilter | 1 | Backend |

#### Sub-Sprint 38.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 38.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S38.6 | — | Security review and input validation audit for Sprint 38 | 0 | Security |

#### Sub-Sprint 38.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 38 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-302.e | APEP-302 | Integrate into pipeline: ScopePatternCompiler | 1 | Backend |

#### Sub-Sprint 38.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 38 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-305.b | APEP-305 | Implement SDK/CLI: agentpep scope compile <pattern> CLI command | 1 | SDK |
| APEP-306.b | APEP-306 | Implement SDK/CLI: agentpep scope validate <plan.yaml> CLI command | 1 | SDK |

#### Sub-Sprint 38.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 38 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-300.c | APEP-300 | Write unit tests for and document scope pattern syntax | 1 | Testing |
| APEP-301.e | APEP-301 | Write unit tests for ScopePatternParser | 1 | Testing |
| APEP-302.f | APEP-302 | Write unit tests for ScopePatternCompiler | 1 | Testing |
| APEP-303.e | APEP-303 | Write unit tests for scope matching in PlanCheckpointFilter | 1 | Testing |
| APEP-304.e | APEP-304 | Write unit tests for scope allow-check in PlanScopeFilter | 1 | Testing |
| APEP-305.c | APEP-305 | Write tests for SDK/CLI: agentpep scope compile <pattern> CLI command | 1 | Testing |
| APEP-306.c | APEP-306 | Write tests for SDK/CLI: agentpep scope validate <plan.yaml> CLI command | 1 | Testing |
| APEP-307.a | APEP-307 | Write unit and component tests: unit tests | 2 | Testing |

#### Sub-Sprint 38.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 38.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-302.g | APEP-302 | Write integration tests for ScopePatternCompiler | 1 | Testing |
| APEP-307.b | APEP-307 | Write integration and adversarial tests: unit tests | 3 | Testing |

#### Sub-Sprint 38.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 38 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S38.11 | — | Sprint 38 documentation and deliverable validation | 0 | Docs |

---

### Sprint 39 — Receipt Chaining with Plan Root

**Goal:** Extend `AuditDecision` with `plan_id` and `parent_receipt_id`; implement per-receipt Ed25519 signing; add plan-scoped receipt retrieval API; implement independent offline verifier.

#### Sub-Sprint 39.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 39 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-308.a | APEP-308 | Design data model and interface for Extend AuditDecision Pydantic model with plan_id, paren | 1 | Backend |
| APEP-309.a | APEP-309 | Design security architecture and threat model for per-receipt Ed25519 signing in AuditLogger | 1 | Security |
| APEP-310.a | APEP-310 | Design data model and interface for ReceiptChainManager | 1 | Backend |
| APEP-311.a | APEP-311 | Design data model and interface for GET /v1/plans/{plan_id}/receipts — return full r | 1 | Backend |
| APEP-312.a | APEP-312 | Design data model and interface for GET /v1/plans/{plan_id}/receipts/summary — retur | 1 | Backend |
| APEP-313.a | APEP-313 | Design security architecture and threat model for OfflineReceiptVerifier | 1 | Security |
| APEP-314.a | APEP-314 | Design SDK/CLI interface for agentpep receipt verify-chain --plan <plan_id> --export receipts.json CLI com... | 1 | SDK |

#### Sub-Sprint 39.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 39 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-309.b | APEP-309 | Define data model and schema for per-receipt Ed25519 signing in AuditLogger | 1 | Backend |
| APEP-310.b | APEP-310 | Implement Pydantic model and MongoDB schema for ReceiptChainManager | 1 | Backend |
| APEP-311.b | APEP-311 | Implement Pydantic model and MongoDB schema for GET /v1/plans/{plan_id}/receipts — return full r | 1 | Backend |
| APEP-313.b | APEP-313 | Define data model and schema for OfflineReceiptVerifier | 1 | Backend |

#### Sub-Sprint 39.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for Extend AuditDecision Pydantic model with plan_i; per-receipt Ed25519 signing in AuditLogger; ReceiptChainManager.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-308.b | APEP-308 | Implement core logic: Extend AuditDecision Pydantic model with plan_id, paren | 1 | Backend |
| APEP-309.c | APEP-309 | Implement core security logic: per-receipt Ed25519 signing in AuditLogger | 2 | Security |
| APEP-310.c | APEP-310 | Implement core business logic: ReceiptChainManager | 1 | Backend |
| APEP-311.c | APEP-311 | Implement core business logic: GET /v1/plans/{plan_id}/receipts — return full r | 1 | Backend |

#### Sub-Sprint 39.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for GET /v1/plans/{plan_id}/receipts/summar; OfflineReceiptVerifier; agentpep receipt verify-chain --plan <plan_id> --export receipts.json CLI command.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-312.b | APEP-312 | Implement core logic: GET /v1/plans/{plan_id}/receipts/summary — retur | 1 | Backend |
| APEP-313.c | APEP-313 | Implement core security logic: OfflineReceiptVerifier | 2 | Security |

#### Sub-Sprint 39.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 39 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-310.d | APEP-310 | Wire API endpoint and service layer for ReceiptChainManager | 1 | Backend |
| APEP-311.d | APEP-311 | Wire API endpoint and service layer for GET /v1/plans/{plan_id}/receipts — return full r | 1 | Backend |

#### Sub-Sprint 39.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 39.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-309.d | APEP-309 | Implement security guards and crypto: per-receipt Ed25519 signing in AuditLogger | 1 | Security |
| APEP-313.d | APEP-313 | Implement security guards and crypto: OfflineReceiptVerifier | 1 | Security |

#### Sub-Sprint 39.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 39 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-309.e | APEP-309 | Integrate into enforcement pipeline: per-receipt Ed25519 signing in AuditLogger | 1 | Security |
| APEP-313.e | APEP-313 | Integrate into enforcement pipeline: OfflineReceiptVerifier | 1 | Security |

#### Sub-Sprint 39.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 39 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-314.b | APEP-314 | Implement SDK/CLI: agentpep receipt verify-chain --plan <plan_id> --export receipts.json CLI com... | 1 | SDK |

#### Sub-Sprint 39.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 39 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-308.c | APEP-308 | Write unit tests for Extend AuditDecision Pydantic model with plan_id, paren | 1 | Testing |
| APEP-309.f | APEP-309 | Write unit tests for per-receipt Ed25519 signing in AuditLogger | 1 | Testing |
| APEP-310.e | APEP-310 | Write unit tests for ReceiptChainManager | 1 | Testing |
| APEP-311.e | APEP-311 | Write unit tests for GET /v1/plans/{plan_id}/receipts — return full r | 1 | Testing |
| APEP-312.c | APEP-312 | Write unit tests for GET /v1/plans/{plan_id}/receipts/summary — retur | 1 | Testing |
| APEP-313.f | APEP-313 | Write unit tests for OfflineReceiptVerifier | 1 | Testing |
| APEP-314.c | APEP-314 | Write tests for SDK/CLI: agentpep receipt verify-chain --plan <plan_id> --export receipts.json CLI com... | 1 | Testing |
| APEP-315.a | APEP-315 | Write unit and component tests: adversarial tests | 2 | Testing |

#### Sub-Sprint 39.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 39.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-309.g | APEP-309 | Write adversarial tests for per-receipt Ed25519 signing in AuditLogger | 1 | Testing |
| APEP-313.g | APEP-313 | Write adversarial tests for OfflineReceiptVerifier | 1 | Testing |
| APEP-315.b | APEP-315 | Write integration and adversarial tests: adversarial tests | 3 | Testing |

#### Sub-Sprint 39.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 39 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S39.11 | — | Sprint 39 documentation and deliverable validation | 0 | Docs |

---

### Sprint 40 — Declarative Delegates-To & Plan Budget Gate

**Goal:** Implement `PlanDelegatesToFilter` as pre-stage in PolicyEvaluator; implement `PlanBudgetGate` with Redis-backed budget state tracking; enforce TTL, delegation count, and risk budget.

#### Sub-Sprint 40.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 40 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-316.a | APEP-316 | Design data model and interface for PlanDelegatesToFilter | 1 | Backend |
| APEP-317.a | APEP-317 | Design data model and interface for delegates_to | 1 | Backend |
| APEP-318.a | APEP-318 | Design architecture and interfaces for PlanBudgetGate | 1 | Backend |
| APEP-319.a | APEP-319 | Design data model and interface for budget exhaustion enforcement | 1 | Backend |
| APEP-320.a | APEP-320 | Design data model and interface for budget status API | 1 | Backend |
| APEP-321.a | APEP-321 | Design data model and interface for budget alert events | 1 | Backend |
| APEP-322.a | APEP-322 | Design data model and interface for plan budget reset | 1 | Backend |

#### Sub-Sprint 40.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 40 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-316.b | APEP-316 | Implement Pydantic model and MongoDB schema for PlanDelegatesToFilter | 1 | Backend |
| APEP-318.b | APEP-318 | Implement Pydantic model and MongoDB schema for PlanBudgetGate | 1 | Backend |
| APEP-319.b | APEP-319 | Implement Pydantic model and MongoDB schema for budget exhaustion enforcement | 1 | Backend |

#### Sub-Sprint 40.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for PlanDelegatesToFilter; delegates_to; PlanBudgetGate.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-316.c | APEP-316 | Implement core business logic: PlanDelegatesToFilter | 1 | Backend |
| APEP-317.b | APEP-317 | Implement core logic: delegates_to | 1 | Backend |
| APEP-318.c | APEP-318 | Implement core logic: PlanBudgetGate | 2 | Backend |
| APEP-319.c | APEP-319 | Implement core business logic: budget exhaustion enforcement | 1 | Backend |

#### Sub-Sprint 40.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for budget status API; budget alert events; plan budget reset.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-320.b | APEP-320 | Implement core logic: budget status API | 1 | Backend |
| APEP-321.b | APEP-321 | Implement core logic: budget alert events | 1 | Backend |
| APEP-322.b | APEP-322 | Implement core logic: plan budget reset | 1 | Backend |

#### Sub-Sprint 40.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 40 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-316.d | APEP-316 | Wire API endpoint and service layer for PlanDelegatesToFilter | 1 | Backend |
| APEP-318.d | APEP-318 | Wire API endpoint and service layer for PlanBudgetGate | 1 | Backend |
| APEP-319.d | APEP-319 | Wire API endpoint and service layer for budget exhaustion enforcement | 1 | Backend |

#### Sub-Sprint 40.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 40.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S40.6 | — | Security review and input validation audit for Sprint 40 | 0 | Security |

#### Sub-Sprint 40.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 40 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-318.e | APEP-318 | Integrate into pipeline: PlanBudgetGate | 1 | Backend |

#### Sub-Sprint 40.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 40 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S40.8 | — | Update SDK documentation and CLI help text for Sprint 40 | 0 | SDK |

#### Sub-Sprint 40.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 40 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-316.e | APEP-316 | Write unit tests for PlanDelegatesToFilter | 1 | Testing |
| APEP-317.c | APEP-317 | Write unit tests for delegates_to | 1 | Testing |
| APEP-318.f | APEP-318 | Write unit tests for PlanBudgetGate | 1 | Testing |
| APEP-319.e | APEP-319 | Write unit tests for budget exhaustion enforcement | 1 | Testing |
| APEP-320.c | APEP-320 | Write unit tests for budget status API | 1 | Testing |
| APEP-321.c | APEP-321 | Write unit tests for budget alert events | 1 | Testing |
| APEP-322.c | APEP-322 | Write unit tests for plan budget reset | 1 | Testing |
| APEP-323.a | APEP-323 | Write unit and component tests: integration tests | 2 | Testing |

#### Sub-Sprint 40.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 40.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-318.g | APEP-318 | Write integration tests for PlanBudgetGate | 1 | Testing |
| APEP-323.b | APEP-323 | Write integration and adversarial tests: integration tests | 3 | Testing |

#### Sub-Sprint 40.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 40 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S40.11 | — | Sprint 40 documentation and deliverable validation | 0 | Docs |

---

### Sprint 41 — Checkpoint-Declared Escalation & Human Intent

**Goal:** Integrate `requires_checkpoint` as a pre-RBAC PolicyEvaluator stage that unconditionally triggers ESCALATE for matched actions; add `human_intent` field propagation through the evaluation pipeline.

#### Sub-Sprint 41.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 41 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-324.a | APEP-324 | Design data model and interface for PlanCheckpointFilter as the first stage in PolicyEvaluator (before RBAC) | 1 | Backend |
| APEP-325.a | APEP-325 | Design data model and interface for Propagate checkpoint match reason to Escalation Manager | 1 | Backend |
| APEP-326.a | APEP-326 | Design data model and interface for checkpoint approval memory scoped to plan | 1 | Backend |
| APEP-327.a | APEP-327 | Design data model and interface for human_intent field propagation | 1 | Backend |
| APEP-328.a | APEP-328 | Design data model and interface for checkpoint pattern testing to policy simulation | 1 | Backend |
| APEP-329.a | APEP-329 | Design component wireframes and state model for Checkpoint History view in Escalation Queue console screen | 1 | Frontend |
| APEP-330.a | APEP-330 | Design data model and interface for Update compliance reports (DPDPA / CERT-In) | 1 | Backend |

#### Sub-Sprint 41.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 41 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-324.b | APEP-324 | Implement Pydantic model and MongoDB schema for PlanCheckpointFilter as the first stage in PolicyEvaluator (before RBAC) | 1 | Backend |
| APEP-325.b | APEP-325 | Implement Pydantic model and MongoDB schema for Propagate checkpoint match reason to Escalation Manager | 1 | Backend |
| APEP-326.b | APEP-326 | Implement Pydantic model and MongoDB schema for checkpoint approval memory scoped to plan | 1 | Backend |

#### Sub-Sprint 41.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for PlanCheckpointFilter as the first stage in PolicyEvaluator (before RBAC); Propagate checkpoint match reason to Escalation Manager; checkpoint approval memory scoped to plan.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-324.c | APEP-324 | Implement core business logic: PlanCheckpointFilter as the first stage in PolicyEvaluator (before RBAC) | 1 | Backend |
| APEP-325.c | APEP-325 | Implement core business logic: Propagate checkpoint match reason to Escalation Manager | 1 | Backend |
| APEP-326.c | APEP-326 | Implement core business logic: checkpoint approval memory scoped to plan | 1 | Backend |
| APEP-327.b | APEP-327 | Implement core logic: human_intent field propagation | 1 | Backend |

#### Sub-Sprint 41.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for checkpoint pattern testing to policy simulation; Checkpoint History view in Escalation Queue console screen; Update compliance reports (DPDPA / CERT-In).

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-328.b | APEP-328 | Implement core logic: checkpoint pattern testing to policy simulation | 1 | Backend |
| APEP-330.b | APEP-330 | Implement core logic: Update compliance reports (DPDPA / CERT-In) | 1 | Backend |

#### Sub-Sprint 41.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 41 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-324.d | APEP-324 | Wire API endpoint and service layer for PlanCheckpointFilter as the first stage in PolicyEvaluator (before RBAC) | 1 | Backend |
| APEP-325.d | APEP-325 | Wire API endpoint and service layer for Propagate checkpoint match reason to Escalation Manager | 1 | Backend |
| APEP-326.d | APEP-326 | Wire API endpoint and service layer for checkpoint approval memory scoped to plan | 1 | Backend |

#### Sub-Sprint 41.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 41.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S41.6 | — | Security review and input validation audit for Sprint 41 | 0 | Security |

#### Sub-Sprint 41.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 41 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S41.7 | — | Wire Kafka events and pipeline hooks for Sprint 41 components | 0 | Backend |

#### Sub-Sprint 41.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 41 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-329.b | APEP-329 | Implement UI component: Checkpoint History view in Escalation Queue console screen | 2 | Frontend |

#### Sub-Sprint 41.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 41 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-324.e | APEP-324 | Write unit tests for PlanCheckpointFilter as the first stage in PolicyEvaluator (before RBAC) | 1 | Testing |
| APEP-325.e | APEP-325 | Write unit tests for Propagate checkpoint match reason to Escalation Manager | 1 | Testing |
| APEP-326.e | APEP-326 | Write unit tests for checkpoint approval memory scoped to plan | 1 | Testing |
| APEP-327.c | APEP-327 | Write unit tests for human_intent field propagation | 1 | Testing |
| APEP-328.c | APEP-328 | Write unit tests for checkpoint pattern testing to policy simulation | 1 | Testing |
| APEP-329.c | APEP-329 | Write component tests for Checkpoint History view in Escalation Queue console screen | 1 | Testing |
| APEP-330.c | APEP-330 | Write unit tests for Update compliance reports (DPDPA / CERT-In) | 1 | Testing |
| APEP-331.a | APEP-331 | Write unit and component tests: integration tests | 2 | Testing |

#### Sub-Sprint 41.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 41.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-329.d | APEP-329 | Write E2E tests for Checkpoint History view in Escalation Queue console screen | 1 | Testing |
| APEP-331.b | APEP-331 | Write integration and adversarial tests: integration tests | 1 | Testing |

#### Sub-Sprint 41.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 41 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S41.11 | — | Sprint 41 documentation and deliverable validation | 0 | Docs |

---

### Sprint 42 — Plan Console UI & Plan-Scoped Audit Tree

**Goal:** Add Plan Management and Plan Explorer screens to Policy Console; implement plan-centric audit tree visualisation; add plan budget dashboard widget.

#### Sub-Sprint 42.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 42 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-332.a | APEP-332 | Design component wireframes and state model for Plan Management list screen | 1 | Frontend |
| APEP-333.a | APEP-333 | Design component wireframes, state model, and data flow for Plan Issuance form | 1 | Frontend |
| APEP-334.a | APEP-334 | Design component wireframes and state model for Plan Detail screen | 1 | Frontend |
| APEP-335.a | APEP-335 | Design component wireframes, state model, and data flow for Plan Explorer — receipt tree view | 1 | Frontend |
| APEP-336.a | APEP-336 | Design component wireframes and state model for receipt node drill-down | 1 | Frontend |
| APEP-337.a | APEP-337 | Design component wireframes and state model for plan budget widget to Risk Dashboard | 1 | Frontend |

#### Sub-Sprint 42.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 42 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-338.a | APEP-338 | Define schema for component wireframes and state model for plan filter to Audit Explorer | 1 | Frontend |

#### Sub-Sprint 42.3 — Core Component Logic (Part 1)

**Goal:** Implement core business logic for Plan Management list screen; Plan Issuance form; Plan Detail screen.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-333.b | APEP-333 | Implement component structure and state management: Plan Issuance form | 2 | Frontend |
| APEP-335.b | APEP-335 | Implement component structure and state management: Plan Explorer — receipt tree view | 2 | Frontend |

#### Sub-Sprint 42.4 — Core Component Logic (Part 2)

**Goal:** Implement core business logic for receipt node drill-down; plan budget widget to Risk Dashboard; plan filter to Audit Explorer.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-333.c | APEP-333 | Implement component rendering and interaction: Plan Issuance form | 2 | Frontend |
| APEP-335.c | APEP-335 | Implement component rendering and interaction: Plan Explorer — receipt tree view | 2 | Frontend |

#### Sub-Sprint 42.5 — API Integration & Data Fetching

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 42 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S42.5 | — | Review API contracts and OpenAPI spec for Sprint 42 endpoints | 0 | Backend |

#### Sub-Sprint 42.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 42.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S42.6 | — | Security review and input validation audit for Sprint 42 | 0 | Security |

#### Sub-Sprint 42.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 42 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S42.7 | — | Wire Kafka events and pipeline hooks for Sprint 42 components | 0 | Backend |

#### Sub-Sprint 42.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 42 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-332.b | APEP-332 | Implement UI component: Plan Management list screen | 2 | Frontend |
| APEP-333.d | APEP-333 | Polish and integrate UI component: Plan Issuance form | 1 | Frontend |
| APEP-334.b | APEP-334 | Implement UI component: Plan Detail screen | 2 | Frontend |
| APEP-335.d | APEP-335 | Polish and integrate UI component: Plan Explorer — receipt tree view | 1 | Frontend |
| APEP-336.b | APEP-336 | Implement UI component: receipt node drill-down | 1 | Frontend |
| APEP-337.b | APEP-337 | Implement UI component: plan budget widget to Risk Dashboard | 1 | Frontend |
| APEP-338.b | APEP-338 | Implement UI component: plan filter to Audit Explorer | 1 | Frontend |

#### Sub-Sprint 42.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 42 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-332.c | APEP-332 | Write component tests for Plan Management list screen | 1 | Testing |
| APEP-333.e | APEP-333 | Write component tests for Plan Issuance form | 1 | Testing |
| APEP-334.c | APEP-334 | Write component tests for Plan Detail screen | 1 | Testing |
| APEP-335.e | APEP-335 | Write component tests for Plan Explorer — receipt tree view | 1 | Testing |
| APEP-336.c | APEP-336 | Write component tests for receipt node drill-down | 1 | Testing |
| APEP-337.c | APEP-337 | Write component tests for plan budget widget to Risk Dashboard | 1 | Testing |
| APEP-338.c | APEP-338 | Write component tests for plan filter to Audit Explorer | 1 | Testing |
| APEP-339.a | APEP-339 | Write unit and component tests: Playwright E2E tests | 2 | Testing |

#### Sub-Sprint 42.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 42.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-332.d | APEP-332 | Write E2E tests for Plan Management list screen | 1 | Testing |
| APEP-333.f | APEP-333 | Write E2E tests for Plan Issuance form | 1 | Testing |
| APEP-334.d | APEP-334 | Write E2E tests for Plan Detail screen | 1 | Testing |
| APEP-335.f | APEP-335 | Write E2E tests for Plan Explorer — receipt tree view | 1 | Testing |
| APEP-339.b | APEP-339 | Write integration and adversarial tests: Playwright E2E tests | 1 | Testing |

#### Sub-Sprint 42.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 42 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S42.11 | — | Sprint 42 documentation and deliverable validation | 0 | Docs |

---

### Sprint 43 — Scope Simulator, Pattern Library & SDK Plan API

**Goal:** Build interactive scope simulator in console and CLI; publish curated enterprise scope pattern library; add plan-aware session API to SDK.

#### Sub-Sprint 43.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 43 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-340.a | APEP-340 | Design component wireframes, state model, and data flow for scope simulator UI | 1 | Frontend |
| APEP-341.a | APEP-341 | Design SDK/CLI interface for agentpep scope simulate --plan plan.yaml --action "delete | 1 | SDK |
| APEP-342.a | APEP-342 | Design architecture and interfaces for enterprise scope pattern library | 1 | Backend |
| APEP-343.a | APEP-343 | Design component wireframes and state model for pattern library UI | 1 | Frontend |
| APEP-344.a | APEP-344 | Design SDK/CLI interface for ToolTrustSession SDK class | 1 | SDK |
| APEP-345.a | APEP-345 | Design SDK/CLI interface for SDK delegate() method | 1 | SDK |
| APEP-346.a | APEP-346 | Outline documentation structure for ToolTrust migration guide | 1 | Docs |

#### Sub-Sprint 43.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 43 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-342.b | APEP-342 | Implement Pydantic model and MongoDB schema for enterprise scope pattern library | 1 | Backend |

#### Sub-Sprint 43.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for scope simulator UI; agentpep scope simulate --plan plan.yaml --action "delete; enterprise scope pattern library.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-341.b | APEP-341 | Implement core logic: agentpep scope simulate --plan plan.yaml --action "delete | 1 | Backend |
| APEP-342.c | APEP-342 | Implement core logic: enterprise scope pattern library | 2 | Backend |

#### Sub-Sprint 43.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for ToolTrustSession SDK class; SDK delegate() method; ToolTrust migration guide.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-344.b | APEP-344 | Implement core logic: ToolTrustSession SDK class | 2 | Backend |

#### Sub-Sprint 43.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 43 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-342.d | APEP-342 | Wire API endpoint and service layer for enterprise scope pattern library | 1 | Backend |
| APEP-344.d | APEP-344 | Wire API endpoints for ToolTrustSession SDK class | 1 | Backend |

#### Sub-Sprint 43.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 43.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S43.6 | — | Security review and input validation audit for Sprint 43 | 0 | Security |

#### Sub-Sprint 43.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 43 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-342.e | APEP-342 | Integrate into pipeline: enterprise scope pattern library | 1 | Backend |

#### Sub-Sprint 43.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 43 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-340.b | APEP-340 | Implement component structure and state management: scope simulator UI | 2 | Frontend |
| APEP-340.c | APEP-340 | Implement component rendering and interaction: scope simulator UI | 2 | Frontend |
| APEP-340.d | APEP-340 | Polish and integrate UI component: scope simulator UI | 1 | Frontend |
| APEP-341.c | APEP-341 | Implement SDK/CLI wrapper: agentpep scope simulate --plan plan.yaml --action "delete | 2 | SDK |
| APEP-343.b | APEP-343 | Implement UI component: pattern library UI | 2 | Frontend |
| APEP-344.c | APEP-344 | Implement SDK/CLI wrapper: ToolTrustSession SDK class | 2 | SDK |
| APEP-345.b | APEP-345 | Implement SDK/CLI: SDK delegate() method | 1 | SDK |

#### Sub-Sprint 43.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 43 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-340.e | APEP-340 | Write component tests for scope simulator UI | 1 | Testing |
| APEP-341.d | APEP-341 | Write unit tests for agentpep scope simulate --plan plan.yaml --action "delete | 1 | Testing |
| APEP-342.f | APEP-342 | Write unit tests for enterprise scope pattern library | 1 | Testing |
| APEP-343.c | APEP-343 | Write component tests for pattern library UI | 1 | Testing |
| APEP-344.e | APEP-344 | Write unit tests for ToolTrustSession SDK class | 1 | Testing |
| APEP-345.c | APEP-345 | Write tests for SDK/CLI: SDK delegate() method | 1 | Testing |
| APEP-347.a | APEP-347 | Write unit and component tests: integration tests | 2 | Testing |

#### Sub-Sprint 43.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 43.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-340.f | APEP-340 | Write E2E tests for scope simulator UI | 1 | Testing |
| APEP-342.g | APEP-342 | Write integration tests for enterprise scope pattern library | 1 | Testing |
| APEP-343.d | APEP-343 | Write E2E tests for pattern library UI | 1 | Testing |
| APEP-344.f | APEP-344 | Write integration tests for ToolTrustSession SDK class | 1 | Testing |
| APEP-347.b | APEP-347 | Write integration and adversarial tests: integration tests | 1 | Testing |

#### Sub-Sprint 43.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 43 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-346.b | APEP-346 | Write and publish documentation: ToolTrust migration guide | 2 | Docs |


---

## 13.7 Sprint Summary — Phase 9

| Sprint | Name | Phase | Stories |
|---|---|---|---|
| 37 | Mission Plan: Model, API & Lifecycle | Phase 9: ToolTrust Roadmap v2 | 8 stories → 11 sub-sprints |
| 38 | Scope Pattern Language & DSL Compiler | Phase 9: ToolTrust Roadmap v2 | 8 stories → 11 sub-sprints |
| 39 | Receipt Chaining with Plan Root | Phase 9: ToolTrust Roadmap v2 | 8 stories → 11 sub-sprints |
| 40 | Declarative Delegates-To & Plan Budget Gate | Phase 9: ToolTrust Roadmap v2 | 8 stories → 11 sub-sprints |
| 41 | Checkpoint-Declared Escalation & Human Intent | Phase 9: ToolTrust Roadmap v2 | 8 stories → 11 sub-sprints |
| 42 | Plan Console UI & Plan-Scoped Audit Tree | Phase 9: ToolTrust Roadmap v2 | 8 stories → 11 sub-sprints |
| 43 | Scope Simulator, Pattern Library & SDK Plan API | Phase 9: ToolTrust Roadmap v2 | 8 stories → 11 sub-sprints |

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
| **Total stories** | ~291 (Sprints 1–36) | **~347** (+ 56 stories decomposed into sub-tasks across 77 sub-sprints, Sprints 37–43) |

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

#### Sub-Sprint 44.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 44 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-348.a | APEP-348 | Design architecture and interfaces for NetworkDLPScanner service | 1 | Backend |
| APEP-349.a | APEP-349 | Design data model and interface for URLScanner pipeline | 1 | Backend |
| APEP-350.a | APEP-350 | Design data model and interface for domain blocklist lookup | 1 | Backend |
| APEP-351.a | APEP-351 | Design data model and interface for DLP pattern matching stage in URLScanner | 1 | Backend |
| APEP-352.a | APEP-352 | Design data model and interface for EntropyAnalyzer | 1 | Backend |
| APEP-353.a | APEP-353 | Design security model and threat surface for SSRFGuard | 1 | Security |
| APEP-354.a | APEP-354 | Design data model and interface for per-domain rate limiting and per-domain data budget in URLScanner | 1 | Backend |
| APEP-355.a | APEP-355 | Design data model and interface for POST /v1/scan endpoint | 1 | Backend |

#### Sub-Sprint 44.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 44 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-348.b | APEP-348 | Implement Pydantic model and MongoDB schema for NetworkDLPScanner service | 1 | Backend |
| APEP-351.b | APEP-351 | Implement Pydantic model and MongoDB schema for DLP pattern matching stage in URLScanner | 1 | Backend |
| APEP-352.b | APEP-352 | Implement Pydantic model and MongoDB schema for EntropyAnalyzer | 1 | Backend |
| APEP-355.b | APEP-355 | Implement Pydantic model and MongoDB schema for POST /v1/scan endpoint | 1 | Backend |

#### Sub-Sprint 44.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for NetworkDLPScanner service; URLScanner pipeline; domain blocklist lookup.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-348.c | APEP-348 | Implement core logic: NetworkDLPScanner service | 2 | Backend |
| APEP-349.b | APEP-349 | Implement core logic: URLScanner pipeline | 1 | Backend |
| APEP-350.b | APEP-350 | Implement core logic: domain blocklist lookup | 1 | Backend |
| APEP-351.c | APEP-351 | Implement core business logic: DLP pattern matching stage in URLScanner | 1 | Backend |

#### Sub-Sprint 44.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for EntropyAnalyzer; SSRFGuard; per-domain rate limiting and per-domain data budget in URLScanner.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-352.c | APEP-352 | Implement core business logic: EntropyAnalyzer | 1 | Backend |
| APEP-353.b | APEP-353 | Implement core security logic: SSRFGuard | 1 | Security |
| APEP-354.b | APEP-354 | Implement core logic: per-domain rate limiting and per-domain data budget in URLScanner | 1 | Backend |
| APEP-355.c | APEP-355 | Implement core business logic: POST /v1/scan endpoint | 1 | Backend |

#### Sub-Sprint 44.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 44 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-348.d | APEP-348 | Wire API endpoint and service layer for NetworkDLPScanner service | 1 | Backend |
| APEP-351.d | APEP-351 | Wire API endpoint and service layer for DLP pattern matching stage in URLScanner | 1 | Backend |
| APEP-352.d | APEP-352 | Wire API endpoint and service layer for EntropyAnalyzer | 1 | Backend |
| APEP-355.d | APEP-355 | Wire API endpoint and service layer for POST /v1/scan endpoint | 1 | Backend |

#### Sub-Sprint 44.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 44.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-353.c | APEP-353 | Implement security guards and validation: SSRFGuard | 1 | Security |

#### Sub-Sprint 44.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 44 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-348.e | APEP-348 | Integrate into pipeline: NetworkDLPScanner service | 1 | Backend |
| APEP-353.d | APEP-353 | Integrate into enforcement pipeline: SSRFGuard | 1 | Security |

#### Sub-Sprint 44.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 44 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S44.8 | — | Update SDK documentation and CLI help text for Sprint 44 | 0 | SDK |

#### Sub-Sprint 44.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 44 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-348.f | APEP-348 | Write unit tests for NetworkDLPScanner service | 1 | Testing |
| APEP-349.c | APEP-349 | Write unit tests for URLScanner pipeline | 1 | Testing |
| APEP-350.c | APEP-350 | Write unit tests for domain blocklist lookup | 1 | Testing |
| APEP-351.e | APEP-351 | Write unit tests for DLP pattern matching stage in URLScanner | 1 | Testing |
| APEP-352.e | APEP-352 | Write unit tests for EntropyAnalyzer | 1 | Testing |
| APEP-353.e | APEP-353 | Write security validation tests for SSRFGuard | 1 | Testing |
| APEP-354.c | APEP-354 | Write unit tests for per-domain rate limiting and per-domain data budget in URLScanner | 1 | Testing |
| APEP-355.e | APEP-355 | Write unit tests for POST /v1/scan endpoint | 1 | Testing |

#### Sub-Sprint 44.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 44.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-348.g | APEP-348 | Write integration tests for NetworkDLPScanner service | 1 | Testing |

#### Sub-Sprint 44.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 44 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S44.11 | — | Sprint 44 documentation and deliverable validation | 0 | Docs |

---

### Sprint 45 — DLP Pre-Scan Hook in Intercept Pipeline

**Goal:** Integrate `NetworkDLPScanner` into the existing `PolicyEvaluator` pipeline as a pre-evaluation stage; auto-elevate risk score when DLP hits are found in tool arguments; auto-taint tool arg values containing credentials.

#### Sub-Sprint 45.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 45 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-356.a | APEP-356 | Design architecture and interfaces for DLPPreScanStage in PolicyEvaluator | 1 | Backend |
| APEP-357.a | APEP-357 | Design data model and interface for DLP-to-risk mapping | 1 | Backend |
| APEP-358.a | APEP-358 | Design security model and threat surface for DLP-to-taint assignment | 1 | Security |
| APEP-359.a | APEP-359 | Design data model and interface for DLP findings to PolicyDecisionResponse | 1 | Backend |
| APEP-360.a | APEP-360 | Design metrics schema and dashboard layout for DLP metrics to Prometheus | 1 | Observability |
| APEP-361.a | APEP-361 | Design data model and interface for DLP pre-scan caching | 1 | Backend |
| APEP-363.a | APEP-363 | Design data model and interface for DLP pattern hot-reload | 1 | Backend |

#### Sub-Sprint 45.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 45 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-356.b | APEP-356 | Implement Pydantic model and MongoDB schema for DLPPreScanStage in PolicyEvaluator | 1 | Backend |

#### Sub-Sprint 45.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for DLPPreScanStage in PolicyEvaluator; DLP-to-risk mapping; DLP-to-taint assignment.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-356.c | APEP-356 | Implement core logic: DLPPreScanStage in PolicyEvaluator | 2 | Backend |
| APEP-357.b | APEP-357 | Implement core logic: DLP-to-risk mapping | 1 | Backend |
| APEP-358.b | APEP-358 | Implement core security logic: DLP-to-taint assignment | 1 | Security |
| APEP-359.b | APEP-359 | Implement core logic: DLP findings to PolicyDecisionResponse | 1 | Backend |

#### Sub-Sprint 45.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for DLP metrics to Prometheus; DLP pre-scan caching; adversarial tests.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-361.b | APEP-361 | Implement core logic: DLP pre-scan caching | 1 | Backend |
| APEP-363.b | APEP-363 | Implement core logic: DLP pattern hot-reload | 1 | Backend |

#### Sub-Sprint 45.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 45 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-356.d | APEP-356 | Wire API endpoint and service layer for DLPPreScanStage in PolicyEvaluator | 1 | Backend |

#### Sub-Sprint 45.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 45.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-358.c | APEP-358 | Implement security guards and validation: DLP-to-taint assignment | 1 | Security |

#### Sub-Sprint 45.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 45 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-356.e | APEP-356 | Integrate into pipeline: DLPPreScanStage in PolicyEvaluator | 1 | Backend |
| APEP-358.d | APEP-358 | Integrate into enforcement pipeline: DLP-to-taint assignment | 1 | Security |

#### Sub-Sprint 45.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 45 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S45.8 | — | Update SDK documentation and CLI help text for Sprint 45 | 0 | SDK |

#### Sub-Sprint 45.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 45 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-356.f | APEP-356 | Write unit tests for DLPPreScanStage in PolicyEvaluator | 1 | Testing |
| APEP-357.c | APEP-357 | Write unit tests for DLP-to-risk mapping | 1 | Testing |
| APEP-358.e | APEP-358 | Write security validation tests for DLP-to-taint assignment | 1 | Testing |
| APEP-359.c | APEP-359 | Write unit tests for DLP findings to PolicyDecisionResponse | 1 | Testing |
| APEP-361.c | APEP-361 | Write unit tests for DLP pre-scan caching | 1 | Testing |
| APEP-362.a | APEP-362 | Write unit and component tests: adversarial tests | 2 | Testing |
| APEP-363.c | APEP-363 | Write unit tests for DLP pattern hot-reload | 1 | Testing |

#### Sub-Sprint 45.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 45.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-356.g | APEP-356 | Write integration tests for DLPPreScanStage in PolicyEvaluator | 1 | Testing |
| APEP-362.b | APEP-362 | Write integration and adversarial tests: adversarial tests | 3 | Testing |

#### Sub-Sprint 45.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 45 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-360.b | APEP-360 | Implement Prometheus metrics and Grafana dashboards: DLP metrics to Prometheus | 1 | Observability |

---

### Sprint 46 — Fetch Proxy & Multi-Pass Response Injection Scanner

**Goal:** Build `/v1/fetch` fetch proxy endpoint; implement `ResponseInjectionScanner` with 6-pass Unicode normalization; auto-taint QUARANTINE when injection detected; integrate with session graph.

#### Sub-Sprint 46.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 46 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-364.a | APEP-364 | Design data model and interface for GET /v1/fetch?url=... fetch proxy | 1 | Backend |
| APEP-365.a | APEP-365 | Design security architecture and threat model for 6-pass ResponseNormalizer | 1 | Security |
| APEP-366.a | APEP-366 | Design security architecture and threat model for ResponseInjectionScanner | 1 | Security |
| APEP-367.a | APEP-367 | Design security model and threat surface for auto-taint on injection detection | 1 | Security |
| APEP-368.a | APEP-368 | Design security model for fetch proxy DLP scan on response body | 1 | Security |
| APEP-369.a | APEP-369 | Design data model and interface for configurable response actions | 1 | Backend |
| APEP-370.a | APEP-370 | Design SDK/CLI interface for SDK fetch_safe() method | 1 | SDK |

#### Sub-Sprint 46.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 46 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-364.b | APEP-364 | Implement Pydantic model and MongoDB schema for GET /v1/fetch?url=... fetch proxy | 1 | Backend |
| APEP-365.b | APEP-365 | Define data model and schema for 6-pass ResponseNormalizer | 1 | Backend |
| APEP-366.b | APEP-366 | Define data model and schema for ResponseInjectionScanner | 1 | Backend |
| APEP-369.b | APEP-369 | Implement Pydantic model and MongoDB schema for configurable response actions | 1 | Backend |

#### Sub-Sprint 46.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for GET /v1/fetch?url=... fetch proxy; 6-pass ResponseNormalizer; ResponseInjectionScanner.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-364.c | APEP-364 | Implement core business logic: GET /v1/fetch?url=... fetch proxy | 1 | Backend |
| APEP-365.c | APEP-365 | Implement core security logic: 6-pass ResponseNormalizer | 2 | Security |
| APEP-366.c | APEP-366 | Implement core security logic: ResponseInjectionScanner | 2 | Security |
| APEP-367.b | APEP-367 | Implement core security logic: auto-taint on injection detection | 1 | Security |

#### Sub-Sprint 46.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for fetch proxy DLP scan on response body; configurable response actions; SDK fetch_safe() method.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-369.c | APEP-369 | Implement core business logic: configurable response actions | 1 | Backend |

#### Sub-Sprint 46.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 46 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-364.d | APEP-364 | Wire API endpoint and service layer for GET /v1/fetch?url=... fetch proxy | 1 | Backend |
| APEP-369.d | APEP-369 | Wire API endpoint and service layer for configurable response actions | 1 | Backend |

#### Sub-Sprint 46.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 46.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-365.d | APEP-365 | Implement security guards and crypto: 6-pass ResponseNormalizer | 1 | Security |
| APEP-366.d | APEP-366 | Implement security guards and crypto: ResponseInjectionScanner | 1 | Security |
| APEP-367.c | APEP-367 | Implement security guards and validation: auto-taint on injection detection | 1 | Security |
| APEP-368.b | APEP-368 | Implement security logic: fetch proxy DLP scan on response body | 1 | Security |

#### Sub-Sprint 46.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 46 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-365.e | APEP-365 | Integrate into enforcement pipeline: 6-pass ResponseNormalizer | 1 | Security |
| APEP-366.e | APEP-366 | Integrate into enforcement pipeline: ResponseInjectionScanner | 1 | Security |
| APEP-367.d | APEP-367 | Integrate into enforcement pipeline: auto-taint on injection detection | 1 | Security |

#### Sub-Sprint 46.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 46 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-370.b | APEP-370 | Implement SDK/CLI: SDK fetch_safe() method | 1 | SDK |

#### Sub-Sprint 46.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 46 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-364.e | APEP-364 | Write unit tests for GET /v1/fetch?url=... fetch proxy | 1 | Testing |
| APEP-365.f | APEP-365 | Write unit tests for 6-pass ResponseNormalizer | 1 | Testing |
| APEP-366.f | APEP-366 | Write unit tests for ResponseInjectionScanner | 1 | Testing |
| APEP-367.e | APEP-367 | Write security validation tests for auto-taint on injection detection | 1 | Testing |
| APEP-368.c | APEP-368 | Write security tests for fetch proxy DLP scan on response body | 1 | Testing |
| APEP-369.e | APEP-369 | Write unit tests for configurable response actions | 1 | Testing |
| APEP-370.c | APEP-370 | Write tests for SDK/CLI: SDK fetch_safe() method | 1 | Testing |
| APEP-371.a | APEP-371 | Write unit and component tests: adversarial tests | 2 | Testing |

#### Sub-Sprint 46.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 46.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-365.g | APEP-365 | Write adversarial tests for 6-pass ResponseNormalizer | 1 | Testing |
| APEP-366.g | APEP-366 | Write adversarial tests for ResponseInjectionScanner | 1 | Testing |
| APEP-371.b | APEP-371 | Write integration and adversarial tests: adversarial tests | 3 | Testing |

#### Sub-Sprint 46.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 46 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S46.11 | — | Sprint 46 documentation and deliverable validation | 0 | Docs |

---

### Sprint 47 — Forward Proxy (CONNECT Tunneling) & WebSocket Proxy

**Goal:** Implement HTTPS_PROXY-compatible forward proxy using asyncio CONNECT tunneling; implement bidirectional WebSocket proxy with DLP and injection frame scanning.

#### Sub-Sprint 47.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 47 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-372.a | APEP-372 | Design architecture and interfaces for asyncio CONNECT tunnel handler | 1 | Backend |
| APEP-373.a | APEP-373 | Design security model and threat surface for request body DLP scan in forward proxy | 1 | Security |
| APEP-374.a | APEP-374 | Design data model and interface for hostname-level blocking in forward proxy | 1 | Backend |
| APEP-375.a | APEP-375 | Design security architecture and threat model for optional TLS interception (MITM) | 1 | Security |
| APEP-376.a | APEP-376 | Design data model and interface for ToolTrust tls init equivalent | 1 | Backend |
| APEP-377.a | APEP-377 | Design data model and interface for WebSocket proxy | 1 | Backend |
| APEP-378.a | APEP-378 | Design security model and threat surface for WebSocket frame DLP + injection scanning | 1 | Security |

#### Sub-Sprint 47.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 47 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-372.b | APEP-372 | Implement Pydantic model and MongoDB schema for asyncio CONNECT tunnel handler | 1 | Backend |
| APEP-375.b | APEP-375 | Define data model and schema for optional TLS interception (MITM) | 1 | Backend |
| APEP-377.b | APEP-377 | Implement Pydantic model and MongoDB schema for WebSocket proxy | 1 | Backend |

#### Sub-Sprint 47.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for asyncio CONNECT tunnel handler; request body DLP scan in forward proxy; hostname-level blocking in forward proxy.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-372.c | APEP-372 | Implement core logic: asyncio CONNECT tunnel handler | 2 | Backend |
| APEP-373.b | APEP-373 | Implement core security logic: request body DLP scan in forward proxy | 1 | Security |
| APEP-374.b | APEP-374 | Implement core logic: hostname-level blocking in forward proxy | 1 | Backend |
| APEP-375.c | APEP-375 | Implement core security logic: optional TLS interception (MITM) | 2 | Security |

#### Sub-Sprint 47.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for ToolTrust tls init equivalent; WebSocket proxy; WebSocket frame DLP + injection scanning.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-376.b | APEP-376 | Implement core logic: ToolTrust tls init equivalent | 1 | Backend |
| APEP-377.c | APEP-377 | Implement core business logic: WebSocket proxy | 1 | Backend |
| APEP-378.b | APEP-378 | Implement core security logic: WebSocket frame DLP + injection scanning | 1 | Security |

#### Sub-Sprint 47.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 47 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-372.d | APEP-372 | Wire API endpoint and service layer for asyncio CONNECT tunnel handler | 1 | Backend |
| APEP-377.d | APEP-377 | Wire API endpoint and service layer for WebSocket proxy | 1 | Backend |

#### Sub-Sprint 47.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 47.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-373.c | APEP-373 | Implement security guards and validation: request body DLP scan in forward proxy | 1 | Security |
| APEP-375.d | APEP-375 | Implement security guards and crypto: optional TLS interception (MITM) | 1 | Security |
| APEP-378.c | APEP-378 | Implement security guards and validation: WebSocket frame DLP + injection scanning | 1 | Security |

#### Sub-Sprint 47.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 47 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-372.e | APEP-372 | Integrate into pipeline: asyncio CONNECT tunnel handler | 1 | Backend |
| APEP-373.d | APEP-373 | Integrate into enforcement pipeline: request body DLP scan in forward proxy | 1 | Security |
| APEP-375.e | APEP-375 | Integrate into enforcement pipeline: optional TLS interception (MITM) | 1 | Security |
| APEP-378.d | APEP-378 | Integrate into enforcement pipeline: WebSocket frame DLP + injection scanning | 1 | Security |

#### Sub-Sprint 47.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 47 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S47.8 | — | Update SDK documentation and CLI help text for Sprint 47 | 0 | SDK |

#### Sub-Sprint 47.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 47 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-372.f | APEP-372 | Write unit tests for asyncio CONNECT tunnel handler | 1 | Testing |
| APEP-373.e | APEP-373 | Write security validation tests for request body DLP scan in forward proxy | 1 | Testing |
| APEP-374.c | APEP-374 | Write unit tests for hostname-level blocking in forward proxy | 1 | Testing |
| APEP-375.f | APEP-375 | Write unit tests for optional TLS interception (MITM) | 1 | Testing |
| APEP-376.c | APEP-376 | Write unit tests for ToolTrust tls init equivalent | 1 | Testing |
| APEP-377.e | APEP-377 | Write unit tests for WebSocket proxy | 1 | Testing |
| APEP-378.e | APEP-378 | Write security validation tests for WebSocket frame DLP + injection scanning | 1 | Testing |
| APEP-379.a | APEP-379 | Write unit and component tests: integration tests | 2 | Testing |

#### Sub-Sprint 47.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 47.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-372.g | APEP-372 | Write integration tests for asyncio CONNECT tunnel handler | 1 | Testing |
| APEP-375.g | APEP-375 | Write adversarial tests for optional TLS interception (MITM) | 1 | Testing |
| APEP-379.b | APEP-379 | Write integration and adversarial tests: integration tests | 3 | Testing |

#### Sub-Sprint 47.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 47 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S47.11 | — | Sprint 47 documentation and deliverable validation | 0 | Docs |

---

### Sprint 48 — MCP Proxy Enhancement: Bidirectional DLP & Tool Poisoning Detection

**Goal:** Enhance existing `mcp_proxy.py` (Sprint 12) with bidirectional DLP scanning; add tool poisoning detection on `tools/list` responses; detect mid-session tool description rug-pulls.

#### Sub-Sprint 48.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 48 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-380.a | APEP-380 | Design data model and interface for MCPProxy outbound scan | 1 | Backend |
| APEP-381.a | APEP-381 | Design security model and threat surface for MCP response scan | 1 | Security |
| APEP-382.a | APEP-382 | Design security model and threat surface for tools/list poisoning detection | 1 | Security |
| APEP-383.a | APEP-383 | Design security model and threat surface for rug-pull detection | 1 | Security |
| APEP-384.a | APEP-384 | Design data model and interface for MCP HTTP reverse proxy mode | 1 | Backend |
| APEP-385.a | APEP-385 | Design data model and interface for MCP session DLP budget | 1 | Backend |
| APEP-387.a | APEP-387 | Outline documentation structure for Update MCP proxy documentation and integration guides for La | 1 | Docs |

#### Sub-Sprint 48.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 48 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-380.b | APEP-380 | Implement Pydantic model and MongoDB schema for MCPProxy outbound scan | 1 | Backend |
| APEP-384.b | APEP-384 | Implement Pydantic model and MongoDB schema for MCP HTTP reverse proxy mode | 1 | Backend |

#### Sub-Sprint 48.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for MCPProxy outbound scan; MCP response scan; tools/list poisoning detection.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-380.c | APEP-380 | Implement core business logic: MCPProxy outbound scan | 1 | Backend |
| APEP-381.b | APEP-381 | Implement core security logic: MCP response scan | 1 | Security |
| APEP-382.b | APEP-382 | Implement core security logic: tools/list poisoning detection | 1 | Security |
| APEP-383.b | APEP-383 | Implement core security logic: rug-pull detection | 1 | Security |

#### Sub-Sprint 48.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for MCP HTTP reverse proxy mode; MCP session DLP budget; adversarial MCP tests.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-384.c | APEP-384 | Implement core business logic: MCP HTTP reverse proxy mode | 1 | Backend |
| APEP-385.b | APEP-385 | Implement core logic: MCP session DLP budget | 1 | Backend |

#### Sub-Sprint 48.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 48 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-380.d | APEP-380 | Wire API endpoint and service layer for MCPProxy outbound scan | 1 | Backend |
| APEP-384.d | APEP-384 | Wire API endpoint and service layer for MCP HTTP reverse proxy mode | 1 | Backend |

#### Sub-Sprint 48.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 48.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-381.c | APEP-381 | Implement security guards and validation: MCP response scan | 1 | Security |
| APEP-382.c | APEP-382 | Implement security guards and validation: tools/list poisoning detection | 1 | Security |
| APEP-383.c | APEP-383 | Implement security guards and validation: rug-pull detection | 1 | Security |

#### Sub-Sprint 48.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 48 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-381.d | APEP-381 | Integrate into enforcement pipeline: MCP response scan | 1 | Security |
| APEP-382.d | APEP-382 | Integrate into enforcement pipeline: tools/list poisoning detection | 1 | Security |
| APEP-383.d | APEP-383 | Integrate into enforcement pipeline: rug-pull detection | 1 | Security |

#### Sub-Sprint 48.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 48 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S48.8 | — | Update SDK documentation and CLI help text for Sprint 48 | 0 | SDK |

#### Sub-Sprint 48.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 48 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-380.e | APEP-380 | Write unit tests for MCPProxy outbound scan | 1 | Testing |
| APEP-381.e | APEP-381 | Write security validation tests for MCP response scan | 1 | Testing |
| APEP-382.e | APEP-382 | Write security validation tests for tools/list poisoning detection | 1 | Testing |
| APEP-383.e | APEP-383 | Write security validation tests for rug-pull detection | 1 | Testing |
| APEP-384.e | APEP-384 | Write unit tests for MCP HTTP reverse proxy mode | 1 | Testing |
| APEP-385.c | APEP-385 | Write unit tests for MCP session DLP budget | 1 | Testing |
| APEP-386.a | APEP-386 | Write unit and component tests: adversarial MCP tests | 2 | Testing |

#### Sub-Sprint 48.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 48.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-386.b | APEP-386 | Write integration and adversarial tests: adversarial MCP tests | 3 | Testing |

#### Sub-Sprint 48.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 48 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-387.b | APEP-387 | Write and publish documentation: Update MCP proxy documentation and integration guides for La | 2 | Docs |

---

### Sprint 49 — Tool Call Chain Detection Engine

**Goal:** Implement `ToolCallChainDetector` with configurable attack sequence patterns; integrate with session history from the taint graph and audit log; emit Kafka security alerts on chain detection.

#### Sub-Sprint 49.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 49 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-388.a | APEP-388 | Design data model and interface for ToolCallChain pattern model | 1 | Backend |
| APEP-389.a | APEP-389 | Design architecture and interfaces for subsequence matching engine | 1 | Backend |
| APEP-390.a | APEP-390 | Design security architecture and threat model for built-in chain pattern library (10 patterns) | 1 | Security |
| APEP-391.a | APEP-391 | Design data model and interface for chain detector into PolicyEvaluator post-decision stage | 1 | Backend |
| APEP-392.a | APEP-392 | Design data model and interface for chain detection escalation | 1 | Backend |
| APEP-393.a | APEP-393 | Design data model and interface for chain pattern management API | 1 | Backend |
| APEP-394.a | APEP-394 | Design metrics schema and dashboard layout for chain detection metrics | 1 | Observability |

#### Sub-Sprint 49.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 49 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-388.b | APEP-388 | Implement Pydantic model and MongoDB schema for ToolCallChain pattern model | 1 | Backend |
| APEP-389.b | APEP-389 | Implement Pydantic model and MongoDB schema for subsequence matching engine | 1 | Backend |
| APEP-390.b | APEP-390 | Define data model and schema for built-in chain pattern library (10 patterns) | 1 | Backend |
| APEP-391.b | APEP-391 | Implement Pydantic model and MongoDB schema for chain detector into PolicyEvaluator post-decision stage | 1 | Backend |
| APEP-392.b | APEP-392 | Implement Pydantic model and MongoDB schema for chain detection escalation | 1 | Backend |

#### Sub-Sprint 49.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for ToolCallChain pattern model; subsequence matching engine; built-in chain pattern library (10 patterns).

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-388.c | APEP-388 | Implement core business logic: ToolCallChain pattern model | 1 | Backend |
| APEP-389.c | APEP-389 | Implement core logic: subsequence matching engine | 2 | Backend |
| APEP-390.c | APEP-390 | Implement core security logic: built-in chain pattern library (10 patterns) | 2 | Security |
| APEP-391.c | APEP-391 | Implement core business logic: chain detector into PolicyEvaluator post-decision stage | 1 | Backend |

#### Sub-Sprint 49.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for chain detection escalation; chain pattern management API; chain detection metrics.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-392.c | APEP-392 | Implement core business logic: chain detection escalation | 1 | Backend |
| APEP-393.b | APEP-393 | Implement core logic: chain pattern management API | 1 | Backend |

#### Sub-Sprint 49.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 49 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-388.d | APEP-388 | Wire API endpoint and service layer for ToolCallChain pattern model | 1 | Backend |
| APEP-389.d | APEP-389 | Wire API endpoint and service layer for subsequence matching engine | 1 | Backend |
| APEP-391.d | APEP-391 | Wire API endpoint and service layer for chain detector into PolicyEvaluator post-decision stage | 1 | Backend |
| APEP-392.d | APEP-392 | Wire API endpoint and service layer for chain detection escalation | 1 | Backend |

#### Sub-Sprint 49.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 49.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-390.d | APEP-390 | Implement security guards and crypto: built-in chain pattern library (10 patterns) | 1 | Security |

#### Sub-Sprint 49.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 49 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-389.e | APEP-389 | Integrate into pipeline: subsequence matching engine | 1 | Backend |
| APEP-390.e | APEP-390 | Integrate into enforcement pipeline: built-in chain pattern library (10 patterns) | 1 | Security |

#### Sub-Sprint 49.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 49 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S49.8 | — | Update SDK documentation and CLI help text for Sprint 49 | 0 | SDK |

#### Sub-Sprint 49.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 49 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-388.e | APEP-388 | Write unit tests for ToolCallChain pattern model | 1 | Testing |
| APEP-389.f | APEP-389 | Write unit tests for subsequence matching engine | 1 | Testing |
| APEP-390.f | APEP-390 | Write unit tests for built-in chain pattern library (10 patterns) | 1 | Testing |
| APEP-391.e | APEP-391 | Write unit tests for chain detector into PolicyEvaluator post-decision stage | 1 | Testing |
| APEP-392.e | APEP-392 | Write unit tests for chain detection escalation | 1 | Testing |
| APEP-393.c | APEP-393 | Write unit tests for chain pattern management API | 1 | Testing |
| APEP-395.a | APEP-395 | Write unit and component tests: adversarial tests | 2 | Testing |

#### Sub-Sprint 49.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 49.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-389.g | APEP-389 | Write integration tests for subsequence matching engine | 1 | Testing |
| APEP-390.g | APEP-390 | Write adversarial tests for built-in chain pattern library (10 patterns) | 1 | Testing |
| APEP-395.b | APEP-395 | Write integration and adversarial tests: adversarial tests | 3 | Testing |

#### Sub-Sprint 49.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 49 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-394.b | APEP-394 | Implement Prometheus metrics and Grafana dashboards: chain detection metrics | 1 | Observability |

---

### Sprint 50 — Kill Switch, Filesystem Sentinel & Adaptive Threat Score

**Goal:** Implement kill switch with 4 independent activation sources; filesystem sentinel for secret monitoring; adaptive per-session threat score integrating network events with authorization events.

#### Sub-Sprint 50.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 50 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-396.a | APEP-396 | Design data model and interface for KillSwitch service | 1 | Backend |
| APEP-397.a | APEP-397 | Design security model and threat surface for kill switch activation sources | 1 | Security |
| APEP-398.a | APEP-398 | Design security model for kill switch isolated API port | 1 | Security |
| APEP-399.a | APEP-399 | Design security architecture and threat model for FilesystemSentinel service | 1 | Security |
| APEP-400.a | APEP-400 | Design security model and threat surface for process lineage attribution on Linux | 1 | Security |
| APEP-401.a | APEP-401 | Design data model and interface for AdaptiveThreatScore | 1 | Backend |
| APEP-402.a | APEP-402 | Design data model and interface for de-escalation timer | 1 | Backend |

#### Sub-Sprint 50.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 50 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-396.b | APEP-396 | Implement Pydantic model and MongoDB schema for KillSwitch service | 1 | Backend |
| APEP-399.b | APEP-399 | Define data model and schema for FilesystemSentinel service | 1 | Backend |
| APEP-401.b | APEP-401 | Implement Pydantic model and MongoDB schema for AdaptiveThreatScore | 1 | Backend |

#### Sub-Sprint 50.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for KillSwitch service; kill switch activation sources; kill switch isolated API port.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-396.c | APEP-396 | Implement core business logic: KillSwitch service | 1 | Backend |
| APEP-397.b | APEP-397 | Implement core security logic: kill switch activation sources | 1 | Security |
| APEP-399.c | APEP-399 | Implement core security logic: FilesystemSentinel service | 2 | Security |

#### Sub-Sprint 50.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for process lineage attribution on Linux; AdaptiveThreatScore; de-escalation timer.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-400.b | APEP-400 | Implement core security logic: process lineage attribution on Linux | 1 | Security |
| APEP-401.c | APEP-401 | Implement core business logic: AdaptiveThreatScore | 1 | Backend |
| APEP-402.b | APEP-402 | Implement core logic: de-escalation timer | 1 | Backend |

#### Sub-Sprint 50.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 50 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-396.d | APEP-396 | Wire API endpoint and service layer for KillSwitch service | 1 | Backend |
| APEP-401.d | APEP-401 | Wire API endpoint and service layer for AdaptiveThreatScore | 1 | Backend |

#### Sub-Sprint 50.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 50.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-397.c | APEP-397 | Implement security guards and validation: kill switch activation sources | 1 | Security |
| APEP-398.b | APEP-398 | Implement security logic: kill switch isolated API port | 1 | Security |
| APEP-399.d | APEP-399 | Implement security guards and crypto: FilesystemSentinel service | 1 | Security |
| APEP-400.c | APEP-400 | Implement security guards and validation: process lineage attribution on Linux | 1 | Security |

#### Sub-Sprint 50.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 50 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-397.d | APEP-397 | Integrate into enforcement pipeline: kill switch activation sources | 1 | Security |
| APEP-399.e | APEP-399 | Integrate into enforcement pipeline: FilesystemSentinel service | 1 | Security |
| APEP-400.d | APEP-400 | Integrate into enforcement pipeline: process lineage attribution on Linux | 1 | Security |

#### Sub-Sprint 50.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 50 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S50.8 | — | Update SDK documentation and CLI help text for Sprint 50 | 0 | SDK |

#### Sub-Sprint 50.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 50 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-396.e | APEP-396 | Write unit tests for KillSwitch service | 1 | Testing |
| APEP-397.e | APEP-397 | Write security validation tests for kill switch activation sources | 1 | Testing |
| APEP-398.c | APEP-398 | Write security tests for kill switch isolated API port | 1 | Testing |
| APEP-399.f | APEP-399 | Write unit tests for FilesystemSentinel service | 1 | Testing |
| APEP-400.e | APEP-400 | Write security validation tests for process lineage attribution on Linux | 1 | Testing |
| APEP-401.e | APEP-401 | Write unit tests for AdaptiveThreatScore | 1 | Testing |
| APEP-402.c | APEP-402 | Write unit tests for de-escalation timer | 1 | Testing |
| APEP-403.a | APEP-403 | Write unit and component tests: integration tests | 2 | Testing |

#### Sub-Sprint 50.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 50.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-399.g | APEP-399 | Write adversarial tests for FilesystemSentinel service | 1 | Testing |
| APEP-403.b | APEP-403 | Write integration and adversarial tests: integration tests | 3 | Testing |

#### Sub-Sprint 50.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 50 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S50.11 | — | Sprint 50 documentation and deliverable validation | 0 | Docs |

---

### Sprint 51 — Rule Bundles, Security Assessment & Network Audit Events

**Goal:** Implement Ed25519-signed community rule bundles; build `ToolTrust assess`-equivalent security assessment; finalize MITRE ATT&CK event tagging; publish TFN documentation.

#### Sub-Sprint 51.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 51 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-404.a | APEP-404 | Design data model and interface for rule bundle format | 1 | Backend |
| APEP-405.a | APEP-405 | Design data model and interface for rule bundle loader | 1 | Backend |
| APEP-406.a | APEP-406 | Design architecture and interfaces for security assessment engine | 1 | Backend |
| APEP-407.a | APEP-407 | Design data model and interface for GET /v1/network/assess assessment endpoint | 1 | Backend |
| APEP-408.a | APEP-408 | Design data model and interface for MITRE ATT&CK technique mapping | 1 | Backend |
| APEP-409.a | APEP-409 | Design component wireframes and state model for TFN events to Policy Console — Network Events tab | 1 | Frontend |
| APEP-410.a | APEP-410 | Design metrics schema and dashboard layout for TFN Prometheus metrics | 1 | Observability |
| APEP-411.a | APEP-411 | Outline documentation structure for TFN documentation | 1 | Docs |

#### Sub-Sprint 51.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 51 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-404.b | APEP-404 | Implement Pydantic model and MongoDB schema for rule bundle format | 1 | Backend |
| APEP-405.b | APEP-405 | Implement Pydantic model and MongoDB schema for rule bundle loader | 1 | Backend |
| APEP-406.b | APEP-406 | Implement Pydantic model and MongoDB schema for security assessment engine | 1 | Backend |
| APEP-407.b | APEP-407 | Implement Pydantic model and MongoDB schema for GET /v1/network/assess assessment endpoint | 1 | Backend |

#### Sub-Sprint 51.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for rule bundle format; rule bundle loader; security assessment engine.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-404.c | APEP-404 | Implement core business logic: rule bundle format | 1 | Backend |
| APEP-405.c | APEP-405 | Implement core business logic: rule bundle loader | 1 | Backend |
| APEP-406.c | APEP-406 | Implement core logic: security assessment engine | 2 | Backend |
| APEP-407.c | APEP-407 | Implement core business logic: GET /v1/network/assess assessment endpoint | 1 | Backend |

#### Sub-Sprint 51.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for MITRE ATT&CK technique mapping; TFN events to Policy Console — Network Events tab; TFN Prometheus metrics.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-408.b | APEP-408 | Implement core logic: MITRE ATT&CK technique mapping | 1 | Backend |

#### Sub-Sprint 51.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 51 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-404.d | APEP-404 | Wire API endpoint and service layer for rule bundle format | 1 | Backend |
| APEP-405.d | APEP-405 | Wire API endpoint and service layer for rule bundle loader | 1 | Backend |
| APEP-406.d | APEP-406 | Wire API endpoint and service layer for security assessment engine | 1 | Backend |
| APEP-407.d | APEP-407 | Wire API endpoint and service layer for GET /v1/network/assess assessment endpoint | 1 | Backend |

#### Sub-Sprint 51.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 51.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S51.6 | — | Security review and input validation audit for Sprint 51 | 0 | Security |

#### Sub-Sprint 51.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 51 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-406.e | APEP-406 | Integrate into pipeline: security assessment engine | 1 | Backend |

#### Sub-Sprint 51.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 51 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-409.b | APEP-409 | Implement UI component: TFN events to Policy Console — Network Events tab | 2 | Frontend |

#### Sub-Sprint 51.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 51 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-404.e | APEP-404 | Write unit tests for rule bundle format | 1 | Testing |
| APEP-405.e | APEP-405 | Write unit tests for rule bundle loader | 1 | Testing |
| APEP-406.f | APEP-406 | Write unit tests for security assessment engine | 1 | Testing |
| APEP-407.e | APEP-407 | Write unit tests for GET /v1/network/assess assessment endpoint | 1 | Testing |
| APEP-408.c | APEP-408 | Write unit tests for MITRE ATT&CK technique mapping | 1 | Testing |
| APEP-409.c | APEP-409 | Write component tests for TFN events to Policy Console — Network Events tab | 1 | Testing |

#### Sub-Sprint 51.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 51.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-406.g | APEP-406 | Write integration tests for security assessment engine | 1 | Testing |
| APEP-409.d | APEP-409 | Write E2E tests for TFN events to Policy Console — Network Events tab | 1 | Testing |

#### Sub-Sprint 51.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 51 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-410.b | APEP-410 | Implement Prometheus metrics and Grafana dashboards: TFN Prometheus metrics | 2 | Observability |
| APEP-411.b | APEP-411 | Write and publish documentation: TFN documentation | 4 | Docs |


---

## 14.7 Sprint Summary — Phase 10

| Sprint | Name | Phase | Stories |
|---|---|---|---|
| 44 | Network DLP Engine & 11-Layer URL Scanner | Phase 10: TrustFabric Network | 8 stories → 11 sub-sprints |
| 45 | DLP Pre-Scan Hook in Intercept Pipeline | Phase 10: TrustFabric Network | 8 stories → 11 sub-sprints |
| 46 | Fetch Proxy & Multi-Pass Response Injection Scanner | Phase 10: TrustFabric Network | 8 stories → 11 sub-sprints |
| 47 | Forward Proxy (CONNECT Tunneling) & WebSocket Proxy | Phase 10: TrustFabric Network | 8 stories → 11 sub-sprints |
| 48 | MCP Proxy Enhancement: Bidirectional DLP & Tool Poisoning | Phase 10: TrustFabric Network | 8 stories → 11 sub-sprints |
| 49 | Tool Call Chain Detection Engine | Phase 10: TrustFabric Network | 8 stories → 11 sub-sprints |
| 50 | Kill Switch, Filesystem Sentinel & Adaptive Threat Score | Phase 10: TrustFabric Network | 8 stories → 11 sub-sprints |
| 51 | Rule Bundles, Security Assessment & Network Audit Events | Phase 10: TrustFabric Network | 8 stories → 11 sub-sprints |

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
| **Total stories** | ~347 (Sprints 1–43) | **~411** (+ 64 stories decomposed into sub-tasks across 88 sub-sprints, Sprints 44–51) |

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

### Sprint 52 — Extended Pattern Library & Scan Mode Router

**Goal:** Expand injection_signatures.py from ~30 to 204 patterns across 25 categories; implement ScanModeRouter with per-category mode restrictions; add content-hash trust cache and allowlist.

#### Sub-Sprint 52.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 52 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-412.a | APEP-412 | Design security architecture and threat model for Expand injection_signatures.py with 204 patterns across all 25 ToolTrust cate... | 1 | Security |
| APEP-413.a | APEP-413 | Design security architecture and threat model for remaining 15 pattern categories | 1 | Security |
| APEP-414.a | APEP-414 | Design data model and interface for ScanModeRouter | 1 | Backend |
| APEP-415.a | APEP-415 | Design data model and interface for CISTrustCache | 1 | Backend |
| APEP-416.a | APEP-416 | Design security model and threat surface for CISAllowlist | 1 | Security |
| APEP-417.a | APEP-417 | Design security model and threat surface for YOLO mode detector | 1 | Security |
| APEP-419.a | APEP-419 | Design data model and interface for Update injection_signatures.py hot-reload to support 204-pat | 1 | Backend |

#### Sub-Sprint 52.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 52 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-412.b | APEP-412 | Define data model and schema for Expand injection_signatures.py with 204 patterns across all 25 ToolTrust cate... | 1 | Backend |
| APEP-413.b | APEP-413 | Define data model and schema for remaining 15 pattern categories | 1 | Backend |
| APEP-414.b | APEP-414 | Implement Pydantic model and MongoDB schema for ScanModeRouter | 1 | Backend |
| APEP-415.b | APEP-415 | Implement Pydantic model and MongoDB schema for CISTrustCache | 1 | Backend |

#### Sub-Sprint 52.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for Expand injection_signatures.py with 204 patterns across all 25 ToolTrust categories; remaining 15 pattern categories; ScanModeRouter.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-412.c | APEP-412 | Implement core security logic: Expand injection_signatures.py with 204 patterns across all 25 ToolTrust cate... | 2 | Security |
| APEP-413.c | APEP-413 | Implement core security logic: remaining 15 pattern categories | 2 | Security |
| APEP-414.c | APEP-414 | Implement core business logic: ScanModeRouter | 1 | Backend |
| APEP-415.c | APEP-415 | Implement core business logic: CISTrustCache | 1 | Backend |

#### Sub-Sprint 52.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for CISAllowlist; YOLO mode detector; pattern validation tests.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-416.b | APEP-416 | Implement core security logic: CISAllowlist | 1 | Security |
| APEP-417.b | APEP-417 | Implement core security logic: YOLO mode detector | 1 | Security |
| APEP-419.b | APEP-419 | Implement core logic: Update injection_signatures.py hot-reload to support 204-pat | 1 | Backend |

#### Sub-Sprint 52.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 52 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-414.d | APEP-414 | Wire API endpoint and service layer for ScanModeRouter | 1 | Backend |
| APEP-415.d | APEP-415 | Wire API endpoint and service layer for CISTrustCache | 1 | Backend |

#### Sub-Sprint 52.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 52.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-412.d | APEP-412 | Implement security guards and crypto: Expand injection_signatures.py with 204 patterns across all 25 ToolTrust cate... | 1 | Security |
| APEP-413.d | APEP-413 | Implement security guards and crypto: remaining 15 pattern categories | 1 | Security |
| APEP-416.c | APEP-416 | Implement security guards and validation: CISAllowlist | 1 | Security |
| APEP-417.c | APEP-417 | Implement security guards and validation: YOLO mode detector | 1 | Security |

#### Sub-Sprint 52.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 52 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-412.e | APEP-412 | Integrate into enforcement pipeline: Expand injection_signatures.py with 204 patterns across all 25 ToolTrust cate... | 1 | Security |
| APEP-413.e | APEP-413 | Integrate into enforcement pipeline: remaining 15 pattern categories | 1 | Security |
| APEP-416.d | APEP-416 | Integrate into enforcement pipeline: CISAllowlist | 1 | Security |
| APEP-417.d | APEP-417 | Integrate into enforcement pipeline: YOLO mode detector | 1 | Security |

#### Sub-Sprint 52.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 52 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S52.8 | — | Update SDK documentation and CLI help text for Sprint 52 | 0 | SDK |

#### Sub-Sprint 52.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 52 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-412.f | APEP-412 | Write unit tests for Expand injection_signatures.py with 204 patterns across all 25 ToolTrust cate... | 1 | Testing |
| APEP-413.f | APEP-413 | Write unit tests for remaining 15 pattern categories | 1 | Testing |
| APEP-414.e | APEP-414 | Write unit tests for ScanModeRouter | 1 | Testing |
| APEP-415.e | APEP-415 | Write unit tests for CISTrustCache | 1 | Testing |
| APEP-416.e | APEP-416 | Write security validation tests for CISAllowlist | 1 | Testing |
| APEP-417.e | APEP-417 | Write security validation tests for YOLO mode detector | 1 | Testing |
| APEP-418.a | APEP-418 | Write unit and component tests: pattern validation tests | 2 | Testing |
| APEP-419.c | APEP-419 | Write unit tests for Update injection_signatures.py hot-reload to support 204-pat | 1 | Testing |

#### Sub-Sprint 52.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 52.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-412.g | APEP-412 | Write adversarial tests for Expand injection_signatures.py with 204 patterns across all 25 ToolTrust cate... | 1 | Testing |
| APEP-413.g | APEP-413 | Write adversarial tests for remaining 15 pattern categories | 1 | Testing |
| APEP-418.b | APEP-418 | Write integration and adversarial tests: pattern validation tests | 3 | Testing |

#### Sub-Sprint 52.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 52 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S52.11 | — | Sprint 52 documentation and deliverable validation | 0 | Docs |

---

### Sprint 53 — ONNX Semantic Injection Classifier (Tier 1)

**Goal:** Integrate ONNX MiniLM-L6-v2 classifier as ONNXSemanticClassifier; wire as Tier 1 in CIS scanner pipeline; benchmark against ToolTrust published F1 metrics; implement graceful fallback.

#### Sub-Sprint 53.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 53 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-420.a | APEP-420 | Design architecture and interfaces for ONNXSemanticClassifier service | 1 | Backend |
| APEP-421.a | APEP-421 | Design data model and interface for model download and SHA-256 verification | 1 | Backend |
| APEP-422.a | APEP-422 | Design data model and interface for per-mode ONNX classification thresholds | 1 | Backend |
| APEP-423.a | APEP-423 | Design data model and interface for text chunking for long content | 1 | Backend |
| APEP-424.a | APEP-424 | Design data model and interface for model-absent graceful fallback | 1 | Backend |
| APEP-425.a | APEP-425 | Design data model and interface for async batch inference | 1 | Backend |
| APEP-426.a | APEP-426 | Design data model and interface for Benchmark ONNX classifier against ToolTrust published metrics | 1 | Backend |
| APEP-427.a | APEP-427 | Design metrics schema and dashboard layout for ONNX inference Prometheus metrics | 1 | Observability |

#### Sub-Sprint 53.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 53 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-420.b | APEP-420 | Implement Pydantic model and MongoDB schema for ONNXSemanticClassifier service | 1 | Backend |
| APEP-421.b | APEP-421 | Implement Pydantic model and MongoDB schema for model download and SHA-256 verification | 1 | Backend |
| APEP-422.b | APEP-422 | Implement Pydantic model and MongoDB schema for per-mode ONNX classification thresholds | 1 | Backend |
| APEP-423.b | APEP-423 | Implement Pydantic model and MongoDB schema for text chunking for long content | 1 | Backend |
| APEP-425.b | APEP-425 | Implement Pydantic model and MongoDB schema for async batch inference | 1 | Backend |
| APEP-426.b | APEP-426 | Implement Pydantic model and MongoDB schema for Benchmark ONNX classifier against ToolTrust published metrics | 1 | Backend |

#### Sub-Sprint 53.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for ONNXSemanticClassifier service; model download and SHA-256 verification; per-mode ONNX classification thresholds.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-420.c | APEP-420 | Implement core logic: ONNXSemanticClassifier service | 2 | Backend |
| APEP-421.c | APEP-421 | Implement core business logic: model download and SHA-256 verification | 1 | Backend |
| APEP-422.c | APEP-422 | Implement core business logic: per-mode ONNX classification thresholds | 1 | Backend |
| APEP-423.c | APEP-423 | Implement core business logic: text chunking for long content | 1 | Backend |

#### Sub-Sprint 53.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for model-absent graceful fallback; async batch inference; Benchmark ONNX classifier against ToolTrust published metrics.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-424.b | APEP-424 | Implement core logic: model-absent graceful fallback | 1 | Backend |
| APEP-425.c | APEP-425 | Implement core business logic: async batch inference | 1 | Backend |
| APEP-426.c | APEP-426 | Implement core business logic: Benchmark ONNX classifier against ToolTrust published metrics | 1 | Backend |

#### Sub-Sprint 53.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 53 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-420.d | APEP-420 | Wire API endpoint and service layer for ONNXSemanticClassifier service | 1 | Backend |
| APEP-421.d | APEP-421 | Wire API endpoint and service layer for model download and SHA-256 verification | 1 | Backend |
| APEP-422.d | APEP-422 | Wire API endpoint and service layer for per-mode ONNX classification thresholds | 1 | Backend |
| APEP-423.d | APEP-423 | Wire API endpoint and service layer for text chunking for long content | 1 | Backend |
| APEP-425.d | APEP-425 | Wire API endpoint and service layer for async batch inference | 1 | Backend |
| APEP-426.d | APEP-426 | Wire API endpoint and service layer for Benchmark ONNX classifier against ToolTrust published metrics | 1 | Backend |

#### Sub-Sprint 53.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 53.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S53.6 | — | Security review and input validation audit for Sprint 53 | 0 | Security |

#### Sub-Sprint 53.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 53 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-420.e | APEP-420 | Integrate into pipeline: ONNXSemanticClassifier service | 1 | Backend |

#### Sub-Sprint 53.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 53 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S53.8 | — | Update SDK documentation and CLI help text for Sprint 53 | 0 | SDK |

#### Sub-Sprint 53.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 53 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-420.f | APEP-420 | Write unit tests for ONNXSemanticClassifier service | 1 | Testing |
| APEP-421.e | APEP-421 | Write unit tests for model download and SHA-256 verification | 1 | Testing |
| APEP-422.e | APEP-422 | Write unit tests for per-mode ONNX classification thresholds | 1 | Testing |
| APEP-423.e | APEP-423 | Write unit tests for text chunking for long content | 1 | Testing |
| APEP-424.c | APEP-424 | Write unit tests for model-absent graceful fallback | 1 | Testing |
| APEP-425.e | APEP-425 | Write unit tests for async batch inference | 1 | Testing |
| APEP-426.e | APEP-426 | Write unit tests for Benchmark ONNX classifier against ToolTrust published metrics | 1 | Testing |

#### Sub-Sprint 53.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 53.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-420.g | APEP-420 | Write integration tests for ONNXSemanticClassifier service | 1 | Testing |

#### Sub-Sprint 53.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 53 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-427.b | APEP-427 | Implement Prometheus metrics and Grafana dashboards: ONNX inference Prometheus metrics | 1 | Observability |

---

### Sprint 54 — Pre-Session Repository Scanner & Agent Instruction File Scanner

**Goal:** Build POST /v1/cis/scan-repo pre-session scanner; implement agent instruction file scanner with STRICT mode defaults; wire scan results to taint auto-labeling; build CIS findings screen in Policy Console.

#### Sub-Sprint 54.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 54 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-428.a | APEP-428 | Design architecture and interfaces for POST /v1/cis/scan-repo | 1 | Backend |
| APEP-429.a | APEP-429 | Design security model and threat surface for agent instruction file scanner | 1 | Security |
| APEP-430.a | APEP-430 | Design data model and interface for scan-on-session-start hook | 1 | Backend |
| APEP-431.a | APEP-431 | Design security architecture and threat model for PostToolUse auto-scan | 1 | Security |
| APEP-432.a | APEP-432 | Design data model and interface for POST /v1/cis/scan-file and POST /v1/cis/scan-text | 1 | Backend |
| APEP-433.a | APEP-433 | Design component wireframes, state model, and data flow for CIS Findings screen in Policy Console | 1 | Frontend |
| APEP-434.a | APEP-434 | Design SDK/CLI interface for SDK cis_scan(path_or_text) helper | 1 | SDK |

#### Sub-Sprint 54.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 54 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-428.b | APEP-428 | Implement Pydantic model and MongoDB schema for POST /v1/cis/scan-repo | 1 | Backend |
| APEP-430.b | APEP-430 | Implement Pydantic model and MongoDB schema for scan-on-session-start hook | 1 | Backend |
| APEP-431.b | APEP-431 | Define data model and schema for PostToolUse auto-scan | 1 | Backend |

#### Sub-Sprint 54.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for POST /v1/cis/scan-repo; agent instruction file scanner; scan-on-session-start hook.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-428.c | APEP-428 | Implement core logic: POST /v1/cis/scan-repo | 2 | Backend |
| APEP-429.b | APEP-429 | Implement core security logic: agent instruction file scanner | 1 | Security |
| APEP-430.c | APEP-430 | Implement core business logic: scan-on-session-start hook | 1 | Backend |
| APEP-431.c | APEP-431 | Implement core security logic: PostToolUse auto-scan | 2 | Security |

#### Sub-Sprint 54.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for POST /v1/cis/scan-file and POST /v1/cis/scan-text; CIS Findings screen in Policy Console; SDK cis_scan(path_or_text) helper.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-432.b | APEP-432 | Implement core logic: POST /v1/cis/scan-file and POST /v1/cis/scan-text | 1 | Backend |

#### Sub-Sprint 54.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 54 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-428.d | APEP-428 | Wire API endpoint and service layer for POST /v1/cis/scan-repo | 1 | Backend |
| APEP-430.d | APEP-430 | Wire API endpoint and service layer for scan-on-session-start hook | 1 | Backend |

#### Sub-Sprint 54.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 54.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-429.c | APEP-429 | Implement security guards and validation: agent instruction file scanner | 1 | Security |
| APEP-431.d | APEP-431 | Implement security guards and crypto: PostToolUse auto-scan | 1 | Security |

#### Sub-Sprint 54.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 54 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-428.e | APEP-428 | Integrate into pipeline: POST /v1/cis/scan-repo | 1 | Backend |
| APEP-429.d | APEP-429 | Integrate into enforcement pipeline: agent instruction file scanner | 1 | Security |
| APEP-431.e | APEP-431 | Integrate into enforcement pipeline: PostToolUse auto-scan | 1 | Security |

#### Sub-Sprint 54.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 54 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-433.b | APEP-433 | Implement component structure and state management: CIS Findings screen in Policy Console | 2 | Frontend |
| APEP-433.c | APEP-433 | Implement component rendering and interaction: CIS Findings screen in Policy Console | 2 | Frontend |
| APEP-433.d | APEP-433 | Polish and integrate UI component: CIS Findings screen in Policy Console | 1 | Frontend |
| APEP-434.b | APEP-434 | Implement SDK/CLI: SDK cis_scan(path_or_text) helper | 1 | SDK |

#### Sub-Sprint 54.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 54 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-428.f | APEP-428 | Write unit tests for POST /v1/cis/scan-repo | 1 | Testing |
| APEP-429.e | APEP-429 | Write security validation tests for agent instruction file scanner | 1 | Testing |
| APEP-430.e | APEP-430 | Write unit tests for scan-on-session-start hook | 1 | Testing |
| APEP-431.f | APEP-431 | Write unit tests for PostToolUse auto-scan | 1 | Testing |
| APEP-432.c | APEP-432 | Write unit tests for POST /v1/cis/scan-file and POST /v1/cis/scan-text | 1 | Testing |
| APEP-433.e | APEP-433 | Write component tests for CIS Findings screen in Policy Console | 1 | Testing |
| APEP-434.c | APEP-434 | Write tests for SDK/CLI: SDK cis_scan(path_or_text) helper | 1 | Testing |
| APEP-435.a | APEP-435 | Write unit and component tests: adversarial tests | 2 | Testing |

#### Sub-Sprint 54.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 54.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-428.g | APEP-428 | Write integration tests for POST /v1/cis/scan-repo | 1 | Testing |
| APEP-431.g | APEP-431 | Write adversarial tests for PostToolUse auto-scan | 1 | Testing |
| APEP-433.f | APEP-433 | Write E2E tests for CIS Findings screen in Policy Console | 1 | Testing |
| APEP-435.b | APEP-435 | Write integration and adversarial tests: adversarial tests | 3 | Testing |

#### Sub-Sprint 54.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 54 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S54.11 | — | Sprint 54 documentation and deliverable validation | 0 | Docs |

---

### Sprint 55 — CaMeL SEQ Rules, Layer 3 Bridge & Self-Protection

**Goal:** Import ToolTrust CaMeL-lite SEQ rules into Phase 10 tool call chain detector; build ToolTrust Layer 3 to AgentPEP Intercept bridge; implement agent-initiated policy modification self-protection.

#### Sub-Sprint 55.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 55 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-436.a | APEP-436 | Design security model and threat surface for Import ToolTrust CaMeL-lite SEQ rules as named chain patterns in Phase 10 Too... | 1 | Security |
| APEP-437.a | APEP-437 | Design data model and interface for session-wide typed marker system for SEQ-001/002 | 1 | Backend |
| APEP-438.a | APEP-438 | Design SDK/CLI interface for ToolTrust -> AgentPEP Intercept bridge | 1 | SDK |
| APEP-439.a | APEP-439 | Design data model and interface for CIS scan verdict as taint input | 1 | Backend |
| APEP-440.a | APEP-440 | Design security model and threat surface for agent-initiated policy modification self-protection | 1 | Security |
| APEP-441.a | APEP-441 | Design security model for protected path patterns for PreToolUse | 1 | Security |

#### Sub-Sprint 55.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 55 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-437.b | APEP-437 | Implement Pydantic model and MongoDB schema for session-wide typed marker system for SEQ-001/002 | 1 | Backend |
| APEP-439.b | APEP-439 | Implement Pydantic model and MongoDB schema for CIS scan verdict as taint input | 1 | Backend |

#### Sub-Sprint 55.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for Import ToolTrust CaMeL-lite SEQ rules as named chain patterns in Phase 10 ToolCallChainDetector (APEP-388); session-wide typed marker system for SEQ-001/002; ToolTrust -> AgentPEP Intercept bridge.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-436.b | APEP-436 | Implement core security logic: Import ToolTrust CaMeL-lite SEQ rules as named chain patterns in Phase 10 Too... | 1 | Security |
| APEP-437.c | APEP-437 | Implement core business logic: session-wide typed marker system for SEQ-001/002 | 1 | Backend |
| APEP-438.b | APEP-438 | Implement core logic: ToolTrust -> AgentPEP Intercept bridge | 2 | Backend |
| APEP-439.c | APEP-439 | Implement core business logic: CIS scan verdict as taint input | 1 | Backend |

#### Sub-Sprint 55.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for agent-initiated policy modification self-protection; protected path patterns for PreToolUse; self-protection adversarial tests.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-440.b | APEP-440 | Implement core security logic: agent-initiated policy modification self-protection | 1 | Security |

#### Sub-Sprint 55.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 55 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-437.d | APEP-437 | Wire API endpoint and service layer for session-wide typed marker system for SEQ-001/002 | 1 | Backend |
| APEP-438.d | APEP-438 | Wire API endpoints for ToolTrust -> AgentPEP Intercept bridge | 1 | Backend |
| APEP-439.d | APEP-439 | Wire API endpoint and service layer for CIS scan verdict as taint input | 1 | Backend |

#### Sub-Sprint 55.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 55.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-436.c | APEP-436 | Implement security guards and validation: Import ToolTrust CaMeL-lite SEQ rules as named chain patterns in Phase 10 Too... | 1 | Security |
| APEP-440.c | APEP-440 | Implement security guards and validation: agent-initiated policy modification self-protection | 1 | Security |
| APEP-441.b | APEP-441 | Implement security logic: protected path patterns for PreToolUse | 1 | Security |

#### Sub-Sprint 55.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 55 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-436.d | APEP-436 | Integrate into enforcement pipeline: Import ToolTrust CaMeL-lite SEQ rules as named chain patterns in Phase 10 Too... | 1 | Security |
| APEP-440.d | APEP-440 | Integrate into enforcement pipeline: agent-initiated policy modification self-protection | 1 | Security |

#### Sub-Sprint 55.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 55 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-438.c | APEP-438 | Implement SDK/CLI wrapper: ToolTrust -> AgentPEP Intercept bridge | 2 | SDK |

#### Sub-Sprint 55.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 55 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-436.e | APEP-436 | Write security validation tests for Import ToolTrust CaMeL-lite SEQ rules as named chain patterns in Phase 10 Too... | 1 | Testing |
| APEP-437.e | APEP-437 | Write unit tests for session-wide typed marker system for SEQ-001/002 | 1 | Testing |
| APEP-438.e | APEP-438 | Write unit tests for ToolTrust -> AgentPEP Intercept bridge | 1 | Testing |
| APEP-439.e | APEP-439 | Write unit tests for CIS scan verdict as taint input | 1 | Testing |
| APEP-440.e | APEP-440 | Write security validation tests for agent-initiated policy modification self-protection | 1 | Testing |
| APEP-441.c | APEP-441 | Write security tests for protected path patterns for PreToolUse | 1 | Testing |
| APEP-442.a | APEP-442 | Write unit and component tests: self-protection adversarial tests | 2 | Testing |
| APEP-443.a | APEP-443 | Write unit and component tests: ToolTrust bridge integration test | 2 | Testing |

#### Sub-Sprint 55.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 55.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-438.f | APEP-438 | Write integration tests for ToolTrust -> AgentPEP Intercept bridge | 1 | Testing |
| APEP-442.b | APEP-442 | Write integration and adversarial tests: self-protection adversarial tests | 3 | Testing |
| APEP-443.b | APEP-443 | Write integration and adversarial tests: ToolTrust bridge integration test | 1 | Testing |

#### Sub-Sprint 55.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 55 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S55.11 | — | Sprint 55 documentation and deliverable validation | 0 | Docs |

---

### Sprint 56 — YOLO Mode, Session Risk Multiplier & Developer Experience

**Goal:** Finalise YOLO mode session risk escalation; build per-session scan mode configuration; publish CIS documentation and integration guides; add CIS metrics to Grafana dashboard.

#### Sub-Sprint 56.1 — Architecture & Design

**Goal:** Design data models, interfaces, and API contracts for all Sprint 56 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-444.a | APEP-444 | Design data model and interface for per-session scan mode configuration | 1 | Backend |
| APEP-445.a | APEP-445 | Design security model and threat surface for YOLO mode session flag propagation | 1 | Security |
| APEP-446.a | APEP-446 | Design SDK/CLI interface for YOLO mode detection via environment probe | 1 | SDK |
| APEP-447.a | APEP-447 | Design component wireframes and state model for CIS Dashboard widget in Policy Console | 1 | Frontend |
| APEP-448.a | APEP-448 | Design data model and interface for CIS scan results to compliance exports | 1 | Backend |
| APEP-449.a | APEP-449 | Design metrics schema and dashboard layout for CIS Prometheus metrics | 1 | Observability |

#### Sub-Sprint 56.2 — Data Models & Schema

**Goal:** Implement Pydantic models, MongoDB collections, indexes, and schema migrations for Sprint 56 data entities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-450.a | APEP-450 | Outline documentation structure for CIS documentation | 1 | Docs |

#### Sub-Sprint 56.3 — Core Backend Logic (Part 1)

**Goal:** Implement core business logic for per-session scan mode configuration; YOLO mode session flag propagation; YOLO mode detection via environment probe.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-444.b | APEP-444 | Implement core logic: per-session scan mode configuration | 1 | Backend |
| APEP-445.b | APEP-445 | Implement core security logic: YOLO mode session flag propagation | 1 | Security |

#### Sub-Sprint 56.4 — Core Backend Logic (Part 2)

**Goal:** Implement core business logic for CIS scan results to compliance exports; CIS Prometheus metrics; CIS documentation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-448.b | APEP-448 | Implement core logic: CIS scan results to compliance exports | 1 | Backend |

#### Sub-Sprint 56.5 — API Endpoints & Service Wiring

**Goal:** Expose REST/gRPC endpoints and wire service layer for Sprint 56 capabilities.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-S56.5 | — | Review API contracts and OpenAPI spec for Sprint 56 endpoints | 0 | Backend |

#### Sub-Sprint 56.6 — Security & Validation Logic

**Goal:** Implement security-specific logic: validators, guards, cryptographic operations, and access control for Sprint 56.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-445.c | APEP-445 | Implement security guards and validation: YOLO mode session flag propagation | 1 | Security |

#### Sub-Sprint 56.7 — Pipeline Integration & Event Wiring

**Goal:** Integrate Sprint 56 components into the PolicyEvaluator pipeline, Kafka event streams, and taint propagation.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-445.d | APEP-445 | Integrate into enforcement pipeline: YOLO mode session flag propagation | 1 | Security |

#### Sub-Sprint 56.8 — Frontend, SDK & CLI

**Goal:** Build UI components, SDK helpers, and CLI commands for Sprint 56 features.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-446.b | APEP-446 | Implement SDK/CLI: YOLO mode detection via environment probe | 1 | SDK |
| APEP-447.b | APEP-447 | Implement UI component: CIS Dashboard widget in Policy Console | 2 | Frontend |

#### Sub-Sprint 56.9 — Unit & Component Testing

**Goal:** Write unit tests and component tests for all Sprint 56 implementations.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-444.c | APEP-444 | Write unit tests for per-session scan mode configuration | 1 | Testing |
| APEP-445.e | APEP-445 | Write security validation tests for YOLO mode session flag propagation | 1 | Testing |
| APEP-446.c | APEP-446 | Write tests for SDK/CLI: YOLO mode detection via environment probe | 1 | Testing |
| APEP-447.c | APEP-447 | Write component tests for CIS Dashboard widget in Policy Console | 1 | Testing |
| APEP-448.c | APEP-448 | Write unit tests for CIS scan results to compliance exports | 1 | Testing |
| APEP-451.a | APEP-451 | Write unit and component tests: CIS end-to-end integration test | 2 | Testing |

#### Sub-Sprint 56.10 — Integration Testing & Performance

**Goal:** Run integration tests, adversarial tests, and performance benchmarks for Sprint 56.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-447.d | APEP-447 | Write E2E tests for CIS Dashboard widget in Policy Console | 1 | Testing |
| APEP-451.b | APEP-451 | Write integration and adversarial tests: CIS end-to-end integration test | 3 | Testing |

#### Sub-Sprint 56.11 — Documentation, Metrics & Sprint Validation

**Goal:** Write documentation, configure Prometheus metrics, and validate Sprint 56 deliverables.

| Sub-Task ID | Parent Story | Description | Points | Area |
|---|---|---|---|---|
| APEP-449.b | APEP-449 | Implement Prometheus metrics and Grafana dashboards: CIS Prometheus metrics | 2 | Observability |
| APEP-450.b | APEP-450 | Write and publish documentation: CIS documentation | 2 | Docs |


---

## 15.7 Sprint Summary - Phase 11

| Sprint | Name | Phase | Stories |
|---|---|---|---|
| 52 | Extended Pattern Library & Scan Mode Router | Phase 11: ToolTrust-Inspired v4 | 8 stories → 11 sub-sprints |
| 53 | ONNX Semantic Injection Classifier (Tier 1) | Phase 11: ToolTrust-Inspired v4 | 8 stories → 11 sub-sprints |
| 54 | Pre-Session Repository Scanner & Instruction File Scanner | Phase 11: ToolTrust-Inspired v4 | 8 stories → 11 sub-sprints |
| 55 | CaMeL SEQ Rules, Layer 3 Bridge & Self-Protection | Phase 11: ToolTrust-Inspired v4 | 8 stories → 11 sub-sprints |
| 56 | YOLO Mode, Session Risk Multiplier & Developer Experience | Phase 11: ToolTrust-Inspired v4 | 8 stories → 11 sub-sprints |

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
