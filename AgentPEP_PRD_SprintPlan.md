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
| **Sprint Count** | 36 Sprints · ~18 Months |
| **Total Stories** | ~291 User Stories |

---

## Document Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | Apr 2026 | Product Team | Initial PRD draft — architecture, features, sprint plan |
| 1.1 | Apr 2026 | Product Team | **Roadmap v1** — AgentZT enhancement analysis and sprint plan (Sprints 29–36) |

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
12. [AgentZT Enhancement Roadmap v1](#12-agentzt-enhancement-roadmap-v1)

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
| 29 | AgentZT — Backend ABCs & Async Architecture | Phase 8: AgentZT Roadmap v1 | 8 |
| 30 | AgentZT — YAML Policy Loading & Offline Evaluation | Phase 8: AgentZT Roadmap v1 | 8 |
| 31 | AgentZT — Auth Providers & Redis Backend | Phase 8: AgentZT Roadmap v1 | 9 |
| 32 | AgentZT — Structured Logging & Notification Channels | Phase 8: AgentZT Roadmap v1 | 8 |
| 33 | AgentZT — Framework Integrations (OpenAI Agents, LangGraph) | Phase 8: AgentZT Roadmap v1 | 8 |
| 34 | AgentZT — Testing Utilities, Simulation & Enhanced CLI | Phase 8: AgentZT Roadmap v1 | 9 |
| 35 | AgentZT — Injection Library, Arg Validation & Risk Scoring | Phase 8: AgentZT Roadmap v1 | 9 |
| 36 | AgentZT — Conflict Detection, Metrics, Tamper Detection & Multi-Tenancy | Phase 8: AgentZT Roadmap v1 | 8 |

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

# 12. AgentZT Enhancement Roadmap v1

## 12.1 Overview

This section documents enhancements to AgentPEP inspired by analysis of [AgentZT](https://github.com/webpro255/agentzt) — an open-source authorization security framework for AI agent systems. AgentZT implements an infrastructure-level authorization layer between agents and their tools, using a three-layer enforcement architecture (Conversation → Authorization Gate → Tool Execution). While AgentPEP already provides a robust deterministic authorization engine, AgentZT introduces several architectural patterns and security mechanisms that would meaningfully strengthen AgentPEP's capabilities.

**Analysis Date:** April 2026
**Scope:** 8 sprints (Sprints 29–36) · 67 stories · ~16 weeks

## 12.2 Gap Analysis: AgentZT vs AgentPEP

The following table summarises capabilities present in AgentZT that are absent or under-developed in AgentPEP, along with their assessed enhancement priority.

| # | AgentZT Capability | AgentPEP Current State | Gap | Priority |
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
│  Existing Stages              New Stages (AgentZT-inspired)   │
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

AgentZT introduces two decision types beyond AgentPEP's current `ALLOW / DENY / ESCALATE / DRY_RUN`:

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

## 12.5 Detailed Sprint Plans — Phase 8: AgentZT Roadmap v1

### Sprint 29 — AgentZT: Backend ABCs & Async Architecture

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

### Sprint 30 — AgentZT: YAML Policy Loading & Offline Evaluation

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

### Sprint 31 — AgentZT: Auth Providers & Redis Backend

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

### Sprint 32 — AgentZT: Structured Logging & Notification Channels

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

### Sprint 33 — AgentZT: Framework Integrations (OpenAI Agents, LangGraph)

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

### Sprint 34 — AgentZT: Testing Utilities, Simulation & Enhanced CLI

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

### Sprint 35 — AgentZT: Injection Library, Arg Validation & Risk Scoring

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
| APEP-283 | Enhance injection signature library: add social engineering patterns, encoding attack patterns, and reconnaissance signatures from AgentZT findings | 3 | Security |
| APEP-284 | Write adversarial tests: tool combo evasion, velocity gaming, echo bypass, hardening effectiveness validation | 5 | Testing |

### Sprint 36 — AgentZT: Conflict Detection, Metrics, Tamper Detection & Multi-Tenancy

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

| Dimension | Before (v1.0 GA) | After (v1.1 with AgentZT Enhancements) |
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
| **Total stories** | ~224 (Sprints 1–28) | ~291 (+ 67 AgentZT enhancement stories) |

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
