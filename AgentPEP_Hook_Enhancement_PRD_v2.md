# AgentPEP Hook Enhancement PRD
## Runtime Enforcement Architecture — Reference Monitor Upgrade
**Version:** 2.1 (Revised — AAPM Boundary Corrections)
**Author:** TrustFabric Product Architecture
**Status:** Draft — Internal Review
**Date:** April 2026
**Classification:** TrustFabric Confidential
**Supersedes:** v2.0 (April 2026)

---

## Revision Notes (v2.0 → v2.1)

The following changes were made after cross-checking against the AAPM (AI Agent Policy Management) product:

| Change | Rationale |
|--------|-----------|
| FEATURE-01 scope reduced — policy bundle management removed | AAPM owns policy lifecycle (PCR workflow, versioning, signing, audit trail). AgentPEP is a consumer, not an author. |
| FEATURE-02 scope reduced — bundle build script removed | Cosign signing of bundles is AAPM's responsibility before publishing to the TrustFabric Policy Registry. |
| New FEATURE-09: AAPM → AgentPEP Integration Contract | The feed mechanism from AAPM Policy Registry to AgentPEP was entirely absent in v2.0. |
| FEATURE-06 updated — Blast Radius Score added | AAPM's Blast Radius Calculator (Neo4j, Sprint 12) feeds posture matrix at session initialisation. |
| FEATURE-07 updated — MITRE ATLAS IDs added | AgentPEP bypass vectors mapped to AAPM's threat taxonomy to create a single portfolio threat model. |

**Architectural Boundary Established:**
> AAPM compiles, signs, and publishes policy bundles. AgentPEP loads, verifies, and enforces them. One policy registry. One audit trail (in AAPM). One authoring language (APDL → compiled to Rego). One runtime enforcement engine (in AgentPEP).

---

## 1. Executive Summary

AgentPEP was designed as a deterministic Policy Enforcement Point at the AI agent tool-call boundary. This enhancement PRD formalises a second-generation architecture upgrade driven by three converging signals:

1. **Industry convergence** — Every major coding agent platform (Claude Code, Cursor, Windsurf, GitHub Copilot, Cline) has independently arrived at the same architectural pattern: pre- and post-tool-use interception hooks backed by declarative policy evaluation. Enterprise vendors (Zenity, Microsoft Agent Governance Toolkit) are extending this pattern to SaaS-embedded and homegrown agents.

2. **Disclosed bypass vectors** — Published CVEs and adversarial research (CVE-2025-59536, CVE-2026-21852, Adversa AI 50-subcommand bypass, Praetorian hook-gaming demonstration) have mapped concrete weaknesses in first-generation hook implementations that AgentPEP must explicitly address.

3. **Reference monitor standard** — Academic research (PCAS, "Trustworthy Agentic AI Requires Deterministic Architectural Boundaries") formalises the classical reference monitor pattern as the correct architectural anchor for agentic enforcement, with empirical evidence: uninstrumented agents achieve 48% policy compliance; reference-monitor-instrumented agents achieve 93% with zero violations.

This PRD defines the feature upgrades, architectural changes, and integration contracts required to position AgentPEP as a **certified enterprise reference monitor** — the highest standard of deterministic enforcement for agentic AI systems — while maintaining clean product boundaries within the TrustFabric portfolio.

---

## 2. Background and Context

### 2.1 TrustFabric Portfolio Boundary

AgentPEP operates within the TrustFabric portfolio with the following boundary with AAPM:

```
AAPM (AI Agent Policy Management)
│  Owns: Policy authoring (APDL), PCR workflow, versioning,
│        cosign signing, Policy Registry, audit trail,
│        Blast Radius Calculator, compliance modules
│  Role: Policy Author + Lifecycle Manager
│
│  Publishes signed Rego bundles to:
│         TrustFabric Policy Registry
│                    │
▼                    ▼
AgentPEP (This Product)
│  Owns: Policy loading, load-time integrity verification,
│        runtime OPA evaluation, PreToolUse enforcement,
│        PostToolUse event emission, trust degradation
│  Role: Policy Consumer + Runtime Enforcer
```

This boundary is the governing constraint for all features in this PRD. Any capability that belongs to the "Policy Author + Lifecycle Manager" role is out of scope for AgentPEP and must be implemented in or consumed from AAPM.

### 2.2 Current AgentPEP Architecture

AgentPEP v1.x implements:
- Deny-by-default RBAC at the tool-call boundary
- FAIL_CLOSED default posture
- Three taint levels (L1 / L2 / L3) governing data sensitivity
- Five-hop delegation chain depth limit
- PreToolUse interception as primary enforcement mechanism

### 2.3 Architecture Gaps Identified

| Gap | Category | Risk |
|-----|----------|------|
| Policies expressed imperatively, not declaratively | Scalability | Enterprise auditability fails |
| No defined policy consumer interface against AAPM Registry | Integration | Policy source of truth ambiguous |
| Policy definitions can be loaded from untrusted paths | Security | Config injection attack vector |
| Evaluation failure falls back to permissive behaviour | Security | Complexity-based bypass |
| Hop counter does not enforce recursive PEP invocation | Security | Subagent trust escalation |
| No PostToolUse hook formalised | Detection | Blind to chained action abuse |
| Taint levels not crossed with deployment tier or blast radius | Coverage | Incomplete posture logic |
| No named bypass threat model with MITRE ATLAS mapping | Compliance | CISO/auditor credibility gap |
| No reference monitor compliance statement | Positioning | Enterprise differentiation gap |

---

## 3. Goals and Non-Goals

### 3.1 Goals

- Satisfy all three classical reference monitor criteria: always invoked, tamper-proof, verifiable
- Introduce a runtime OPA/Rego Policy Decision Point (PDP) as a **policy consumer** (not author)
- Define a clean integration contract consuming policy bundles published by AAPM
- Harden AgentPEP against all four documented bypass vector classes
- Formalise PostToolUse hooks and define the TrustSOC integration contract
- Introduce an enforcement posture matrix (taint level × deployment tier × blast radius)
- Replace hop-counting with recursive PEP invocation and trust degradation
- Define AgentRT as AgentPEP's mandatory adversarial validation harness

### 3.2 Non-Goals

- **Policy authoring, versioning, PCR workflow, or audit trail** — owned by AAPM
- **Cosign signing of policy bundles** — AAPM signs before publishing to the registry
- **Policy bundle build pipeline** — AAPM's responsibility
- **MITRE ATLAS / OWASP LLM Top 10 threat taxonomy** — defined in AAPM; AgentPEP references, does not own
- **Blast Radius Calculator** — owned by AAPM (Neo4j, Sprint 12); AgentPEP consumes the score
- **Governing agent internal reasoning** — acknowledged residual risk; mitigated by TrustSOC sequence analysis
- **Standalone SIEM or SOC capability** — owned by TrustSOC

---

## 4. User Personas

| Persona | Role | Primary Concern |
|---------|------|-----------------|
| Enterprise Security Architect | Designs enforcement architecture | Reference monitor compliance, framework agnosticism |
| CISO | Accountable for agent risk | Audit trails, policy governance, regulatory defensibility |
| Compliance Officer | Audits controls | Policy readability (via AAPM), change history (via AAPM), TRQF mapping |
| Platform Engineering Lead | Deploys and operates AgentPEP | Integration contracts, latency, operational overhead |
| Red Team / AgentRT Operator | Adversarially validates enforcement | Bypass coverage, test harness integration |

---

## 5. Feature Specifications

---

### FEATURE-01: Runtime Policy Decision Point (PDP) — Consumer Mode

**Priority:** Tier 1 — Architectural
**TRQF Controls:** TRQF-PEP-01, TRQF-PEP-04, TRQF-GOV-02
**Boundary Note:** AgentPEP owns the OPA engine and runtime evaluation only. Policy authoring, bundle management, versioning, and audit trail are AAPM's domain.

#### 5.1.1 Problem Statement

Current AgentPEP evaluates policy through imperative rule logic embedded in application code. This fails enterprise auditability and does not integrate with AAPM's policy lifecycle. AgentPEP needs a declarative runtime evaluation engine that loads and executes policies authored and published by AAPM — without duplicating AAPM's governance capabilities.

#### 5.1.2 Solution

Introduce a **Runtime Policy Decision Point (PDP)** backed by an OPA/Rego engine that:
- Loads signed Rego bundles from the TrustFabric Policy Registry (published by AAPM)
- Evaluates structured authorisation requests at PreToolUse and PostToolUse
- Returns structured decisions (ALLOW / DENY / MODIFY + reason code)
- Emits enforcement decision events (not policy change events — those belong in AAPM)

AgentPEP does NOT author Rego directly. The Rego bundles are compiled outputs of AAPM's APDL authoring pipeline. AgentPEP's OPA engine is a runtime consumer of those outputs.

#### 5.1.3 Architecture

```
AAPM Policy Registry (Source of Truth)
      │
      │  Signed Rego Bundle (cosign, published by AAPM)
      ▼
AgentPEP Policy Loader ──► Integrity Verification (FEATURE-02)
      │
      ▼
OPA/Rego Runtime Engine (AgentPEP)
      │
      ├── PreToolUse Interceptor sends authorisation request
      │
      ▼
 ALLOW / DENY / MODIFY + reason code
      │
      ▼
PostToolUse Hook ──► Enforcement Decision Event (OCSF) ──► TrustSOC
```

#### 5.1.4 Authorisation Request Schema

```json
{
  "input": {
    "principal": {
      "agent_id": "string",
      "delegation_chain": ["agent_id_1", "agent_id_2"],
      "trust_score": 0.85,
      "roles": ["analyst", "read_only"],
      "blast_radius_score": 0.62
    },
    "action": {
      "tool_name": "string",
      "tool_args": {},
      "taint_level": 2,
      "deployment_tier": "saas_embedded"
    },
    "resource": {
      "type": "string",
      "classification": "confidential",
      "owner_org": "string"
    },
    "context": {
      "session_id": "string",
      "hop_number": 2,
      "timestamp_utc": "ISO8601",
      "policy_bundle_version": "1.4.2"
    }
  }
}
```

#### 5.1.5 Enforcement Decision Audit Log

AgentPEP emits **enforcement decision logs** — what was evaluated, what was decided, at what latency, against which bundle version. This is distinct from AAPM's **policy change audit log** (who changed the policy and why). Both exist; neither duplicates the other.

```json
{
  "event_type": "enforcement_decision",
  "session_id": "string",
  "agent_id": "string",
  "tool_name": "string",
  "decision": "DENY",
  "reason_code": "TAINT_L3_SAAS_DENY",
  "policy_bundle_version": "1.4.2",
  "policy_rule_id": "taint_l3.deny_saas_embedded",
  "evaluation_latency_ms": 6.2,
  "timestamp_utc": "ISO8601"
}
```

#### 5.1.6 Acceptance Criteria

- [ ] OPA engine integrated; all policy logic evaluated via Rego (no imperative rules remain)
- [ ] Rego bundles loaded exclusively from AAPM-published registry (not from local paths)
- [ ] Enforcement decision log emitted for every evaluation (ALLOW and DENY)
- [ ] PDP evaluation latency P99 < 10ms under 1,000 concurrent evaluations
- [ ] Bundle version recorded in every enforcement decision log
- [ ] Rego bundles are not authored or owned by AgentPEP team

---

### FEATURE-02: Trusted Policy Loader with Integrity Verification

**Priority:** Tier 1 — Architectural
**CVE Addressed:** CVE-2025-59536, CVE-2026-21852
**TRQF Controls:** TRQF-PEP-02, TRQF-SUPPLY-01
**Boundary Note:** AAPM signs bundles before publishing. AgentPEP verifies signatures at load time. AgentPEP does NOT build or sign bundles.

#### 5.2.1 Problem Statement

CVE-2025-59536 demonstrated that when hook definitions can be loaded from a repository-local config file, an attacker controlling the repository can inject a malicious hook that executes before any trust dialog. The enforcement layer itself becomes an attack vector. AgentPEP must verify the integrity of every policy bundle it loads and reject any bundle from an untrusted source.

#### 5.2.2 Solution

Implement a **Trusted Policy Loader** that:
- Accepts policy bundles only from the TrustFabric Policy Registry URL (allowlisted, TLS-pinned)
- Verifies the cosign signature on every bundle before loading (public key pinned in binary)
- Rejects any policy source from the agent's operational path (working directory, env vars, agent-writable config)
- Emits SECURITY_VIOLATION events on any rejected load attempt

AAPM is responsible for signing bundles with cosign before publishing. AgentPEP verifies, but does not sign.

#### 5.2.3 Trust Verification Flow

```
TrustFabric Policy Registry (published and signed by AAPM)
        │
        │  HTTPS + TLS pinning
        ▼
AgentPEP Policy Loader
        │
        ├── Source path allowlist check → REJECT if not registry URL
        ├── cosign signature verification → REJECT if invalid (FAIL_CLOSED)
        ├── Bundle format validation → REJECT if malformed
        └── Load into OPA engine memory (never disk-cached in agent path)
```

#### 5.2.4 Enforcement Rules

- AgentPEP binary ships with a pinned public key for bundle signature verification
- Only the TrustFabric Policy Registry URL is an allowlisted source
- Any attempt to load from working directory, env var, or CLI flag → SECURITY_VIOLATION + DENY
- Policy reload requires full signature re-verification

#### 5.2.5 Acceptance Criteria

- [ ] Policy loader rejects any bundle with invalid or missing cosign signature
- [ ] Policy loader rejects any source not on the registry allowlist
- [ ] Tampered bundle injection attempt generates SECURITY_VIOLATION event in TrustSOC
- [ ] Policy public key pinned in binary; cannot be overridden at runtime
- [ ] Penetration test: repo-local config injection blocked with DENY + SECURITY_VIOLATION alert

---

### FEATURE-03: Complexity-as-Deny-Signal with Evaluation Timeout FAIL_CLOSED

**Priority:** Tier 1 — Architectural
**Bypass Addressed:** Adversa AI 50-subcommand bypass (March 2026)
**TRQF Controls:** TRQF-PEP-03, TRQF-RES-01

#### 5.3.1 Problem Statement

Adversa AI disclosed that Claude Code silently skipped deny rules when a shell command contained more than 50 subcommands, because a hard cap was introduced to avoid UI freezes. When the limit was exceeded, enforcement fell back to a generic prompt that could be auto-allowed. The root failure: **evaluation failure resulted in permissive fallback**. This inverts the security model.

#### 5.3.2 Evaluation Guarantee Invariant

> *If AgentPEP cannot fully evaluate a tool call within defined resource bounds, the decision is DENY. The agent is informed that the action was denied due to evaluation complexity. No action is taken. This invariant has no exceptions.*

#### 5.3.3 Complexity Budget Parameters

| Parameter | Default | Configurable |
|-----------|---------|--------------|
| Max tool call argument size | 64 KB | Yes (operator) |
| Max subcommand count | 20 | Yes (operator) |
| Max argument nesting depth | 10 | Yes (operator) |
| PDP evaluation timeout | 50ms | Yes (operator) |
| Action on budget exceeded | DENY + COMPLEXITY_EXCEEDED event | No |

#### 5.3.4 Acceptance Criteria

- [ ] Tool calls exceeding any budget parameter denied before PDP evaluation begins
- [ ] PDP evaluation timeout triggers DENY, not fallback-to-allow
- [ ] COMPLEXITY_EXCEEDED events emitted to TrustSOC audit stream
- [ ] AgentRT regression suite includes compound command bypass test cases
- [ ] No operator configuration can set the budget-exceeded action to ALLOW

---

### FEATURE-04: Recursive PEP Invocation with Trust Degradation

**Priority:** Tier 1 — Architectural
**Current Behaviour:** 5-hop delegation depth counter
**TRQF Controls:** TRQF-IAM-03, TRQF-PEP-05, TRQF-DELEG-01

#### 5.4.1 Problem Statement

The current 5-hop delegation limit checks depth but does not enforce recursive PEP invocation per hop. A subagent at hop 3 may carry the full permissions of the delegating agent at hop 2, rather than being constrained to the root principal's permissions. This allows trust to accumulate across delegation chains rather than degrade.

#### 5.4.2 Recursive Trust Evaluation Model

1. Every tool call at any hop triggers a full PDP evaluation
2. The evaluation input carries the complete delegation chain (all principal IDs from root to current agent)
3. Effective permission set = intersection of root principal's permissions and current agent's permissions
4. Trust score degrades at each hop using a configurable decay function (default: linear 15% reduction per hop)
5. Chain terminates when trust score drops below minimum viable threshold

#### 5.4.3 Trust Score Model

```
TrustScore(hop_n) = TrustScore(hop_0) × (1 - decay_rate)^n

Default decay_rate      = 0.15
TrustScore(hop_0)       = 1.0 (root principal, fully authenticated)
TrustScore(hop_5)       = 1.0 × (0.85)^5 ≈ 0.44

Minimum viable trust threshold = 0.50 (configurable per deployment)
→ Chain terminates at first hop where score drops below threshold
```

#### 5.4.4 Delegation Context Propagation

Every tool call context carries:

```json
{
  "delegation_chain": [
    {"agent_id": "root-agent-001", "trust_score": 1.0, "hop": 0},
    {"agent_id": "sub-agent-002", "trust_score": 0.85, "hop": 1},
    {"agent_id": "sub-agent-003", "trust_score": 0.72, "hop": 2}
  ],
  "effective_permissions": ["read:data_l1", "write:report"],
  "chain_root_principal": "user-principal-xyz"
}
```

#### 5.4.5 Acceptance Criteria

- [ ] Every subagent tool call triggers full PDP evaluation with delegation chain in context
- [ ] Effective permissions never exceed root principal's permissions
- [ ] Trust score decays correctly; chain terminates below minimum threshold
- [ ] Trust escalation attempt generates TRUST_VIOLATION event
- [ ] AgentRT includes delegation chain abuse test cases

---

### FEATURE-05: PostToolUse Hook with TrustSOC Integration Contract

**Priority:** Tier 2 — Feature Addition
**TRQF Controls:** TRQF-DET-01, TRQF-AUD-02

#### 5.5.1 Problem Statement

AgentPEP currently focuses on PreToolUse enforcement. PostToolUse events are not formalised as a hook type and have no defined event schema or integration contract with TrustSOC. This creates a detection blind spot for chained action abuse, where individually permissible actions combine into a harmful sequence.

#### 5.5.2 PostToolUse Event Schema (OCSF)

```json
{
  "class_uid": 6001,
  "class_name": "AgentPEP.PostToolUseEvent",
  "time": "ISO8601",
  "session_uid": "string",
  "sequence_id": "string",
  "agent": {
    "agent_id": "string",
    "hop_number": 0,
    "trust_score": 1.0,
    "blast_radius_score": 0.62
  },
  "tool": {
    "name": "string",
    "args_hash": "sha256",
    "execution_duration_ms": 120
  },
  "outcome": {
    "status": "success | failure | partial",
    "data_taint_observed": 2,
    "output_size_bytes": 4096,
    "anomaly_signals": []
  },
  "policy": {
    "bundle_version": "1.4.2",
    "rule_evaluated": "taint_l2.allow_read",
    "decision": "ALLOW"
  }
}
```

#### 5.5.3 TrustSOC Integration Contract

| Property | Value |
|----------|-------|
| Transport | Kafka topic: `agentpep.posttooluse.events` |
| Serialisation | OCSF JSON |
| Delivery guarantee | At-least-once |
| Max event latency | 500ms from tool call completion |
| TrustSOC consumer | AgentBehaviourAnalyser module |
| Retention | 90 days (configurable per regulatory requirement) |

#### 5.5.4 Acceptance Criteria

- [ ] PostToolUse events emitted for every completed tool call (ALLOW and DENY)
- [ ] Sequence ID links PreToolUse and PostToolUse events for the same invocation
- [ ] Events conform to TrustFabric OCSF Profile schema (validated by schema linter in CI)
- [ ] TrustSOC receives events within 500ms SLA under load
- [ ] Event stream is tamper-evident (HMAC signature on each event)

---

### FEATURE-06: Enforcement Posture Matrix (Taint Level × Deployment Tier × Blast Radius)

**Priority:** Tier 2 — Feature Addition
**TRQF Controls:** TRQF-PEP-06, TRQF-RISK-02
**Dependency:** AAPM Blast Radius Calculator (Sprint 12) — score consumed at session initialisation

#### 5.6.1 Problem Statement

AgentPEP's three taint levels govern data sensitivity but do not account for deployment context or the reach of a compromised agent. A taint-L3 access by a high-blast-radius SaaS-embedded agent is materially more dangerous than the same access by a low-blast-radius endpoint agent. Enforcement posture must be a function of all three dimensions.

#### 5.6.2 Blast Radius Integration

At session initialisation, AgentPEP queries the AAPM Blast Radius API for the current agent's blast radius score (0.0–1.0, Neo4j-powered graph traversal). This score is:
- Attached to the session context
- Included in the OPA authorisation request input
- Used by Rego policies to elevate posture for high-reach agents
- Recorded in all PostToolUse events for the session

If the AAPM Blast Radius API is unavailable, AgentPEP defaults to blast_radius_score = 1.0 (maximum — FAIL_CLOSED principle).

#### 5.6.3 Enforcement Posture Matrix

**Primary dimensions — Taint Level × Deployment Tier:**

| | Endpoint Agent | SaaS / Embedded | Homegrown / Custom |
|---|---|---|---|
| **Taint L1** | MONITOR | MONITOR | MONITOR |
| **Taint L2** | MONITOR + LOG | RESTRICT | RESTRICT |
| **Taint L3** | RESTRICT | DENY + ALERT | DENY + ALERT |

**Blast Radius Elevation:** If blast_radius_score ≥ 0.75, posture elevates one tier (e.g., RESTRICT → DENY + ALERT).

**Posture Definitions:**
- **MONITOR** — Allow with full PostToolUse event emission
- **MONITOR + LOG** — Allow with enhanced logging (full arg capture). Flagged for TrustSOC review
- **RESTRICT** — Allow only if explicit role-based permit exists. HITL approval workflow triggered for borderline cases
- **DENY + ALERT** — Hard deny. Immediate TrustSOC alert. Session flagged for human review

#### 5.6.4 Deployment Tier Detection

Tier determined at session init via:
- Explicit operator configuration (highest trust)
- Runtime environment fingerprinting (framework SDK, environment variables)
- Default: HOMEGROWN (most restrictive if tier is ambiguous)

#### 5.6.5 Acceptance Criteria

- [ ] Blast radius score fetched from AAPM API at session init; defaults to 1.0 on API unavailability
- [ ] Blast radius score ≥ 0.75 elevates posture one tier
- [ ] All nine base matrix cells implemented and tested
- [ ] Ambiguous tier defaults to HOMEGROWN posture
- [ ] Blast radius score recorded in all PostToolUse events for the session

---

### FEATURE-07: Bypass Threat Model with MITRE ATLAS Mapping

**Priority:** Tier 3 — Documentation
**Dependency:** AAPM threat taxonomy (MITRE ATLAS + OWASP LLM Top 10, AAPM Sprint 18)

#### 5.7.1 Named Bypass Vectors with MITRE ATLAS IDs

AgentPEP's bypass threat model references AAPM's MITRE ATLAS taxonomy as the authoritative threat classification. AAPM owns the taxonomy; AgentPEP references it for each bypass vector.

| Bypass Class | Real-World Example | MITRE ATLAS Technique | AgentPEP Mitigation | Residual Risk |
|---|---|---|---|---|
| Config Injection | CVE-2025-59536 — malicious hook via settings.json | AML.T0054 (LLM Prompt Injection via Third-Party Services) | FEATURE-02: Trusted Policy Loader | Supply chain compromise of AAPM Policy Registry |
| Complexity Bypass | Adversa AI 50-subcommand bypass | AML.T0051 (LLM Jailbreak) | FEATURE-03: Complexity budget + FAIL_CLOSED | Novel complexity vectors not yet characterised |
| Reasoning Boundary | Agent decomposes blocked action into permissible sub-actions | AML.T0043 (Craft Adversarial Data) | PostToolUse sequence stream to TrustSOC (FEATURE-05) | Detection latency; not preventable at PEP layer |
| Hook Gaming | Praetorian agent gaming its own enforcement hook | AML.T0051 (LLM Jailbreak) | AgentRT regression suite; FEATURE-04 recursive evaluation | Emergent agent behaviour; continuous AgentRT validation required |

---

### FEATURE-08: Reference Monitor Compliance Statement

**Priority:** Tier 3 — Positioning

#### 5.8.1 Reference Monitor Criteria — Post-Enhancement Compliance

| Criterion | Current State | Post-Enhancement State | Evidence |
|-----------|---------------|----------------------|----------|
| Always Invoked | Partial — no recursive subagent enforcement | Satisfied | FEATURE-04: recursive PEP invocation at every hop |
| Tamper-Proof | Not addressed | Satisfied | FEATURE-02: trusted policy loader; policy source locked to AAPM registry |
| Verifiable | Partial — imperative rules not independently auditable | Satisfied | FEATURE-01: OPA/Rego evaluation; AAPM-authored APDL readable by non-engineers |

---

### FEATURE-09: AAPM → AgentPEP Integration Contract

**Priority:** Tier 1 — Architectural (New in v2.1)
**Owner:** Joint — AgentPEP team (consumer) + AAPM team (publisher)
**TRQF Controls:** TRQF-GOV-03, TRQF-INT-01

#### 5.9.1 Problem Statement

v2.0 of this PRD treated AgentPEP's policy store as self-contained, with no defined mechanism for consuming policies published by AAPM. This left the most critical integration in the TrustFabric portfolio undefined: how does a policy approved via AAPM's PCR workflow reach AgentPEP's runtime enforcement engine?

#### 5.9.2 Integration Architecture

```
AAPM PCR Workflow (policy approved)
        │
        ▼
AAPM Bundle Compiler (APDL → Rego)
        │
        ▼
AAPM cosign signs bundle
        │
        ▼
TrustFabric Policy Registry (S3-compatible, versioned)
        │
        │  Push notification (SNS/webhook) OR pull polling
        ▼
AgentPEP Policy Loader (FEATURE-02)
        │
        ├── Verify signature
        ├── Validate format
        └── Load into OPA engine
```

#### 5.9.3 Integration Contract Definition

| Property | Value |
|----------|-------|
| Policy source | TrustFabric Policy Registry (AAPM-managed) |
| Bundle format | Signed OPA Rego bundle (cosign) |
| Bundle naming | `agentpep-policy-{version}.tar.gz` |
| Push mechanism | Registry webhook → AgentPEP policy reload endpoint |
| Pull fallback | AgentPEP polls registry every 60s if webhook unavailable |
| Rollout SLA | AAPM PCR approval → AgentPEP enforcement active: ≤ 5 minutes |
| Version negotiation | AgentPEP reports current bundle version in every enforcement event; AAPM monitors for stale deployments |
| Rollback | AAPM re-publishes previous bundle version; AgentPEP loads on next poll/push cycle |
| Emergency revocation | AAPM publishes deny-all bundle; AgentPEP enforces within push SLA |

#### 5.9.4 Acceptance Criteria

- [ ] AAPM PCR approval triggers bundle publish to registry within 2 minutes
- [ ] AgentPEP receives push notification and loads new bundle within 3 minutes (total ≤ 5 min)
- [ ] Pull polling fallback active when webhook delivery fails
- [ ] Bundle version reported in all AgentPEP enforcement decision events
- [ ] AAPM emergency deny-all bundle enforced by AgentPEP within 5-minute SLA
- [ ] AgentPEP rolls back gracefully when AAPM republishes a prior bundle version
- [ ] Integration contract document signed off by both AgentPEP and AAPM teams

---

## 6. AgentRT Integration

AgentPEP's enforcement claims are only as strong as the adversarial validation behind them. AgentRT is designated as AgentPEP's mandatory validation harness:

- Every policy bundle must pass an AgentRT regression suite before deployment to production
- The AgentRT suite covers all four named bypass vector classes (FEATURE-07)
- AgentRT results are a required gate in the AAPM policy bundle release pipeline (not just AgentPEP's)
- New bypass vectors disclosed publicly are converted to AgentRT test cases within 14 days of disclosure

---

## 7. Architecture Diagram (Post-Enhancement)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AAPM (Policy Author)                             │
│  APDL Authoring → PCR Workflow → Rego Compilation → cosign Sign    │
│                    → TrustFabric Policy Registry                    │
└─────────────────────────────────────────┬───────────────────────────┘
                                          │ Signed Rego Bundle
                                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  AgentPEP Enforcement Layer                         │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                 Policy Loader (FEATURE-02)                   │   │
│  │    Source allowlist → Signature verify → OPA load           │   │
│  └────────────────────────────┬─────────────────────────────────┘   │
│                               │                                     │
│  ┌────────────────────────────▼─────────────────────────────────┐   │
│  │              PreToolUse Interceptor                          │   │
│  │  ┌──────────────┐  ┌─────────────────┐  ┌───────────────┐   │   │
│  │  │  Complexity  │  │   Delegation    │  │   Posture     │   │   │
│  │  │   Budget     │  │  Chain Eval     │  │   Matrix      │   │   │
│  │  │ (FEATURE-03) │  │  (FEATURE-04)   │  │ (FEATURE-06)  │   │   │
│  │  └──────┬───────┘  └──────┬──────────┘  └──────┬────────┘   │   │
│  │         └─────────────────┴─────────────────────┘            │   │
│  │                           │                                  │   │
│  │                           ▼                                  │   │
│  │              ┌────────────────────────┐                      │   │
│  │              │  OPA/Rego PDP Engine   │                      │   │
│  │              │   (FEATURE-01)         │                      │   │
│  │              └────────────┬───────────┘                      │   │
│  │                           │                                  │   │
│  │              ALLOW / DENY / MODIFY                           │   │
│  └───────────────────────────┬──────────────────────────────────┘   │
│                              │                                      │
│  ┌───────────────────────────▼──────────────────────────────────┐   │
│  │              PostToolUse Hook (FEATURE-05)                   │   │
│  │            OCSF Event + HMAC Signature                       │   │
│  └───────────────────────────┬──────────────────────────────────┘   │
└──────────────────────────────┼──────────────────────────────────────┘
                               │
               ┌───────────────┴──────────────────┐
               ▼                                  ▼
        TrustSOC                        Enforcement Decision Log
   (Sequence Analysis)                (Bundle version, rule, latency)
                                               │
                                               ▼
                                      AAPM (Stale version monitoring)
```

---

## 8. TRQF Control Mapping

| Feature | TRQF Controls |
|---------|--------------|
| FEATURE-01: Runtime PDP | TRQF-PEP-01, TRQF-PEP-04, TRQF-GOV-02 |
| FEATURE-02: Trusted Policy Loader | TRQF-PEP-02, TRQF-SUPPLY-01 |
| FEATURE-03: Complexity Budget | TRQF-PEP-03, TRQF-RES-01 |
| FEATURE-04: Recursive PEP | TRQF-IAM-03, TRQF-PEP-05, TRQF-DELEG-01 |
| FEATURE-05: PostToolUse Hook | TRQF-DET-01, TRQF-AUD-02 |
| FEATURE-06: Posture Matrix | TRQF-PEP-06, TRQF-RISK-02 |
| FEATURE-07: Bypass Threat Model | TRQF-RISK-01, TRQF-THREAT-01 |
| FEATURE-08: Reference Monitor Statement | TRQF-GOV-01, TRQF-COMP-01 |
| FEATURE-09: AAPM Integration Contract | TRQF-GOV-03, TRQF-INT-01 |

---

## 9. Success Metrics

| Metric | Baseline | Target (Post-Enhancement) |
|--------|----------|--------------------------|
| Policy compliance rate (instrumented agents) | ~48% (industry baseline) | ≥ 93% |
| PDP evaluation latency P99 | N/A | < 10ms |
| PostToolUse event delivery latency | N/A | < 500ms |
| AAPM PCR → AgentPEP enforcement SLA | N/A | ≤ 5 minutes |
| Known bypass vector coverage | 0/4 documented | 4/4 documented + mitigated or acknowledged |
| Policy bundle stale rate (version lag > 1) | N/A | < 1% of sessions |
| AgentRT regression coverage | 0% | 100% of named bypass classes |
| Reference monitor criteria met | 1/3 (partial) | 3/3 |

---

## 10. Dependencies

| Dependency | Owner | Required For |
|-----------|-------|-------------|
| AAPM Policy Registry (published bundles) | AAPM team | FEATURE-01, FEATURE-02, FEATURE-09 |
| AAPM Blast Radius API | AAPM team (Sprint 12) | FEATURE-06 |
| AAPM MITRE ATLAS threat taxonomy | AAPM team (Sprint 18) | FEATURE-07 |
| AAPM bundle webhook notification | AAPM team | FEATURE-09 |
| OPA Python SDK / sidecar | Platform Engineering | FEATURE-01 |
| Kafka topic provisioning | Infrastructure | FEATURE-05 |
| TrustSOC AgentBehaviourAnalyser module | TrustSOC team | FEATURE-05 |
| AgentRT bypass regression suite | AgentRT team | FEATURE-08 |
| TRQF v3.0 control mapping review | Compliance | FEATURE-07, FEATURE-08 |

---

## 11. Open Questions

1. **OPA deployment model:** Embedded library vs. sidecar? Sidecar offers independent scaling; embedded offers lower latency. Decision required before FEATURE-01 sprint begins (ADR-001).
2. **Trust score decay rate:** Default 15% per hop may be too aggressive for LangGraph multi-hop workflows common in Indian enterprise deployments. Validate with design partners before S-E06.
3. **Blast Radius API availability SLA:** AAPM Blast Radius API unavailability defaults to score = 1.0 (FAIL_CLOSED). Is this too disruptive for AAPM API downtime events? Consider a cached last-known value with TTL as an alternative.
4. **Bundle polling interval:** 60-second pull polling fallback — acceptable SLA for enterprise? Some regulated customers may require near-realtime policy updates (< 60s).
5. **AAPM Sprint 12 timing:** AAPM Blast Radius Calculator targets completion at Week 24 of AAPM's sprint plan. AgentPEP FEATURE-06 (S-E08) must be sequenced after AAPM Sprint 12 completes.

---

*Document Owner: TrustFabric Product Architecture*
*Next Review: Sprint S-E01 kickoff*
*Distribution: Internal — Engineering, Security Architecture, Compliance, AAPM Team*
