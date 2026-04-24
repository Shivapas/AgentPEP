# AgentPEP — AAPM Portfolio Boundary

**Document ID:** ARCH-001
**Status:** Draft — Pending AAPM Acceptance
**Sprint:** S-E01 (E01-T09)
**Owner:** TrustFabric Product Architecture
**Date:** April 2026
**Acceptance Required From:** AgentPEP team, AAPM team

---

## 1. Purpose

This document formally defines the product boundary between AgentPEP and AAPM (AI Agent Policy Management) within the TrustFabric portfolio. It is the single authoritative reference for any capability ownership question between the two products.

This boundary governs:
- Feature scope decisions in both products
- Integration contract design (see `docs/integrations/aapm_agentpep_contract_draft.md`)
- TRQF compliance ownership (see `docs/compliance/trqf_mapping.md`)
- Reference monitor compliance statement scope (S-E10)

---

## 2. One-Sentence Boundary Statement

> **AAPM compiles, signs, and publishes policy bundles. AgentPEP loads, verifies, and enforces them.**

---

## 3. Capability Ownership Table

### 3.1 Policy Authoring and Lifecycle — AAPM Owns

| Capability | Owner | Notes |
|---|---|---|
| Policy authoring language (APDL) | AAPM | Human-readable; security team reviews APDL in AAPM |
| Policy Change Request (PCR) workflow | AAPM | Approval, versioning, change history |
| APDL → Rego compilation | AAPM | Rego is a compiled output; AgentPEP consumes but does not author Rego |
| Bundle cosign signing | AAPM | AAPM holds the private key; AgentPEP verifies with pinned public key |
| TrustFabric Policy Registry | AAPM | Hosts published bundles; AgentPEP only reads from this registry |
| Policy audit trail | AAPM | Who changed what and why; policy change history |
| Policy versioning and rollback | AAPM | Bundle version management; emergency revocation procedure |
| MITRE ATLAS / OWASP LLM Top 10 threat taxonomy | AAPM | Canonical taxonomy for TrustFabric portfolio; AgentPEP references, does not own |

### 3.2 Runtime Enforcement — AgentPEP Owns

| Capability | Owner | Notes |
|---|---|---|
| Policy loading from registry | AgentPEP | Pulls from AAPM-published registry URL only |
| cosign signature verification at load time | AgentPEP | Verifies using public key pinned in AgentPEP binary |
| OPA/Rego runtime evaluation engine | AgentPEP | Embedded library; evaluates AAPM-compiled bundles |
| PreToolUse enforcement | AgentPEP | Intercepts every tool call; returns ALLOW/DENY/MODIFY |
| PostToolUse event emission | AgentPEP | Emits OCSF-format events to TrustSOC; includes enforcement decision |
| Enforcement decision log | AgentPEP | Per-evaluation log: agent, tool, bundle version, decision, latency |
| Trust degradation across delegation chains | AgentPEP | Trust score decay and permission intersection |
| Enforcement posture matrix | AgentPEP | (Taint level × deployment tier × blast radius) → posture |
| AAPM Blast Radius API consumption | AgentPEP | AgentPEP calls AAPM API at session init; AAPM owns the calculator |
| Bypass threat model (AgentPEP-side) | AgentPEP | Four vector classes documented; maps to AAPM's unified taxonomy |
| Reference monitor compliance claim | AgentPEP | AgentPEP is the reference monitor; AAPM is a dependency, not the claimant |

### 3.3 Blast Radius Calculator — AAPM Owns, AgentPEP Consumes

| Capability | Owner | Notes |
|---|---|---|
| Blast radius computation (Neo4j graph analysis) | AAPM | AAPM Sprint 12 |
| Blast radius API endpoint | AAPM | `GET /v1/blast-radius`; AgentPEP calls at session init |
| Blast radius score interpretation | AgentPEP | Score ≥ 0.75 → posture elevation; fallback = 1.0 on API unavailability |

### 3.4 Observability and Audit — Split Ownership

| Capability | Owner | Notes |
|---|---|---|
| Enforcement decision log (what was evaluated and decided) | AgentPEP | Per-tool-call log; includes bundle version |
| Policy change audit trail (who changed the policy and why) | AAPM | PCR workflow creates the change audit record |
| TrustSOC event stream (PostToolUse OCSF events) | AgentPEP produces; TrustSOC consumes | AgentPEP emits; TrustSOC stores and analyses |
| Sequence-level anomaly detection (reasoning boundary analysis) | TrustSOC | Consumes AgentPEP's PostToolUse event stream |

---

## 4. What AgentPEP Does NOT Own

The following capabilities are explicitly **out of scope** for AgentPEP. Any AgentPEP PR or feature request touching these areas must be rejected and redirected to the owning product:

| Out-of-Scope Capability | Reason | Owning Product |
|---|---|---|
| Authoring Rego directly | AgentPEP consumes AAPM-compiled Rego; authoring duplicates AAPM | AAPM |
| Building or signing policy bundles | AAPM owns the signing pipeline | AAPM |
| Running a policy registry | AAPM runs the registry | AAPM |
| Maintaining a policy audit trail | AAPM's PCR workflow is the audit trail | AAPM |
| Blast radius calculation | Requires AAPM's Neo4j graph | AAPM |
| Defining the portfolio threat taxonomy | AAPM's unified threat taxonomy | AAPM |
| SIEM / SOC capabilities | TrustSOC's domain | TrustSOC |
| Governing agent internal reasoning | Acknowledged residual risk; outside enforcement boundary | N/A (residual risk) |

---

## 5. Boundary Violation Indicators

The following are signals that a proposed feature may violate the boundary:

| Signal | Issue | Resolution |
|---|---|---|
| AgentPEP PR includes Rego authoring | AgentPEP should not author policy | Redirect to AAPM for APDL authoring |
| AgentPEP PR adds a local policy config file format | Undermines trusted policy loader | Reject; all policy from registry |
| AgentPEP PR adds a policy change audit log | Duplicates AAPM's audit trail | Remove; enforcement decisions are logged, policy changes are not |
| AgentPEP PR fetches policy from a non-registry URL | Violates source allowlist | Reject; registry URL is the only source |
| AAPM PR modifies AgentPEP's enforcement logic | AAPM should influence via policy bundle content | Redirect to integration contract |

---

## 6. Integration Points (Formal Interfaces)

| Interface | Direction | Protocol | Document |
|---|---|---|---|
| Policy bundle delivery | AAPM → AgentPEP | HTTPS + cosign | `docs/integrations/aapm_agentpep_contract_draft.md` |
| Webhook push notification | AAPM → AgentPEP | HTTPS POST + HMAC | `docs/integrations/aapm_agentpep_contract_draft.md` |
| Blast Radius API | AgentPEP → AAPM | HTTPS GET | `docs/integrations/aapm_agentpep_contract_draft.md` |
| PostToolUse event stream | AgentPEP → TrustSOC | Kafka | `docs/integrations/trustsoc_contract.md` (S-E07) |

---

## 7. Acceptance

This boundary document requires acceptance from both teams before Sprint S-E03 begins. Acceptance constitutes agreement that neither team will build capabilities listed as the other's responsibility without a formal boundary revision.

| Role | Name | Status |
|---|---|---|
| AgentPEP Architecture Lead | Shiv | Authored — accepted |
| AAPM Product Lead | TBD | Pending |
| TrustFabric Portfolio Architecture | TBD | Pending |

---

## 8. Change Control

Changes to this boundary document require:
1. Joint review by AgentPEP and AAPM leads
2. Approval from TrustFabric Portfolio Architecture
3. Update to integration contract (`docs/integrations/aapm_agentpep_contract_draft.md`) if the integration interface changes
4. Update to TRQF mapping (`docs/compliance/trqf_mapping.md`) if control ownership changes

---

*Document Owner: TrustFabric Product Architecture*
*Distribution: Internal — Engineering, Security Architecture, AAPM Team, TrustSOC Team*
*Next Review: S-E01 exit meeting (AAPM acceptance)*
