# TRQF Control Mapping — AgentPEP Hook Enhancement Features

**Document ID:** COMP-002
**Status:** Draft — S-E01 deliverable
**Sprint:** S-E01 (E01-T08)
**Owner:** TrustFabric Product Architecture
**Date:** April 2026
**Review Required:** Compliance team sign-off (Sprint S-E10)

---

## 1. Overview

This document maps all nine AgentPEP v2.1 enhancement features to the Trust and Risk Qualification Framework (TRQF) control taxonomy. The mapping is the primary artefact for compliance sign-off (Sprint S-E10, E10-T05) and provides the audit evidence trail for enterprise customers and regulatory reviewers.

**TRQF Control Families referenced:**
- `TRQF-PEP` — Policy Enforcement Point controls
- `TRQF-SUPPLY` — Supply chain and policy integrity controls
- `TRQF-RES` — Resilience and availability controls
- `TRQF-GOV` — Policy governance controls
- `TRQF-TRUST` — Trust and delegation controls
- `TRQF-OBS` — Observability and audit controls
- `TRQF-RISK` — Risk posture and classification controls
- `TRQF-THR` — Threat model and adversarial validation controls
- `TRQF-CERT` — Certification and compliance documentation controls

---

## 2. Control Mapping Table

### FEATURE-01: Runtime Policy Decision Point (OPA/Rego PDP)

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-PEP-01 | Policy evaluation engine must be declarative and auditable | OPA/Rego engine; AAPM-authored Rego bundles; all evaluation declarative | Planned — S-E04 |
| TRQF-PEP-04 | Enforcement decision log must include policy bundle version at time of evaluation | `enforcement_log.py`; every log entry records `policy_bundle_version` | Planned — S-E04 |
| TRQF-GOV-02 | Policy logic must be externally auditable without access to application source code | Declarative Rego evaluated by OPA; bundle readable by compliance team via AAPM | Planned — S-E04 |

---

### FEATURE-02: Trusted Policy Loader with Integrity Verification

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-PEP-02 | Policy source must be from an allowlisted, integrity-verified location | Source allowlist check in `loader.py`; cosign verification before load | Planned — S-E03 |
| TRQF-SUPPLY-01 | Policy bundles must be cryptographically signed and verified before execution | cosign signature verification; public key pinned in binary | Planned — S-E03 |
| TRQF-SUPPLY-02 | Policy public key must be compile-time pinned; not runtime-configurable | Pinned key in `trusted_key.py`; no runtime override path | Planned — S-E03 |

---

### FEATURE-03: Complexity FAIL_CLOSED with Evaluation Timeout

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-PEP-03 | Evaluation failure must default to DENY (FAIL_CLOSED); no permissive fallback | `complexity_budget.py` + `eval_timeout.py`; Evaluation Guarantee Invariant (INV-001) | Planned — S-E02 |
| TRQF-RES-01 | System must maintain enforcement posture under adversarial load (timeout, complexity overload) | Adversarial tests: `test_compound_command_bypass.py`, `test_eval_timeout_bypass.py` | Planned — S-E02 |

---

### FEATURE-04: Recursive Trust Enforcement and Delegation

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-TRUST-01 | Subagent permissions must not exceed root principal's permissions | `permission_intersection.py`; effective permission = intersection of chain | Planned — S-E06 |
| TRQF-TRUST-02 | Trust score must degrade across delegation hops | `trust_score.py`; linear decay per hop, configurable rate | Planned — S-E06 |
| TRQF-TRUST-03 | Full delegation chain must be propagated to every PDP evaluation | Delegation context in OPA `input.principal.delegation_chain` | Planned — S-E06 |
| TRQF-TRUST-04 | TRUST_VIOLATION event must be emitted when subagent claims higher permissions | Event emission on permission escalation attempt | Planned — S-E06 |

---

### FEATURE-05: PostToolUse Hooks and TrustSOC Integration

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-OBS-01 | PostToolUse event must be emitted for every tool call (ALLOW and DENY) | `post_tool_use.py`; hook invoked on all tool call outcomes | Planned — S-E07 |
| TRQF-OBS-02 | Pre and PostToolUse events must be linked by a sequence ID for the same invocation | Sequence ID generated in PreToolUse; propagated to PostToolUse | Planned — S-E07 |
| TRQF-OBS-03 | Event stream must be tamper-evident (HMAC or equivalent) | HMAC signature on each emitted event | Planned — S-E07 |
| TRQF-OBS-04 | PostToolUse events must be delivered to TrustSOC within 500ms SLA | Kafka producer; delivery latency integration test | Planned — S-E07 |
| TRQF-OBS-05 | Events must conform to OCSF schema and pass OCSF linter in CI | OCSF schema definition; linter in CI pipeline | Planned — S-E07 |

---

### FEATURE-06: Enforcement Posture Matrix + Blast Radius

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-RISK-01 | Enforcement posture must be determined by a combination of taint level and deployment tier | `posture_matrix.py`; 3×3 matrix (taint × tier) | Planned — S-E08 |
| TRQF-RISK-02 | Blast radius score ≥ 0.75 must elevate posture by one tier | Elevation logic in `posture_matrix.py` | Planned — S-E08 |
| TRQF-RISK-03 | Blast radius score must be fetched from AAPM API at session initialisation | `blast_radius_client.py`; session init hook | Planned — S-E08 |
| TRQF-RISK-04 | AAPM Blast Radius API unavailability must default to score = 1.0 (FAIL_CLOSED) | Fallback in `blast_radius_client.py`; unit test for API unavailability | Planned — S-E08 |
| TRQF-RISK-05 | Ambiguous deployment tier must default to HOMEGROWN (most restrictive classification) | Default in `tier_detection.py` | Planned — S-E08 |

---

### FEATURE-07: Bypass Threat Model with MITRE ATLAS Mapping

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-THR-01 | A formal bypass threat model must be documented with recognised threat taxonomy references | `docs/threat_model/bypass_vectors.md`; MITRE ATLAS IDs for all four classes | **COMPLETE — S-E01** |
| TRQF-THR-02 | Each bypass vector must be mapped to a mitigating feature and residual risk assessment | Section 4 of `docs/threat_model/bypass_vectors.md` — full mapping table | **COMPLETE — S-E01** |
| TRQF-THR-03 | Adversarial test cases must exist for each bypass vector class | AgentRT suites: Classes 1–4 (S-E09) | Planned — S-E09 |
| TRQF-THR-04 | New public disclosures must result in test cases within 14 days | CVE-to-test process: `docs/process/cve_to_test.md` (S-E09) | Planned — S-E09 |

---

### FEATURE-08: Reference Monitor Compliance Statement

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-CERT-01 | A named design principle (Evaluation Guarantee Invariant) must be documented | `docs/invariants/evaluation_guarantee.md` | **COMPLETE — S-E01** |
| TRQF-CERT-02 | Current-state compliance assessment against reference monitor criteria must be documented | `docs/compliance/reference_monitor_assessment.md` | **COMPLETE — S-E01** |
| TRQF-CERT-03 | Final reference monitor compliance statement with code-level evidence must be published | `docs/compliance/reference_monitor_statement.md` (S-E10) | Planned — S-E10 |
| TRQF-CERT-04 | Reference monitor compliance audit must be performed against implemented code | S-E10 audit report | Planned — S-E10 |

---

### FEATURE-09: AAPM → AgentPEP Integration Contract

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-SUPPLY-03 | The policy source of truth must be formally defined in an integration contract | `docs/integrations/aapm_agentpep_contract_draft.md` | **COMPLETE (DRAFT) — S-E01** |
| TRQF-SUPPLY-04 | Emergency policy revocation must be achievable within a defined SLA | Emergency deny-all bundle procedure in integration contract; 5-minute SLA | Planned — S-E05 (validated) |
| TRQF-GOV-01 | Policy ownership boundary must be formally documented and accepted by both portfolio teams | `docs/architecture/portfolio_boundary.md` | **COMPLETE (DRAFT) — S-E01** |
| TRQF-GOV-03 | Policy update delivery must be tested end-to-end (PCR → bundle → enforcement active) | E2E test: S-E05-T06 | Planned — S-E05 |

---

## 3. Control Coverage Summary

| TRQF Family | Total Controls | Implemented (v1.x) | Complete in v2.1 | In Sprint S-E01 |
|---|---|---|---|---|
| TRQF-PEP | 4 | 1 | 4 | 0 |
| TRQF-SUPPLY | 4 | 0 | 4 | 1 (draft) |
| TRQF-RES | 1 | 0 | 1 | 0 |
| TRQF-GOV | 3 | 0 | 3 | 1 (draft) |
| TRQF-TRUST | 4 | 1 (partial) | 4 | 0 |
| TRQF-OBS | 5 | 1 (partial) | 5 | 0 |
| TRQF-RISK | 5 | 0 | 5 | 0 |
| TRQF-THR | 4 | 0 | 4 | 2 |
| TRQF-CERT | 4 | 0 | 4 | 2 |
| **Total** | **34** | **3** | **34** | **6** |

**S-E01 contributes:** 6 controls (2 COMPLETE, 4 in DRAFT pending AAPM acceptance)

---

## 4. Sign-Off Requirements

| Milestone | Sign-Off Required By | Target |
|---|---|---|
| TRQF-THR-01, TRQF-THR-02 (threat model) | Security Architecture | S-E01 exit |
| TRQF-CERT-01, TRQF-CERT-02 (invariant, assessment) | Security Architecture | S-E01 exit |
| TRQF-SUPPLY-03, TRQF-GOV-01 (contract, boundary) | Security Architecture + AAPM | S-E01 exit |
| Full TRQF mapping review | Compliance team | Sprint S-E10 |

---

*Document Owner: TrustFabric Product Architecture*
*Distribution: Internal — Engineering, Compliance, Security Architecture, AAPM Team*
*Next Review: Sprint S-E10 — full compliance sign-off*
