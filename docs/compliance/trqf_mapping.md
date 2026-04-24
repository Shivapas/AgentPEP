# TRQF Control Mapping — AgentPEP Hook Enhancement Features

**Document ID:** COMP-002
**Version:** 2.1 (Final — Release Sign-Off)
**Status:** SIGNED OFF — Sprint S-E10 compliance review complete
**Sprint:** S-E01 (E01-T08) → S-E10 (E10-T05)
**Owner:** TrustFabric Product Architecture
**Initial Date:** April 2026
**Sign-Off Date:** April 2026

---

## 1. Overview

This document maps all nine AgentPEP v2.1 enhancement features to the Trust and Risk Qualification Framework (TRQF) control taxonomy. All 34 controls are now implemented and verified for the v2.1 release.

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
| TRQF-PEP-01 | Policy evaluation engine must be declarative and auditable | OPA/Rego engine in `backend/app/pdp/engine.py`; AAPM-compiled Rego bundle `agentpep-core-v1.0.0`; all imperative rules decommissioned (S-E05-T09); bundle auditable by compliance team without application source access | **COMPLETE — S-E04/S-E05** |
| TRQF-PEP-04 | Enforcement decision log must include policy bundle version at time of evaluation | `backend/app/pdp/enforcement_log.py` — every log entry records `policy_bundle_version`, `decision`, `reason_code`, `eval_latency_ms`, `agent_id`, `session_id`, `tool_name`, `timestamp` | **COMPLETE — S-E04** |
| TRQF-GOV-02 | Policy logic must be externally auditable without access to application source code | Declarative Rego evaluated by OPA; AAPM compliance team independently verified bundle against 23-case parity test (`tests/parity/test_aapm_bundle_parity.py`) — zero divergences | **COMPLETE — S-E05** |

---

### FEATURE-02: Trusted Policy Loader with Integrity Verification

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-PEP-02 | Policy source must be from an allowlisted, integrity-verified location | Source URL allowlist in `backend/app/policy/loader.py`; cosign verification before deserialization; working-directory / env-var paths raise `PolicySourceViolation` + emit `SECURITY_VIOLATION` | **COMPLETE — S-E03** |
| TRQF-SUPPLY-01 | Policy bundles must be cryptographically signed and verified before execution | cosign signature verification in `loader.py`; FAIL_CLOSED on verification failure; AgentRT BV-001 suite: all 12 scenarios blocked | **COMPLETE — S-E03** |
| TRQF-SUPPLY-02 | Policy public key must be compile-time pinned; not runtime-configurable | `backend/app/policy/trusted_key.py` — `AAPM_POLICY_PUBLIC_KEY` is a compile-time constant; no env var, config file, or CLI flag override path exists | **COMPLETE — S-E03** |

---

### FEATURE-03: Complexity FAIL_CLOSED with Evaluation Timeout

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-PEP-03 | Evaluation failure must default to DENY (FAIL_CLOSED); no permissive fallback | `backend/app/enforcement/complexity_budget.py` + `backend/app/enforcement/eval_timeout.py`; Evaluation Guarantee Invariant (INV-001) implemented in `backend/app/pdp/client.py`; try/except wraps full evaluation; `asyncio.timeout(EVAL_TIMEOUT_SECONDS)` enforces 50ms deadline | **COMPLETE — S-E02** |
| TRQF-RES-01 | System must maintain enforcement posture under adversarial load (timeout, complexity overload) | AgentRT BV-002: 18/18 scenarios passed; CB-07 through CB-09 confirm DENY on timeout, exception, and policy unavailability; INV-001 verified under OPA engine failure in load test | **COMPLETE — S-E02** |

---

### FEATURE-04: Recursive Trust Enforcement and Delegation

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-TRUST-01 | Subagent permissions must not exceed root principal's permissions | `backend/app/trust/permission_intersection.py` — effective permission = intersection of delegation chain; adversarial test: `tests/adversarial/test_trust_escalation.py` — DENY + TRUST_VIOLATION confirmed | **COMPLETE — S-E06** |
| TRQF-TRUST-02 | Trust score must degrade across delegation hops | `backend/app/trust/trust_score.py` — linear decay per hop, 15% default rate; configurable rate; minimum threshold enforced; `tests/test_trust_enforcement.py` — all decay scenarios pass | **COMPLETE — S-E06** |
| TRQF-TRUST-03 | Full delegation chain must be propagated to every PDP evaluation | `backend/app/trust/delegation_context.py`; OPA `input.principal.delegation_chain` carries full chain; `backend/app/pdp/request_builder.py` includes chain in every authorisation request | **COMPLETE — S-E06** |
| TRQF-TRUST-04 | TRUST_VIOLATION event must be emitted when subagent claims higher permissions | `backend/app/trust/events.py` — `TRUST_VIOLATION` event emitted on permission escalation attempt; OCSF schema compliant; adversarial test confirmed in `tests/adversarial/test_trust_escalation.py` | **COMPLETE — S-E06** |

---

### FEATURE-05: PostToolUse Hooks and TrustSOC Integration

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-OBS-01 | PostToolUse event must be emitted for every tool call (ALLOW and DENY) | `backend/app/hooks/post_tool_use.py` — hook invoked on all outcomes; integration test: `tests/integration/test_posttooluse_emission.py`; AgentRT BV-003 scenario RB-09 confirms DENY PostToolUse events | **COMPLETE — S-E07** |
| TRQF-OBS-02 | Pre and PostToolUse events must be linked by a sequence ID for the same invocation | `backend/app/events/sequence_id.py` — sequence ID generated in PreToolUse; propagated to PostToolUse; AgentRT BV-003 scenario RB-07 confirms Pre/Post pairing | **COMPLETE — S-E07** |
| TRQF-OBS-03 | Event stream must be tamper-evident (HMAC or equivalent) | `backend/app/events/event_signer.py` — HMAC-SHA256 signature on each emitted event; AgentRT BV-003 scenario RB-06: HMAC verified on all 13 events | **COMPLETE — S-E07** |
| TRQF-OBS-04 | PostToolUse events must be delivered to TrustSOC within 500ms SLA | `backend/app/transport/kafka_producer.py` — Kafka topic `agentpep.posttooluse.events`; load test P99 = 312ms (target: < 500ms); AgentRT BV-003 scenario RB-08 confirms | **COMPLETE — S-E07** |
| TRQF-OBS-05 | Events must conform to OCSF schema and pass OCSF linter in CI | `backend/app/events/ocsf_linter.py` — linter integrated in CI pipeline (`.github/workflows/ci.yml`); `backend/app/events/post_tool_use_event.py` defines OCSF-compliant schema; AgentRT BV-003 scenario RB-10: 0 OCSF violations | **COMPLETE — S-E07** |

---

### FEATURE-06: Enforcement Posture Matrix + Blast Radius

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-RISK-01 | Enforcement posture must be determined by a combination of taint level and deployment tier | `backend/app/enforcement/posture_matrix.py` — 3×3 matrix: (taint_level: L0/L1/L2) × (deployment_tier: HOMEGROWN/SAAS_EMBEDDED/VENDOR_MANAGED); `tests/test_posture_matrix.py` — all nine base cells tested | **COMPLETE — S-E08** |
| TRQF-RISK-02 | Blast radius score ≥ 0.75 must elevate posture by one tier | Elevation logic in `backend/app/enforcement/posture_matrix.py`; `tests/test_posture_matrix.py` — elevation scenario confirmed; load test: 8.3% of sessions triggered elevation | **COMPLETE — S-E08** |
| TRQF-RISK-03 | Blast radius score must be fetched from AAPM API at session initialisation | `backend/app/session/blast_radius_client.py` — HTTP call to AAPM Blast Radius API at session init; score attached to session context; included in all PostToolUse events for session | **COMPLETE — S-E08** |
| TRQF-RISK-04 | AAPM Blast Radius API unavailability must default to score = 1.0 (FAIL_CLOSED) | Fallback in `backend/app/session/blast_radius_client.py`; `tests/test_posture_matrix.py` API unavailability test; load test Section 7.1 confirms fallback behaviour | **COMPLETE — S-E08** |
| TRQF-RISK-05 | Ambiguous deployment tier must default to HOMEGROWN (most restrictive classification) | Default in `backend/app/session/tier_detection.py` — unrecognised env fingerprint → HOMEGROWN; `tests/test_posture_matrix.py` — HOMEGROWN default tested | **COMPLETE — S-E08** |

---

### FEATURE-07: Bypass Threat Model with MITRE ATLAS Mapping

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-THR-01 | A formal bypass threat model must be documented with recognised threat taxonomy references | `docs/threat_model/bypass_vectors.md` (TM-001) — all four bypass classes documented with MITRE ATLAS IDs (AML.T0020.002, AML.T0043.003, AML.T0051.001, AML.T0054.002) | **COMPLETE — S-E01** |
| TRQF-THR-02 | Each bypass vector must be mapped to a mitigating feature and residual risk assessment | Section 4 of `docs/threat_model/bypass_vectors.md` — full mapping table; residual risk rated: BV-001 LOW, BV-002 MEDIUM, BV-003 HIGH (disclosed), BV-004 HIGH (disclosed) | **COMPLETE — S-E01** |
| TRQF-THR-03 | Adversarial test cases must exist for each bypass vector class | AgentRT suites: `agentrt/suites/bypass_config_injection.py` (BV-001, 12 scenarios), `bypass_complexity.py` (BV-002, 18 scenarios), `bypass_reasoning_boundary.py` (BV-003, 10 scenarios), `bypass_hook_gaming.py` (BV-004, 10 scenarios); all passing | **COMPLETE — S-E09** |
| TRQF-THR-04 | New public disclosures must result in test cases within 14 days | CVE-to-test process: `docs/process/cve_to_test.md`; SLA: 14 days from public disclosure to AgentRT test case; integrated as AAPM bundle release pipeline gate | **COMPLETE — S-E09** |

---

### FEATURE-08: Reference Monitor Compliance Statement

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-CERT-01 | A named design principle (Evaluation Guarantee Invariant) must be documented | `docs/invariants/evaluation_guarantee.md` (INV-001) — invariant stated, failure modes enumerated, implementation requirements specified, verification criteria defined | **COMPLETE — S-E01** |
| TRQF-CERT-02 | Current-state compliance assessment against reference monitor criteria must be documented | `docs/compliance/reference_monitor_assessment.md` (COMP-001) — v1.x baseline (7/15 FAIL) and v2.1 final audit (15/15 PASS) with code-level evidence for each criterion | **COMPLETE — S-E01 (baseline) / S-E10 (final audit)** |
| TRQF-CERT-03 | Final reference monitor compliance statement with code-level evidence must be published | `docs/compliance/reference_monitor_statement.md` (COMP-003) — formal external compliance claim; C1/C2/C3 satisfied; residual risks disclosed; audit sign-off recorded | **COMPLETE — S-E10** |
| TRQF-CERT-04 | Reference monitor compliance audit must be performed against implemented code | S-E10-T01 audit completed; COMP-001 v2.1 records all evidence points with file references; AgentRT regression and load test results referenced | **COMPLETE — S-E10** |

---

### FEATURE-09: AAPM → AgentPEP Integration Contract

| TRQF Control | Control Description | Implementation Evidence | Status |
|---|---|---|---|
| TRQF-SUPPLY-03 | The policy source of truth must be formally defined in an integration contract | `docs/integrations/aapm_agentpep_contract_draft.md` — registry URL, webhook vs. poll, bundle naming convention, rollout SLA, emergency revocation; contract agreed with AAPM team in S-E01 | **COMPLETE — S-E01** |
| TRQF-SUPPLY-04 | Emergency policy revocation must be achievable within a defined SLA | Emergency deny-all bundle procedure in integration contract; 5-minute SLA; AgentRT E2E test confirmed bundle active within 3m 42s; load test Section 7.2 confirms webhook delivery < 90s | **COMPLETE — S-E05 (validated)** |
| TRQF-GOV-01 | Policy ownership boundary must be formally documented and accepted by both portfolio teams | `docs/architecture/portfolio_boundary.md` — AgentPEP vs. AAPM ownership boundary documented and accepted | **COMPLETE — S-E01** |
| TRQF-GOV-03 | Policy update delivery must be tested end-to-end (PCR → bundle → enforcement active) | E2E integration test: `tests/integration/test_aapm_e2e_integration.py`; AgentRT E2E suite: PCR → bundle compiled → signed → registry → webhook → AgentPEP → enforcement active; full flow validated | **COMPLETE — S-E05** |

---

## 3. Control Coverage Summary — v2.1 Final

| TRQF Family | Total Controls | v1.x Implemented | v2.1 Complete |
|---|---|---|---|
| TRQF-PEP | 4 | 1 | **4** |
| TRQF-SUPPLY | 4 | 0 | **4** |
| TRQF-RES | 1 | 0 | **1** |
| TRQF-GOV | 3 | 0 | **3** |
| TRQF-TRUST | 4 | 1 (partial) | **4** |
| TRQF-OBS | 5 | 1 (partial) | **5** |
| TRQF-RISK | 5 | 0 | **5** |
| TRQF-THR | 4 | 0 | **4** |
| TRQF-CERT | 4 | 0 | **4** |
| **Total** | **34** | **3** | **34** |

**v2.1: 34/34 controls implemented and verified (100%).**

---

## 4. Sign-Off

This TRQF control mapping is reviewed and signed off by the TrustFabric compliance team for AgentPEP v2.1.

| Role | Organisation | Decision | Date |
|---|---|---|---|
| Product Architecture Lead | TrustFabric | APPROVED | April 2026 |
| Security Architecture Lead | TrustFabric | APPROVED | April 2026 |
| Compliance Team Lead | TrustFabric | **SIGNED OFF** | April 2026 |
| AAPM Integration Owner | AAPM Team | ACKNOWLEDGED | April 2026 |

**Compliance team sign-off statement:** All 34 TRQF controls have been verified against implemented code with documented evidence. The mapping is accepted as the authoritative compliance artefact for AgentPEP v2.1. This sign-off supersedes all prior draft versions of this document.

---

*Document Owner: TrustFabric Product Architecture*
*Document ID: COMP-002 v2.1*
*Distribution: Internal — Engineering, Compliance, Security Architecture, AAPM Team*
*Next Review: AgentPEP v2.2 or major feature change*
