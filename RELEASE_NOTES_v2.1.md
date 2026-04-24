# AgentPEP v2.1 Release Notes

**Release:** v2.1.0
**Date:** Q3 2026
**Sprint:** S-E10 (E10-T06)
**Type:** Major feature release — Reference Monitor Certification
**Upgrade path:** v1.x → v2.1 (see migration guide: `docs/migration/v1_to_v2.md`)

---

## Overview

AgentPEP v2.1 is the **Reference Monitor Certification** release. It delivers nine security enhancements that collectively close the gap between AgentPEP v1.x (7/15 reference monitor compliance) and the classical reference monitor standard (15/15).

The headline change is that enforcement is no longer expressed as imperative Python rules. All policy logic now lives in AAPM-compiled Rego bundles, evaluated by an embedded OPA engine, loaded exclusively from the AAPM Policy Registry with cryptographic signature verification. This separates the policy lifecycle from the AgentPEP release cycle and makes the enforcement logic independently auditable.

**Empirical improvement:** Reference-monitor-instrumented agents achieve 93% policy compliance vs. 48% for uninstrumented agents (PCAS, 2025 baseline). AgentPEP v2.1 is built to hit that 93% target.

---

## Breaking Changes

### Policy Source: AAPM Policy Registry (Required)

**This is the only breaking change in v2.1.**

AgentPEP v2.1 no longer loads policy from:
- Local YAML files (`policies/rules.yaml`, etc.)
- Environment variable `POLICY_PATH`
- CLI `--policy-path` flag
- Working directory scan

Policy is now loaded exclusively from the AAPM Policy Registry via signed Rego bundle. Any attempt to load policy from a non-allowlisted source raises a `PolicySourceViolation` and defaults enforcement to DENY.

**Migration:** See `docs/migration/v1_to_v2.md` — decommissioning local policy configuration is a one-time step with no policy logic re-authoring required (AAPM has translated all existing rules to APDL).

---

## New Features

### FEATURE-01: Runtime Policy Decision Point (OPA/Rego PDP)

All enforcement decisions are now evaluated by an embedded Open Policy Agent (OPA) engine against Rego policies compiled and signed by the AAPM team. Imperative Python rule evaluation is decommissioned.

**What this means for operators:**
- Policy updates are delivered by AAPM via webhook or polling — no AgentPEP restart required
- Enforcement decisions are traceable to a specific `policy_bundle_version` in the decision log
- Compliance teams can audit the Rego bundle directly without AgentPEP source access

**Performance:** OPA evaluation P99 = 7.2ms at 1,000 concurrent sessions (under the 10ms SLA). Embedded library mode (ADR-001) chosen to avoid sidecar latency overhead.

**Key files:** `backend/app/pdp/engine.py`, `backend/app/pdp/client.py`, `backend/app/pdp/enforcement_log.py`

---

### FEATURE-02: Trusted Policy Loader with Integrity Verification

Policy loading is now restricted to the AAPM Policy Registry URL. Every bundle is verified with cosign before load. The AAPM cosign public key is a compile-time constant — not configurable at runtime.

**Security improvements:**
- Eliminates CVE-2025-59536 (working directory config injection)
- Eliminates CVE-2026-21852 (environment variable policy redirect)
- Attempts to load from non-allowlisted paths emit `SECURITY_VIOLATION` events to TrustSOC
- Policy bundle version is tracked in memory and reported in all enforcement decision log entries

**Key files:** `backend/app/policy/loader.py`, `backend/app/policy/trusted_key.py`, `backend/app/policy/registry_webhook.py`, `backend/app/policy/registry_poll.py`

---

### FEATURE-03: Complexity FAIL_CLOSED with Evaluation Timeout

A pre-evaluation complexity budget gate blocks oversized tool call arguments before OPA evaluation is attempted. An asyncio-enforced evaluation timeout ensures that if OPA evaluation takes longer than 50ms, the decision defaults to DENY — not ALLOW.

**The Evaluation Guarantee Invariant (INV-001):** On any evaluation failure (timeout, exception, policy unavailability, malformed response), AgentPEP returns DENY. This behaviour is not operator-configurable.

**Addresses:** Adversa AI 50-subcommand compound command bypass (March 2026). AgentRT adversarial suite: 18/18 complexity bypass scenarios blocked.

**Key files:** `backend/app/enforcement/complexity_budget.py`, `backend/app/enforcement/eval_timeout.py`

---

### FEATURE-04: Recursive Trust Enforcement and Delegation

Subagent trust and permissions are now enforced recursively across delegation chains. The effective permissions available to a subagent are always the intersection of the permissions in the full delegation chain — a subagent can never exceed the root principal's permissions.

**Trust score degradation:** Trust degrades linearly across hops (default 15% per hop). When trust falls below the minimum threshold, the chain is terminated.

**What changes:**
- `TRUST_VIOLATION` event emitted when a subagent attempts to claim higher permissions than its principal
- Delegation chain is propagated to every OPA evaluation in the `input.principal.delegation_chain` field
- LangGraph multi-hop workflow validated: 15% default decay rate does not false-positive legitimate chains

**Key files:** `backend/app/trust/delegation_context.py`, `backend/app/trust/trust_score.py`, `backend/app/trust/permission_intersection.py`

---

### FEATURE-05: PostToolUse Hooks and TrustSOC Integration

PostToolUse is now a formalised hook type with guaranteed emission for every tool call (ALLOW and DENY). Events use OCSF schema, are HMAC-signed for tamper evidence, and are delivered to TrustSOC via Kafka within 500ms.

**Event capabilities:**
- Sequence ID links PreToolUse and PostToolUse events for the same invocation
- `blast_radius_score` field included in every event for session context
- `policy_bundle_version` included for audit traceability
- OCSF schema linter runs in CI — malformed events fail the build

**TrustSOC integration:** Formal contract documented at `docs/integrations/trustsoc_contract.md`. TrustSOC uses the PostToolUse event stream for Reasoning Boundary bypass detection (multi-call sequence analysis).

**Key files:** `backend/app/hooks/post_tool_use.py`, `backend/app/events/post_tool_use_event.py`, `backend/app/transport/kafka_producer.py`

---

### FEATURE-06: Enforcement Posture Matrix + Blast Radius Integration

AgentPEP now determines enforcement posture from a 3×3 matrix combining taint level and deployment tier, with dynamic elevation based on AAPM's Blast Radius API.

**Posture matrix dimensions:**
- Taint level: L0 (clean), L1 (user-tainted), L2 (external-tainted)
- Deployment tier: HOMEGROWN, SAAS_EMBEDDED, VENDOR_MANAGED
- AAPM blast radius score ≥ 0.75 → elevate posture one tier

**Posture actions:**
- AUDIT: log decision; allow execution
- RESTRICT: role-based permit check + HITL approval workflow trigger
- DENY + ALERT: hard deny + immediate TrustSOC alert (within 500ms)

**FAIL_CLOSED defaults:** AAPM Blast Radius API unavailable → score = 1.0 (maximum blast radius). Unrecognised deployment tier → HOMEGROWN (most restrictive).

**Key files:** `backend/app/enforcement/posture_matrix.py`, `backend/app/session/blast_radius_client.py`, `backend/app/session/tier_detection.py`

---

### FEATURE-07: Bypass Threat Model with MITRE ATLAS Mapping

A formal bypass threat model documents all four bypass vector classes with MITRE ATLAS IDs, mitigation mapping, and residual risk assessment. This is the authoritative input to AgentRT and to the Reference Monitor Compliance Statement.

**Document:** `docs/threat_model/bypass_vectors.md` (TM-001)

---

### FEATURE-08: Reference Monitor Compliance Statement

AgentPEP v2.1 publishes a formal Reference Monitor Compliance Statement claiming satisfaction of C1 (Always Invoked), C2 (Tamper-Proof), and C3 (Verifiable) against the PCAS 2025 standard.

**Score change:** v1.x 7/15 (FAIL) → v2.1 15/15 (PASS)

**Document:** `docs/compliance/reference_monitor_statement.md` (COMP-003)

Audit report with code-level evidence: `docs/compliance/reference_monitor_assessment.md` (COMP-001 v2.1)

---

### FEATURE-09: AAPM → AgentPEP Integration Contract

The integration contract between AgentPEP and the AAPM Policy Registry is formally defined and validated. This includes webhook delivery, pull polling fallback, emergency revocation, bundle naming conventions, and rollout SLA.

**Validated:** Full PCR → Rego bundle → signed → registry → webhook → AgentPEP enforcement E2E flow, confirmed within 90s (5-minute SLA). Emergency deny-all bundle confirmed active within 3m 42s.

**Contract document:** `docs/integrations/aapm_agentpep_contract_draft.md`

---

## Bypass Vectors Addressed

| Bypass Class | CVE / Research | v1.x Status | v2.1 Status |
|---|---|---|---|
| Configuration Injection | CVE-2025-59536, CVE-2026-21852 | VULNERABLE | **ELIMINATED** |
| Complexity Bypass | Adversa AI 50-subcommand (March 2026) | VULNERABLE | **ELIMINATED** |
| Reasoning Boundary | PCAS Paper (2025) | UNMITIGATED | **MITIGATED** (TrustSOC primary) |
| Hook Gaming | Praetorian (2026) | UNMITIGATED | **MITIGATED** (9/10 blocked; 1/10 residual disclosed) |

---

## AAPM Integration Changes

For operators managing the AAPM → AgentPEP policy lifecycle:

| Change | Details |
|---|---|
| Policy authoring | Now in AAPM (APDL language) — not in AgentPEP YAML config |
| Policy delivery | AAPM Policy Registry via webhook push or 60-second polling fallback |
| Bundle verification | cosign signature verified on every bundle load |
| Bundle version tracking | Reported in every enforcement decision log entry |
| Emergency revocation | AAPM publishes deny-all bundle → AgentPEP enforces within 5 minutes |
| Policy update SLA | PCR approval → enforcement active in < 5 minutes (observed: < 90s) |

See operator migration guide: `docs/migration/v1_to_v2.md`

---

## Performance

All performance SLAs are met. Full report: `docs/reports/load_test_report_v2.1.md`.

| Metric | v1.x | v2.1 | Status |
|---|---|---|---|
| Intercept API P50 latency | ≤ 5 ms | 4.3 ms | PASS |
| Intercept API P99 latency | ≤ 25 ms | 14.8 ms | PASS |
| PDP evaluation P99 (1,000 concurrent) | — | 7.2 ms (< 10ms SLA) | PASS |
| PostToolUse Kafka P99 | — | 312 ms (< 500ms SLA) | PASS |
| Throughput | ≥ 10,000 dec/s | 14,800 dec/s | PASS |
| Memory (60-min soak) | No leak | +12 MB/hr (stable) | PASS |

---

## Security and Compliance

- **Reference monitor certified:** 15/15 COMP-001 criteria (C1, C2, C3 all satisfied)
- **TRQF sign-off:** 34/34 controls implemented and signed off by compliance team (COMP-002 v2.1)
- **AgentRT regression:** 49/50 scenarios pass; 1/50 is the documented 1/10 Hook Gaming residual rate
- **CVE-2025-59536 and CVE-2026-21852:** fully mitigated (pentest confirmed)
- **Adversa AI 50-subcommand bypass:** fully mitigated (AgentRT BV-002 confirmed)

---

## Deprecations and Removals

| Removed Component | Replacement |
|---|---|
| Local YAML policy loading (`policies/rules.yaml`, etc.) | AAPM Policy Registry (signed Rego bundle) |
| `POLICY_PATH` environment variable | Not replaceable — policy source is fixed to AAPM registry |
| `--policy-path` CLI flag | Not replaceable — policy source is fixed to AAPM registry |
| Imperative Python rule evaluation (`RegoNativeEvaluator` production path) | OPA/Rego engine (`FirstAAMPBundleEvaluator` → AAPM bundle) |
| `policies/` directory as runtime config | Retained as example reference only; not loaded by AgentPEP v2.1 |

---

## Upgrade Path

See the detailed operator migration guide: `docs/migration/v1_to_v2.md`

**Summary:**
1. Configure AAPM Policy Registry URL (replaces local policy config)
2. Confirm AAPM team has published the `agentpep-core-v1.0.0` bundle to your registry instance
3. Remove or archive local `policies/` directory overrides
4. Verify `POLICY_PATH` env var is not set (will be blocked and logged if set)
5. Deploy v2.1 (rolling deployment supported — old and new pods can coexist briefly)
6. Verify enforcement decision logs show `policy_bundle_version: agentpep-core-v1.0.0`

---

## Documentation

| Document | Location |
|---|---|
| Reference Monitor Compliance Statement | `docs/compliance/reference_monitor_statement.md` |
| Reference Monitor Audit | `docs/compliance/reference_monitor_assessment.md` |
| TRQF Control Mapping (signed off) | `docs/compliance/trqf_mapping.md` |
| Operator Migration Guide | `docs/migration/v1_to_v2.md` |
| AAPM Integration Contract | `docs/integrations/aapm_agentpep_contract_draft.md` |
| TrustSOC Integration Contract | `docs/integrations/trustsoc_contract.md` |
| AgentRT Contract | `docs/integrations/agentrt_contract.md` |
| Bypass Threat Model | `docs/threat_model/bypass_vectors.md` |
| Evaluation Guarantee Invariant | `docs/invariants/evaluation_guarantee.md` |
| AAPM Policy Source Runbook | `docs/operations/aapm_policy_source.md` |
| AgentRT Regression Report | `docs/reports/agentrt_regression_report_v2.1.md` |
| Load Test Report | `docs/reports/load_test_report_v2.1.md` |

---

*AgentPEP v2.1 · TrustFabric Portfolio · Reference Monitor Certified · Q3 2026*
