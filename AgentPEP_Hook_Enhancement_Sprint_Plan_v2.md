# AgentPEP Hook Enhancement Sprint Plan
## Reference Monitor Upgrade — v2.1 (Revised — AAPM Boundary Corrections)
**Version:** 2.1
**Author:** TrustFabric Product Architecture
**Status:** Draft
**Date:** April 2026
**Linked PRD:** AgentPEP Hook Enhancement PRD v2.1

---

## Revision Notes (v2.0 → v2.1)

| Sprint | Change | Rationale |
|--------|--------|-----------|
| S-E03 | Added AAPM Policy Registry consumer interface task | Missing in v2.0; this is the critical integration |
| S-E05 | Removed bundle build + sign script tasks (E05-T06) | Belongs in AAPM's release pipeline, not AgentPEP |
| S-E05 | Reframed Rego migration as receiving AAPM-compiled bundles | AgentPEP consumes Rego; AAPM compiles from APDL |
| S-E05 | Removed security team Rego readability gate | Security team reviews APDL in AAPM (human-readable); Rego is a compilation output |
| S-E05 | Added parity test against AAPM-compiled bundle | First real bundle received from AAPM; validate decisions match existing behaviour |
| S-E08 | Added AAPM Blast Radius API integration | FEATURE-06 requires blast radius score at session init |
| New S-E09 task | AAPM integration E2E test | Validate full AAPM PCR → Policy Registry → AgentPEP enforcement flow |
| All sprints | Dependency tracking against AAPM sprint plan added | FEATURE-06 blocked until AAPM Sprint 12 (Blast Radius Calculator) completes |

---

## Sprint Overview

| Sprint | Theme | Features | Duration |
|--------|-------|----------|----------|
| S-E01 | Foundations — Threat Model + Design Invariants | FEATURE-07, FEATURE-09 (design), FEATURE-08 (partial) | 2 weeks |
| S-E02 | Complexity Hardening | FEATURE-03 | 2 weeks |
| S-E03 | Trusted Policy Loader + AAPM Consumer Interface | FEATURE-02, FEATURE-09 (Part A) | 2 weeks |
| S-E04 | OPA Runtime Engine — Core | FEATURE-01 (Part A) | 2 weeks |
| S-E05 | First AAPM Bundle Integration + Parity Validation | FEATURE-01 (Part B), FEATURE-09 (Part B) | 2 weeks |
| S-E06 | Recursive Trust Enforcement | FEATURE-04 | 2 weeks |
| S-E07 | PostToolUse Hooks + TrustSOC Contract | FEATURE-05 | 2 weeks |
| S-E08 | Enforcement Posture Matrix + Blast Radius | FEATURE-06 | 2 weeks |
| S-E09 | AgentRT Integration + Bypass Regression + E2E | All features | 2 weeks |
| S-E10 | Hardening, Reference Monitor Certification, Release | FEATURE-08 (complete) | 2 weeks |

**Total duration:** 20 weeks (10 sprints × 2 weeks)
**Target completion:** Q3 2026
**Team:** Solo builder (Shiv) — tasks sized for single-engineer execution
**External dependency:** AAPM team for Policy Registry, Blast Radius API, and APDL compilation pipeline

---

## Sprint S-E01: Foundations — Threat Model, Design Invariants, Integration Design

**Duration:** 2 weeks
**Features:** FEATURE-07, FEATURE-09 (design), FEATURE-08 (partial)
**Goal:** Establish architectural guardrails, design invariants, and the AAPM integration contract design before any code is written.

### Tasks

| ID | Task | Output | Est. Days |
|----|------|--------|-----------|
| E01-T01 | Document the Evaluation Guarantee Invariant as a named design principle | `docs/invariants/evaluation_guarantee.md` | 0.5 |
| E01-T02 | Write the bypass threat model — all four vector classes with MITRE ATLAS IDs (reference AAPM's threat taxonomy) | `docs/threat_model/bypass_vectors.md` | 2 |
| E01-T03 | Map each bypass vector to AgentPEP mitigation feature and residual risk | Section in threat model doc | 1 |
| E01-T04 | Reference monitor compliance current-state assessment: score each criterion against current implementation | `docs/compliance/reference_monitor_assessment.md` | 1 |
| E01-T05 | Define OPA engine deployment model: embedded library vs. sidecar (ADR-001) | `docs/adr/ADR-001-opa-deployment-model.md` | 1 |
| E01-T06 | Design AAPM → AgentPEP integration contract: registry URL, webhook vs. poll, bundle naming convention, rollout SLA, emergency revocation | `docs/integrations/aapm_agentpep_contract_draft.md` | 1.5 |
| E01-T07 | Confirm AAPM team availability and sprint alignment: AAPM Policy Registry readiness, Blast Radius API ETA (must precede S-E08) | Decision log | 0.5 |
| E01-T08 | Draft TRQF control mapping for all nine enhancement features | `docs/compliance/trqf_mapping.md` | 1 |
| E01-T09 | Document portfolio boundary: what AgentPEP owns vs. AAPM owns (policy authoring, signing, audit trail, blast radius) | `docs/architecture/portfolio_boundary.md` | 0.5 |

**Exit Criteria:**
- [ ] Evaluation Guarantee Invariant documented and accepted
- [ ] All four bypass vectors documented with MITRE ATLAS IDs
- [ ] ADR-001 decided
- [ ] AAPM integration contract draft reviewed and agreed with AAPM team
- [ ] AAPM Blast Radius API delivery date confirmed (required before S-E08 begins)
- [ ] Portfolio boundary document accepted by both AgentPEP and AAPM teams

**Dependencies:** AAPM team availability for contract design review
**Risk:** Low — documentation sprint; no production impact. The AAPM coordination is the only external dependency.

---

## Sprint S-E02: Complexity Hardening

**Duration:** 2 weeks
**Feature:** FEATURE-03
**Goal:** Eliminate the complexity-based bypass class. Implement the Evaluation Guarantee Invariant in code.

### Tasks

| ID | Task | Output | Est. Days |
|----|------|--------|-----------|
| E02-T01 | Implement complexity budget checker as a pre-evaluation gate in the PreToolUse interceptor | `agentpep/enforcement/complexity_budget.py` | 2 |
| E02-T02 | Define budget parameters as operator-configurable values with hardcoded DENY on exceeded (no permissive fallback configurable) | Config schema + validation | 1 |
| E02-T03 | Implement evaluation timeout using asyncio; on timeout → DENY (Evaluation Guarantee Invariant) | `agentpep/enforcement/eval_timeout.py` | 1 |
| E02-T04 | Implement COMPLEXITY_EXCEEDED event emission (stub OCSF schema; formalised in S-E07) | Event emission function | 1 |
| E02-T05 | Write unit tests: argument size exceeded, subcommand count exceeded, nesting depth exceeded, timeout triggered | `tests/test_complexity_budget.py` | 2 |
| E02-T06 | Adversarial test: 50+ subcommand compound command → verify DENY + COMPLEXITY_EXCEEDED event | `tests/adversarial/test_compound_command_bypass.py` | 1 |
| E02-T07 | Adversarial test: deliberately slow evaluation triggering timeout → verify DENY | `tests/adversarial/test_eval_timeout_bypass.py` | 0.5 |
| E02-T08 | Document complexity budget parameters in operator runbook | `docs/operations/complexity_budget.md` | 0.5 |

**Exit Criteria:**
- [ ] All budget parameters implemented and tested
- [ ] Timeout FAIL_CLOSED implemented and tested
- [ ] Adversarial compound command test: DENY confirmed
- [ ] Adversarial timeout test: DENY confirmed
- [ ] No operator configuration can produce ALLOW on budget exceeded

**Dependencies:** S-E01 (Evaluation Guarantee Invariant defined)
**Risk:** Medium — changes PreToolUse interceptor hot path; latency regression testing required

---

## Sprint S-E03: Trusted Policy Loader + AAPM Consumer Interface

**Duration:** 2 weeks
**Features:** FEATURE-02, FEATURE-09 (Part A)
**Goal:** Implement the trusted policy loader and the AgentPEP side of the AAPM integration contract. Establish the registry consumer interface before the OPA engine is built.

### Tasks

| ID | Task | Output | Est. Days |
|----|------|--------|-----------|
| E03-T01 | Implement policy loader with allowlisted source (AAPM Policy Registry URL only; no working directory, no env var) | `agentpep/policy/loader.py` | 1.5 |
| E03-T02 | Implement cosign signature verification in loader: verify before load, FAIL_CLOSED on failure | Cosign verification in loader | 1.5 |
| E03-T03 | Pin AAPM policy public key in AgentPEP binary (compile-time constant, not runtime config) | `agentpep/policy/trusted_key.py` | 1 |
| E03-T04 | Implement SECURITY_VIOLATION event on: invalid signature, untrusted source path, env var override attempt | Event emission + test | 1 |
| E03-T05 | Implement AAPM registry webhook receiver: accept push notification from AAPM → trigger policy reload | `agentpep/policy/registry_webhook.py` | 1.5 |
| E03-T06 | Implement pull polling fallback: poll AAPM registry every 60s if webhook unavailable | `agentpep/policy/registry_poll.py` | 1 |
| E03-T07 | Implement bundle version tracking: current version stored in memory; reported in enforcement decision events | Version tracking module | 0.5 |
| E03-T08 | Write unit tests: valid bundle loads, invalid signature rejects, untrusted path rejects, env var override rejects | `tests/test_policy_loader.py` | 1 |
| E03-T09 | Pentest: simulate CVE-2025-59536 config injection attack → verify block + SECURITY_VIOLATION event | `tests/pentest/test_config_injection.py` | 1 |
| E03-T10 | Stub AAPM registry for local development (mock server serving a pre-signed test bundle) | `scripts/mock_aapm_registry.py` | 0.5 |

**Exit Criteria:**
- [ ] Policy loader rejects all untrusted source paths
- [ ] cosign verification integrated and tested
- [ ] Public key pinned in binary
- [ ] Webhook receiver operational (tested against mock registry)
- [ ] Pull polling fallback operational
- [ ] Config injection pentest: attack blocked + SECURITY_VIOLATION event confirmed
- [ ] Mock AAPM registry available for development use

**Dependencies:** S-E01 (AAPM integration contract agreed, cosign public key received from AAPM team)
**Risk:** Medium — requires cosign key coordination with AAPM team; mock registry mitigates for initial development

---

## Sprint S-E04: OPA Runtime Engine — Core

**Duration:** 2 weeks
**Feature:** FEATURE-01 (Part A)
**Goal:** Integrate OPA engine as AgentPEP's runtime policy evaluation engine. Scope: consumer only — no policy authoring.

### Tasks

| ID | Task | Output | Est. Days |
|----|------|--------|-----------|
| E04-T01 | Integrate OPA Python SDK or deploy OPA sidecar per ADR-001 decision | OPA engine operational in AgentPEP | 2 |
| E04-T02 | Implement authorisation request builder: PreToolUse interceptor context → structured OPA input JSON | `agentpep/pdp/request_builder.py` | 2 |
| E04-T03 | Implement PDP response parser: OPA output → ALLOW / DENY / MODIFY + reason code | `agentpep/pdp/response_parser.py` | 1 |
| E04-T04 | Implement PDP client with timeout enforcement (connects to FEATURE-03 FAIL_CLOSED) | `agentpep/pdp/client.py` | 1 |
| E04-T05 | Implement enforcement decision log: every evaluation logged with agent, tool, bundle version, decision, latency | `agentpep/pdp/enforcement_log.py` | 1 |
| E04-T06 | Load stub Rego bundle from mock AAPM registry (built in S-E03-T10) for integration testing | Integration test setup | 0.5 |
| E04-T07 | Write integration tests: PreToolUse interceptor → PDP → ALLOW/DENY decision round trip | `tests/integration/test_pdp_roundtrip.py` | 1 |
| E04-T08 | Latency benchmark: PDP decision latency under 100, 500, 1000 concurrent evaluations; verify P99 < 10ms | Benchmark report | 1 |

**Exit Criteria:**
- [ ] OPA engine operational and receiving evaluation requests
- [ ] Authorisation request schema matches PRD v2.1 specification (including blast_radius_score placeholder)
- [ ] Round-trip integration test passing against stub bundle
- [ ] PDP latency P99 < 10ms (benchmark result documented)
- [ ] Every evaluation produces an enforcement decision log entry with bundle version
- [ ] No Rego authored by AgentPEP team — only the AAPM-provided stub bundle used

**Dependencies:** S-E03 (policy loader + mock AAPM registry)
**Risk:** High — core architectural change; parallel-run against existing imperative rules required

---

## Sprint S-E05: First AAPM Bundle Integration + Parity Validation

**Duration:** 2 weeks
**Features:** FEATURE-01 (Part B), FEATURE-09 (Part B)
**Goal:** Receive the first real Rego bundle compiled by AAPM from APDL. Validate that AAPM-compiled policies produce identical enforcement decisions to AgentPEP's current imperative rules. Decommission imperative rules after parity is confirmed.

### Tasks

| ID | Task | Output | Est. Days |
|----|------|--------|-----------|
| E05-T01 | Audit all existing AgentPEP imperative enforcement rules; produce inventory for AAPM team | Rule inventory doc (input to AAPM's APDL authoring) | 1 |
| E05-T02 | Provide rule inventory to AAPM team; AAPM team translates to APDL and compiles to signed Rego bundle | AAPM deliverable (not AgentPEP task — track as dependency) | — |
| E05-T03 | Receive first AAPM-compiled bundle from Policy Registry; load via trusted policy loader (S-E03) | Bundle loaded in test environment | 0.5 |
| E05-T04 | Parity test: run existing imperative rules and AAPM-compiled Rego bundle against identical inputs; compare decisions | `tests/parity/test_aapm_bundle_parity.py` | 2 |
| E05-T05 | Root-cause any decision divergences between old rules and AAPM bundle; raise issues with AAPM team for correction | Divergence report | 1.5 |
| E05-T06 | Validate full AAPM integration flow end-to-end: PCR approval in AAPM → bundle published to registry → AgentPEP webhook → new bundle active | E2E integration test | 1.5 |
| E05-T07 | Validate pull polling fallback: disable webhook; confirm AgentPEP picks up new bundle within 60s via polling | Polling test | 0.5 |
| E05-T08 | Validate emergency deny-all bundle: AAPM publishes deny-all → AgentPEP enforces within 5-minute SLA | Emergency bundle test | 0.5 |
| E05-T09 | Decommission imperative rule evaluation code after 100% parity confirmed | Code removal + changelog entry | 0.5 |
| E05-T10 | Update operator documentation: policy is now authored in AAPM, not in AgentPEP config | Updated runbook | 0.5 |

**Exit Criteria:**
- [ ] First real AAPM-compiled bundle received and loaded successfully
- [ ] Parity test: 100% decision match between old imperative rules and AAPM bundle
- [ ] E2E integration flow validated: PCR approval → AgentPEP enforcement active within 5 minutes
- [ ] Pull polling and webhook delivery both tested
- [ ] Emergency deny-all bundle enforced within SLA
- [ ] Imperative rule code removed
- [ ] Operator documentation updated to reflect AAPM as policy source

**Dependencies:**
- S-E03 (trusted policy loader), S-E04 (OPA engine)
- AAPM team deliverable: APDL authoring of AgentPEP rules + first signed bundle
- AAPM Policy Registry must be operational

**Risk:** High — AAPM team dependency is the critical path item. If AAPM bundle is not ready, parity testing is blocked. Mitigation: use extended mock AAPM registry with manually-authored Rego stubs; real AAPM bundle integration as a follow-up task in S-E06 warmup.

---

## Sprint S-E06: Recursive Trust Enforcement

**Duration:** 2 weeks
**Feature:** FEATURE-04
**Goal:** Replace the hop counter with recursive PEP invocation and trust score degradation across delegation chains.

### Tasks

| ID | Task | Output | Est. Days |
|----|------|--------|-----------|
| E06-T01 | Implement delegation context propagation: principal chain carried in every tool call context | `agentpep/trust/delegation_context.py` | 2 |
| E06-T02 | Implement trust score calculator: linear decay per hop, configurable decay rate, minimum threshold | `agentpep/trust/trust_score.py` | 1 |
| E06-T03 | Implement effective permission calculator: intersection of root principal and current agent permissions | `agentpep/trust/permission_intersection.py` | 2 |
| E06-T04 | Update authorisation request builder (E04-T02) to include full delegation chain and trust score in OPA input | Updated request builder | 0.5 |
| E06-T05 | Implement TRUST_VIOLATION event: emitted when subagent claims higher permissions than root principal | Event emission | 0.5 |
| E06-T06 | Write unit tests: single hop, max hop termination, trust score decay, permission intersection | `tests/test_trust_enforcement.py` | 1 |
| E06-T07 | Adversarial test: subagent attempts permission escalation beyond root principal → verify DENY + TRUST_VIOLATION | `tests/adversarial/test_trust_escalation.py` | 1 |
| E06-T08 | Validate decay rate against LangGraph multi-hop workflow: confirm 15% default does not over-terminate legitimate chains | Validation report | 1 |

**Exit Criteria:**
- [ ] Delegation chain propagated to every PDP evaluation
- [ ] Trust score degrades correctly across hops
- [ ] Effective permissions never exceed root principal's permissions
- [ ] Trust escalation adversarial test: DENY + TRUST_VIOLATION event confirmed
- [ ] Chain terminates below minimum trust threshold
- [ ] LangGraph workflow validation: default decay rate does not cause false positives in real multi-agent patterns

**Dependencies:** S-E04, S-E05 (PDP + real AAPM bundle operational)
**Risk:** High — changes the permission model; extensive testing against real multi-agent workflows required

---

## Sprint S-E07: PostToolUse Hooks and TrustSOC Integration Contract

**Duration:** 2 weeks
**Feature:** FEATURE-05
**Goal:** Formalise PostToolUse as a named hook type with OCSF-native event emission and a defined TrustSOC integration contract.

### Tasks

| ID | Task | Output | Est. Days |
|----|------|--------|-----------|
| E07-T01 | Implement PostToolUse hook registration and invocation | `agentpep/hooks/post_tool_use.py` | 2 |
| E07-T02 | Implement OCSF event schema for PostToolUse (aligned with TrustFabric OCSF Profile, includes blast_radius_score field) | `agentpep/events/post_tool_use_event.py` | 1.5 |
| E07-T03 | Implement sequence ID linking PreToolUse and PostToolUse events for same invocation | Sequence ID generation + propagation | 1 |
| E07-T04 | Implement HMAC signature on each emitted event (tamper-evident stream) | Event signing | 1 |
| E07-T05 | Implement Kafka producer for PostToolUse events (topic: `agentpep.posttooluse.events`) | `agentpep/transport/kafka_producer.py` | 1 |
| E07-T06 | Upgrade COMPLEXITY_EXCEEDED and SECURITY_VIOLATION events (stubs from S-E02, S-E03) to full OCSF schema | Updated event classes | 0.5 |
| E07-T07 | Write OCSF schema linter integration for CI | CI pipeline step | 0.5 |
| E07-T08 | Formalise TrustSOC integration contract document | `docs/integrations/trustsoc_contract.md` | 1 |
| E07-T09 | Integration test: tool call completes → PostToolUse event on Kafka within 500ms | `tests/integration/test_posttooluse_emission.py` | 0.5 |

**Exit Criteria:**
- [ ] PostToolUse events emitted for every tool call (ALLOW and DENY)
- [ ] Sequence ID links Pre and PostToolUse events
- [ ] HMAC signature implemented and verified
- [ ] Kafka delivery within 500ms SLA under load
- [ ] TrustSOC integration contract signed off
- [ ] OCSF schema linter passes in CI
- [ ] blast_radius_score included in PostToolUse event schema (placeholder until S-E08)

**Dependencies:** Kafka infrastructure
**Risk:** Medium — Kafka dependency; local mock Kafka acceptable for testing

---

## Sprint S-E08: Enforcement Posture Matrix + Blast Radius Integration

**Duration:** 2 weeks
**Feature:** FEATURE-06
**Goal:** Implement the 3×3 posture matrix with blast radius elevation. Integrate AAPM Blast Radius API at session initialisation.

**Hard Dependency:** AAPM Sprint 12 (Blast Radius Calculator) must be complete before this sprint begins. Confirm with AAPM team at S-E07 retrospective.

### Tasks

| ID | Task | Output | Est. Days |
|----|------|--------|-----------|
| E08-T01 | Implement AAPM Blast Radius API client: query at session start, attach score to session context | `agentpep/session/blast_radius_client.py` | 1.5 |
| E08-T02 | Implement FAIL_CLOSED for Blast Radius API unavailability: default score = 1.0 | Fallback in blast radius client | 0.5 |
| E08-T03 | Implement deployment tier detection at session start: operator config → env fingerprint → default HOMEGROWN | `agentpep/session/tier_detection.py` | 1.5 |
| E08-T04 | Implement posture matrix lookup: (taint_level, deployment_tier) → base posture | `agentpep/enforcement/posture_matrix.py` | 1 |
| E08-T05 | Implement blast radius elevation: if blast_radius_score ≥ 0.75, elevate posture one tier | Elevation logic in posture matrix | 0.5 |
| E08-T06 | Implement DENY + ALERT posture: hard deny + immediate TrustSOC alert event | Alert event emission | 1 |
| E08-T07 | Implement RESTRICT posture: role-based permit check + HITL approval workflow trigger stub | HITL workflow stub | 1 |
| E08-T08 | Update OPA authorisation request to include blast_radius_score and deployment_tier | Updated request builder | 0.5 |
| E08-T09 | Write unit tests: all nine base matrix cells, blast radius elevation, HOMEGROWN default | `tests/test_posture_matrix.py` | 1.5 |
| E08-T10 | Test: AAPM Blast Radius API unavailable → defaults to 1.0 → posture elevated correctly | Fallback test | 0.5 |

**Exit Criteria:**
- [ ] Blast radius score fetched from AAPM API at session init
- [ ] API unavailability defaults to 1.0 (FAIL_CLOSED)
- [ ] Blast radius ≥ 0.75 elevates posture one tier
- [ ] All nine base matrix cells implemented and tested
- [ ] Ambiguous tier defaults to HOMEGROWN
- [ ] blast_radius_score in all PostToolUse events for the session (connects to S-E07 schema)
- [ ] DENY + ALERT posture emits TrustSOC alert within 500ms

**Dependencies:**
- S-E05 (AAPM bundle operational), S-E07 (PostToolUse events)
- **AAPM Sprint 12 (Blast Radius Calculator) — hard external dependency**

**Risk:** High — AAPM Sprint 12 timing is outside AgentPEP team control. If delayed, implement posture matrix without blast radius dimension first; add elevation logic as a follow-up task once AAPM API is available. Do not hold S-E08 entirely for this dependency.

---

## Sprint S-E09: AgentRT Integration + Bypass Regression + E2E Validation

**Duration:** 2 weeks
**Goal:** Establish AgentRT as AgentPEP's mandatory validation harness. Build bypass regression suite. Validate the complete AAPM → AgentPEP → TrustSOC chain end-to-end.

### Tasks

| ID | Task | Output | Est. Days |
|----|------|--------|-----------|
| E09-T01 | Define AgentRT integration interface: API contract between AAPM policy bundle release pipeline and AgentRT test runner | `docs/integrations/agentrt_contract.md` | 1 |
| E09-T02 | Bypass regression — Class 1 (Config Injection): CVE-2025-59536 pattern → verify BLOCK + SECURITY_VIOLATION | `agentrt/suites/bypass_config_injection.py` | 1.5 |
| E09-T03 | Bypass regression — Class 2 (Complexity Bypass): compound command variants, timeout triggers | `agentrt/suites/bypass_complexity.py` | 1.5 |
| E09-T04 | Bypass regression — Class 3 (Reasoning Boundary): action decomposition sequences — individually permissible, collectively harmful | `agentrt/suites/bypass_reasoning_boundary.py` | 2 |
| E09-T05 | Bypass regression — Class 4 (Hook Gaming): adversarial agent prompted to identify and exploit loopholes | `agentrt/suites/bypass_hook_gaming.py` | 2 |
| E09-T06 | Integrate AgentRT regression suite as a gate in the AAPM policy bundle release pipeline (CI block on failure) | CI pipeline integration (joint with AAPM team) | 1 |
| E09-T07 | E2E validation: AAPM PCR approval → Rego bundle compiled → signed → published to registry → AgentPEP webhook → new policy active → AgentRT regression passes | E2E test run + report | 1 |
| E09-T08 | Document CVE-to-test SLA: new public disclosures → AgentRT test cases within 14 days | `docs/process/cve_to_test.md` | 0.5 |

**Exit Criteria:**
- [ ] AgentRT integration interface defined and agreed
- [ ] All four bypass classes have regression tests
- [ ] AgentRT regression suite integrated as CI gate on AAPM bundle releases
- [ ] E2E validation: full AAPM → AgentPEP → TrustSOC flow confirmed
- [ ] CVE-to-test process documented

**Dependencies:** All S-E02 through S-E08 complete; AgentRT team for test runner integration
**Risk:** Medium — Class 4 (hook gaming) tests non-deterministic; define pass threshold (8/10 runs blocked)

---

## Sprint S-E10: Hardening, Reference Monitor Certification, and Release

**Duration:** 2 weeks
**Feature:** FEATURE-08 (complete)
**Goal:** Close the reference monitor compliance gap, complete documentation, ship AgentPEP v2.1.

### Tasks

| ID | Task | Output | Est. Days |
|----|------|--------|-----------|
| E10-T01 | Reference monitor compliance audit: verify each criterion against implemented code with evidence | Compliance audit report | 1.5 |
| E10-T02 | Write Reference Monitor Compliance Statement for external product documentation | `docs/compliance/reference_monitor_statement.md` | 1 |
| E10-T03 | Run full AgentRT regression suite on release candidate | Regression report | 0.5 |
| E10-T04 | Load test: 1,000 concurrent sessions; verify PDP P99 < 10ms, PostToolUse P99 < 500ms | Load test report | 1 |
| E10-T05 | TRQF control mapping review sign-off with compliance team | Signed TRQF mapping | 1 |
| E10-T06 | Write release notes: what changed, bypass vectors addressed, AAPM integration changes, migration from v1.x | `RELEASE_NOTES_v2.1.md` | 1 |
| E10-T07 | Write operator migration guide: policy is now sourced from AAPM — how to decommission any remaining local config | `docs/migration/v1_to_v2.md` | 1 |
| E10-T08 | LinkedIn launch content: reference monitor certification + 93% vs 48% stat + AAPM integration as portfolio story | Draft content | 0.5 |
| E10-T09 | Update README, architecture diagram, and product page with v2.1 architecture | Updated docs | 0.5 |
| E10-T10 | Tag v2.1 release; merge to main; deploy to staging | Release artefact | 0.5 |

**Exit Criteria:**
- [ ] Reference monitor compliance audit: 3/3 criteria satisfied with evidence
- [ ] Full AgentRT regression passes on release candidate
- [ ] Load test confirms latency SLAs
- [ ] TRQF mapping signed off
- [ ] Release notes and migration guide published
- [ ] v2.1 tagged and deployed to staging

**Dependencies:** All S-E01 through S-E09 complete
**Risk:** Low — hardening and documentation sprint; no new architectural changes

---

## Portfolio Dependency Tracker

| AgentPEP Sprint | AAPM Dependency | AAPM Sprint | Status |
|-----------------|-----------------|-------------|--------|
| S-E01 | Integration contract design agreement | Any | Required before S-E01 exits |
| S-E03 | cosign public key for bundle verification | Any | Required before S-E03 begins |
| S-E03 | Policy Registry operational (even stub) | AAPM Sprint 1–4 | Required for S-E03 testing |
| S-E05 | First AAPM-compiled Rego bundle from APDL | AAPM Sprint 9 | Critical path for S-E05 parity test |
| S-E05 | PCR workflow operational for E2E test | AAPM Sprint 10 | Required for S-E05-T06 |
| S-E08 | Blast Radius Calculator API available | AAPM Sprint 12 | Hard block on S-E08-T01 |
| S-E09 | AgentRT gate in AAPM bundle release pipeline | AAPM any | Joint task — coordinate with AAPM team |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| AAPM bundle not ready for S-E05 parity test | Medium | High | Extend mock AAPM registry with hand-authored Rego stubs; real bundle as S-E06 warmup |
| AAPM Blast Radius API (Sprint 12) delayed beyond S-E08 | Medium | Medium | Implement posture matrix without blast radius elevation first; add in follow-up sprint |
| OPA sidecar latency exceeds 10ms P99 | Medium | High | Benchmark in S-E04; fall back to embedded library per ADR-001 |
| Parity test reveals rule translation errors in AAPM bundle | Medium | High | Do not decommission imperative rules until 100% parity; raise issues with AAPM team |
| AAPM team bandwidth conflicts | Medium | High | Agree integration contract deliverables in S-E01; document as external dependency; escalate early if at risk |
| AgentRT Class 4 (hook gaming) non-deterministic | High | Medium | Pass threshold: 8/10 runs blocked; document as known limitation |
| Single-engineer bandwidth | High | Medium | Sprints sequenced so each builds on the last; AAPM dependencies are the true critical path |

---

## Definition of Done (All Sprints)

- [ ] All sprint tasks completed
- [ ] Unit tests passing (≥ 90% coverage on new code)
- [ ] Adversarial/pentest tests passing where specified
- [ ] No new critical or high severity issues introduced
- [ ] OCSF schema linter passing on all new events
- [ ] AgentRT regression suite passing (from S-E09 onwards)
- [ ] Relevant documentation updated
- [ ] AAPM team notified of any integration contract changes
- [ ] Sprint retrospective note filed

---

## Milestone Summary

| Milestone | Sprint | Description |
|-----------|--------|-------------|
| **M1: Hardened Interceptor** | S-E02 complete | Complexity-based bypass class eliminated |
| **M2: Trusted Policy Consumer** | S-E03 complete | Config injection attack class eliminated; AAPM registry integration live |
| **M3: OPA Runtime Engine Live** | S-E04 complete | Declarative evaluation operational |
| **M4: AAPM Bundle Active** | S-E05 complete | First real AAPM-compiled bundle enforced; imperative rules decommissioned |
| **M5: Recursive Trust Enforcement** | S-E06 complete | Subagent trust escalation eliminated |
| **M6: Full Observability** | S-E07 complete | PostToolUse stream flowing to TrustSOC |
| **M7: Posture Matrix + Blast Radius** | S-E08 complete | Enterprise posture configurable; AAPM Blast Radius integrated |
| **M8: Bypass Validated** | S-E09 complete | All four bypass classes regression-tested; full E2E flow validated |
| **M9: AgentPEP v2.1 — Reference Monitor Certified** | S-E10 complete | Full reference monitor compliance claimed, evidenced, and published |

---

## Post-v2.1 Backlog

| Item | Rationale |
|------|-----------|
| HITL approval workflow (full implementation) | RESTRICT posture stub in S-E08 becomes full async human approval flow |
| Cedar policy language support | Evaluate if AAPM adopts Cedar alongside OPA for AWS-ecosystem customers |
| Homegrown agent SDK integrations (LangChain, CrewAI, LangGraph) | Official SDK wrappers to extend framework-agnostic claim |
| AgentPEP-as-a-Service | Hosted PDP for SaaS deployments — requires MSA partnership alignment |
| AAPM Blast Radius score caching with TTL | Mitigate AAPM API downtime without defaulting to score = 1.0 |

---

*Document Owner: TrustFabric Product Architecture*
*Next Review: Sprint S-E01 kickoff*
*Distribution: Internal — Engineering, Security Architecture, AAPM Team*
