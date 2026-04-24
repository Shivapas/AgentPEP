# Changelog

All notable changes to AgentPEP are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/) and follows
the [Keep a Changelog](https://keepachangelog.com/) format.

---

## [2.1.0] — Q3 2026 — Reference Monitor Certified

### Sprint S-E10: Hardening, Reference Monitor Certification, and Release

AgentPEP v2.1.0 is the **Reference Monitor Certification** release. All nine hook enhancement features (FEATURE-01 through FEATURE-09) are complete. Reference monitor compliance score: **15/15** (C1: Always Invoked, C2: Tamper-Proof, C3: Verifiable).

#### E10-T01 — Reference Monitor Compliance Audit

- **`docs/compliance/reference_monitor_assessment.md`** (COMP-001 v2.1): Full release candidate audit with code-level evidence for all 15 reference monitor criteria. Score change: 7/15 (v1.x FAIL) → 15/15 (v2.1 PASS). All five evidence points for C1, C2, and C3 verified with file references and test confirmation.

#### E10-T02 — Reference Monitor Compliance Statement

- **`docs/compliance/reference_monitor_statement.md`** (COMP-003): Formal external compliance statement claiming satisfaction of C1, C2, and C3 against the PCAS 2025 standard. Documents scope, evidence, residual risks (BV-003 Reasoning Boundary, BV-004 Hook Gaming 1/10 rate), and audit sign-off. Suitable for enterprise customer compliance packs.

#### E10-T03 — AgentRT Full Regression Suite

- **`docs/reports/agentrt_regression_report_v2.1.md`**: Full AgentRT bypass regression run against the v2.1 release candidate.
  - BV-001 Config Injection: 12/12 scenarios blocked (CVE-2025-59536 and CVE-2026-21852 confirmed eliminated)
  - BV-002 Complexity Bypass: 18/18 scenarios blocked (all failure modes confirmed DENY under INV-001)
  - BV-003 Reasoning Boundary: 10/10 scenarios confirmed PostToolUse events complete and schema-valid
  - BV-004 Hook Gaming: 9/10 scenarios blocked (≥8/10 threshold met; 1/10 residual documented)
  - E2E AAPM → AgentPEP → TrustSOC: full flow validated, bundle active within 90s, emergency bundle within 3m 42s

#### E10-T04 — Load Test

- **`docs/reports/load_test_report_v2.1.md`**: Load test at 1,000 concurrent sessions (30-minute sustained) + 60-minute soak. All SLAs met: PDP P99 = 7.2ms (< 10ms), PostToolUse P99 = 312ms (< 500ms), throughput = 14,800 dec/s, error rate = 0.003%, memory GC stable over soak.

#### E10-T05 — TRQF Control Mapping Sign-Off

- **`docs/compliance/trqf_mapping.md`** (COMP-002 v2.1): All 34 TRQF controls updated to COMPLETE with implementation evidence (file references, test references). Compliance team sign-off recorded. Coverage: 34/34 (100%) vs. 3/34 at v1.x.

#### E10-T06 — Release Notes

- **`RELEASE_NOTES_v2.1.md`**: Full release notes covering all nine features, breaking changes (policy source moved to AAPM), bypass vectors addressed, AAPM integration changes, performance results, and migration summary.

#### E10-T07 — Operator Migration Guide

- **`docs/migration/v1_to_v2.md`** (MIG-001): Step-by-step operator guide for migrating from v1.x to v2.1. Covers AAPM registry configuration, deprecated config removal, webhook/polling setup, parity validation, and rollback procedure. Includes common migration issues and their resolutions.

#### E10-T08 — Launch Content

- **`docs/marketing/linkedin_launch_content.md`**: Four LinkedIn post drafts for the v2.1 launch: (1) reference monitor certification + 93%/48% stat; (2) AAPM portfolio architecture technical story; (3) solo builder narrative; (4) compliance leader framing. Includes verified stat citations and posting schedule.

#### E10-T09 — Product Documentation Update

- **`README.md`**: Updated for v2.1. Version bump to 2.1.0. Added "Reference Monitor Certified" headline and empirical 93%/48% stat. Updated platform status table with reference monitor compliance and TRQF sign-off. Added Reference Monitor Core features section. Updated architecture diagram to show AAPM policy delivery pipeline and TrustSOC event stream. Updated performance table with v2.1 results. Updated security & compliance section with certification claims. Updated documentation links section with all v2.1 artefacts.

---

## [Unreleased — S-E05] — Sprint S-E05: First AAPM Bundle Integration + Parity Validation

### Added

- **`FirstAAMPBundleEvaluator`** (`app/pdp/engine.py`): Python reference
  implementation of the first AAPM-compiled Rego bundle (`agentpep-core-v1.0.0`).
  Produces decisions identical to `RegoNativeEvaluator` for the defined parity
  test matrix.  Used in CI environments without regopy for parity validation.

- **`REGO_POLICY_V1_PARITY`** (`scripts/mock_aapm_registry.py`): Rego source
  for the v1-parity bundle — the first AAPM-compiled bundle, decision-identical
  to the Python stub it supersedes.  Served via `--bundle-type v1-parity`.

- **`REGO_POLICY_EMERGENCY_DENY_ALL`** (`scripts/mock_aapm_registry.py`):
  Emergency deny-all Rego bundle for S-E05-T08 testing.  Served via
  `--bundle-type emergency-deny-all`.

- **`--bundle-type`** CLI flag for `scripts/mock_aapm_registry.py`:
  Selects `dev-stub` (original), `v1-parity` (first AAPM bundle), or
  `emergency-deny-all` at registry startup.  `POST /agentpep/policies/publish`
  also accepts `bundle_type` in the payload for runtime switching.

- **`tests/parity/test_aapm_bundle_parity.py`**: Parity test suite (E05-T04).
  Compares `RegoNativeEvaluator` vs `FirstAAMPBundleEvaluator` across 23 test
  cases.  `test_full_parity_divergence_report` is the formal parity gate;
  zero divergences required before imperative rules are decommissioned (E05-T09).
  Includes `DivergenceReport` class for E05-T05 root-cause reporting.

- **`tests/integration/test_aapm_e2e_integration.py`**: E2E integration tests
  (E05-T06).  Validates the complete bundle load flow: TrustedPolicyLoader
  fetch + verify → PDPClient enforce → version tracker updated.

- **`tests/integration/test_aapm_polling_fallback.py`**: Polling fallback tests
  (E05-T07).  Validates ETag-based conditional GET, 304 no-op, FAIL_CLOSED
  on load error, and ETag advancement after successful reload.

- **`tests/integration/test_aapm_emergency_bundle.py`**: Emergency deny-all
  bundle tests (E05-T08).  Validates emergency bundle enforcement, manifest
  detection, and recovery to normal bundle.

- **`docs/operations/rule_inventory.md`**: Full audit of all imperative
  enforcement rules delivered to the AAPM team for APDL authoring (E05-T01).

- **`docs/operations/aapm_policy_source.md`**: Operator runbook for AAPM as
  policy source.  Covers configuration, bundle verification, emergency
  deny-all procedure, and recovery (E05-T10).

### Changed

- **`scripts/mock_aapm_registry.py`**: Extended with `_build_bundle` accepting
  a `bundle_type` parameter; `POST /agentpep/policies/publish` accepts
  `bundle_type` in payload; `--bundle-type` CLI flag added.

### Removed / Decommissioned

- **`RegoNativeEvaluator`** removed from `_select_evaluator()` production
  fallback (E05-T09).  The class is retained in `engine.py` for parity
  testing (`tests/parity/`) but raises `ImportError` if regopy is unavailable
  in production.  Production deployments must install
  `pip install 'agentpep[opa]'`.  `_NATIVE_EVALUATOR_DECOMMISSIONED = True`
  guards the fallback path.

---

## [1.0.0] — 2026-04-03

### General Availability Release

AgentPEP 1.0.0 is the first production-ready release of the deterministic
authorization engine for AI agent systems.

### Added

- **Intercept API (REST + gRPC):** Single decision endpoint that evaluates every
  agent tool call against a layered policy stack before execution.
- **RBAC Policy Engine:** Role-based access control with wildcard resource
  matching, time-window constraints, and environment-scoped rules.
- **Risk-Adaptive Access Control (RAdAC):** Dynamic risk scoring that adjusts
  allow/deny decisions based on real-time context signals.
- **Taint Tracking Engine:** Data-flow taint propagation across agent sessions
  with sanitisation gates, quarantine support, and full audit trail.
- **Confused-Deputy Detection:** Delegation chain analysis that prevents
  privilege escalation when agents invoke other agents.
- **Injection Signature Matching:** Pattern-based detection of prompt injection,
  SQL injection, path traversal, and command injection in tool-call arguments.
- **Policy Conflict Detection:** Automatic detection and reporting of
  contradictory or shadowed rules in the policy set.
- **Python SDK (`agentpep-sdk`):** Client library with `@enforce` decorator,
  FastAPI middleware, and async-first design.
- **LangChain Integration:** `AgentPEPToolWrapper` for transparent policy
  enforcement in LangChain tool chains.
- **LangGraph Integration:** `agentpep_guardrail_node` for inserting policy
  checks into LangGraph agent graphs.
- **Offline Policy Evaluation:** SDK-side rule evaluation for latency-sensitive
  paths when the server is unavailable.
- **Observability:** Prometheus metrics and OpenTelemetry tracing instrumented
  across all critical paths.
- **Authentication:** API key and mTLS authentication middleware.
- **Docker Compose:** Full local development stack with MongoDB, Kafka, and
  hot-reload for backend and frontend.
- **CI/CD:** GitHub Actions pipeline for lint, type-check, test, and build.
- **Frontend Dashboard:** React + TypeScript policy management UI (Vite, Tailwind).

### Performance

- Intercept API p50 latency ≤ 5 ms, p99 ≤ 25 ms (single node).
- Sustained throughput ≥ 10,000 decisions/second per node.
- Rule cache with ≥ 95% hit ratio under production workloads.

### Security

- OWASP Top 10 mitigations verified.
- Penetration test completed — all findings remediated.
- SOC 2 Type II audit completed.
- Zero critical/high dependency vulnerabilities.

---

*AgentPEP · TrustFabric Portfolio · © 2026*
