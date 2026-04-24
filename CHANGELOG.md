# Changelog

All notable changes to AgentPEP are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/) and follows
the [Keep a Changelog](https://keepachangelog.com/) format.

---

## [Unreleased] — Sprint S-E05: First AAPM Bundle Integration + Parity Validation

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
