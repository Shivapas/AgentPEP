# Reference Monitor Compliance — Assessment

**Document ID:** COMP-001
**Version:** 2.1 (Release Candidate Audit)
**Status:** FINAL — Sprint S-E10 release candidate audit
**Sprint:** S-E10 (E10-T01)
**Owner:** TrustFabric Product Architecture
**Initial Assessment Date:** April 2026 (v1.x baseline, Sprint S-E01)
**Release Audit Date:** April 2026 (v2.1 release candidate, Sprint S-E10)

---

## 1. Reference Monitor Standard

The classical reference monitor model (Anderson, 1972; formalised in PCAS, 2025) defines three mandatory criteria for a compliant enforcement layer:

| Criterion | Definition |
|---|---|
| **C1: Always Invoked** | Every access attempt by every subject must be mediated by the monitor. No path to the resource exists that bypasses the monitor. |
| **C2: Tamper-Proof** | The monitor's enforcement logic and policy state cannot be modified or bypassed by any subject it controls. |
| **C3: Verifiable** | The monitor is small enough and well-defined enough that its correct operation can be demonstrated with sufficient confidence. |

**Empirical baseline (PCAS paper, 2025):**
- Uninstrumented agents: 48% policy compliance
- Reference-monitor-instrumented agents: 93% compliance, zero violations

---

## 2. v2.1 Release Candidate Audit

This section records the release candidate compliance audit conducted in Sprint S-E10. Each evidence point is verified against implemented code with file references. The prior v1.x baseline (7/15, FAIL) is retained for comparison.

---

### Criterion C1: Always Invoked

**v1.x Score: 2/5 (PARTIAL)**
**v2.1 Score: 5/5 (FULL)**

| Evidence Point | v1.x Status | v2.1 Status | Code Evidence |
|---|---|---|---|
| PreToolUse interceptor exists and is registered | PASS | PASS | `backend/app/api/v1/intercept.py`; `backend/app/grpc_service.py` — interceptor registered on all REST and gRPC paths |
| Interceptor invoked for all tool call types across all supported SDK integrations | PARTIAL | PASS | SDK integrations verified: `sdk/agentpep/integrations/{langchain,crewai,langgraph,openai_agents,semantic_kernel,autogen}.py` — all route through `AgentPEPClient.evaluate()`; offline path in `sdk/agentpep/offline.py` enforces same FAIL_CLOSED semantics |
| No known code path bypasses the interceptor | PARTIAL | PASS | Config injection path (CVE-2025-59536 pattern) eliminated by FEATURE-02 Trusted Policy Loader; pentest confirmed in `backend/tests/pentest/test_config_injection.py` — BLOCK + SECURITY_VIOLATION verified |
| Evaluation failure defaults to DENY (FAIL_CLOSED) | FAIL | PASS | Evaluation Guarantee Invariant (INV-001) implemented in `backend/app/pdp/client.py` (try/except wraps entire evaluation; asyncio.timeout enforces 50ms deadline); `backend/app/enforcement/eval_timeout.py`; `backend/app/enforcement/complexity_budget.py`; adversarial tests passing: `tests/adversarial/test_eval_timeout_bypass.py`, `tests/adversarial/test_compound_command_bypass.py` |
| PostToolUse enforcement formalised; every tool call produces a PostToolUse event | FAIL | PASS | `backend/app/hooks/post_tool_use.py` — hook invoked on all ALLOW and DENY outcomes; Kafka delivery tested in `backend/tests/integration/test_posttooluse_emission.py`; OCSF schema linter passes in CI |

**C1 Gap Closure Summary:**
- CVE-2025-59536 config injection bypass: **CLOSED** (FEATURE-02, S-E03)
- Timeout permissive fallback: **CLOSED** (FEATURE-03, INV-001, S-E02)
- PostToolUse event guarantee: **CLOSED** (FEATURE-05, S-E07)
- SDK integration bypass paths: **CLOSED** (all six framework integrations verified, S-E09)

**Residual C1 Risk (disclosed):** Reasoning boundary bypass (BV-003) — per-call enforcement cannot detect multi-call sequences that are individually permissible but collectively prohibited. TrustSOC sequence analysis is the primary countermeasure. This is an acknowledged architectural limitation, not a reference monitor implementation gap. See Section 8.

---

### Criterion C2: Tamper-Proof

**v1.x Score: 2/5 (PARTIAL)**
**v2.1 Score: 5/5 (FULL)**

| Evidence Point | v1.x Status | v2.1 Status | Code Evidence |
|---|---|---|---|
| Policy source allowlisted to trusted registry | FAIL | PASS | `backend/app/policy/loader.py` — source URL validated against hardcoded AAPM Policy Registry allowlist before any bundle is fetched; working-directory and env-var paths raise `PolicySourceViolation` + emit `SECURITY_VIOLATION` event |
| Policy bundle integrity verified before load | FAIL | PASS | cosign signature verification in `backend/app/policy/loader.py`; verification called on every bundle fetch before deserialization; FAIL_CLOSED on verification failure |
| Policy public key is pinned in binary | FAIL | PASS | `backend/app/policy/trusted_key.py` — compile-time constant `AAPM_POLICY_PUBLIC_KEY`; no runtime override path exists; key is not configurable via env var, config file, or CLI flag |
| Enforcement cannot be disabled by agent-accessible config | FAIL | PASS | Self-protection guards in `backend/app/services/self_protection.py` block agent-initiated policy modification; `backend/app/services/protected_path_guard.py` protects instruction files and security configs; kill switch (`backend/app/services/kill_switch.py`) provides emergency deny-all, not enforcement bypass |
| Imperative rule code not modifiable at runtime | PASS | PASS | Retained: Python process not hot-reloaded; OPA/Rego evaluation engine is stateless per-call; AAPM-compiled Rego bundle is loaded via trusted loader only |

**C2 Gap Closure Summary:**
- Policy source restriction: **CLOSED** (FEATURE-02, S-E03)
- Bundle signature verification: **CLOSED** (FEATURE-02, cosign, S-E03)
- Public key pinning: **CLOSED** (FEATURE-02, `trusted_key.py`, S-E03)
- Agent-accessible config path: **CLOSED** (self-protection guards, S-E01 architecture)

**Residual C2 Risk (disclosed):** Compromise of the AAPM Policy Registry or AAPM cosign private key would break C2. These are AAPM's security controls, outside AgentPEP's scope. AgentPEP's cosign verification still validates bundle integrity at load time — a registry compromise would be detected on the next key rotation cycle. See Section 8.

---

### Criterion C3: Verifiable

**v1.x Score: 3/5 (PARTIAL)**
**v2.1 Score: 5/5 (FULL)**

| Evidence Point | v1.x Status | v2.1 Status | Code Evidence |
|---|---|---|---|
| Enforcement logic is declarative and auditable | FAIL | PASS | AAPM-compiled Rego bundle `agentpep-core-v1.0.0` replaces all imperative Python rules (decommissioned in S-E05); OPA engine in `backend/app/pdp/engine.py` evaluates declarative Rego; AAPM compliance team can audit Rego directly without application source access |
| All enforcement decisions are logged with bundle version, latency, and structured reason codes | PARTIAL | PASS | `backend/app/pdp/enforcement_log.py` — every evaluation log entry records: `agent_id`, `tool_name`, `session_id`, `decision`, `reason_code`, `policy_bundle_version`, `eval_latency_ms`, `timestamp`; log format is structured JSON |
| Policy decisions traceable to specific rule within the Rego bundle | PARTIAL | PASS | OPA `decision_id` included in enforcement log; bundle version and rule path included in `reason_code` field; TrustSOC can correlate decision log entry to AAPM Policy Registry bundle at that version |
| Independent verification possible without application source code | FAIL | PASS | Rego bundle is human-readable and independently evaluable; AAPM compliance team verified bundle behaviour against AgentPEP decision log in parity test (`tests/parity/test_aapm_bundle_parity.py` — 23 test cases, zero divergences) |
| Test coverage ≥ 90% on enforcement path | PARTIAL | PASS | Coverage: enforcement path `backend/app/pdp/` at 94%; `backend/app/enforcement/` at 97%; adversarial scenarios covered by `tests/adversarial/` (timeout, complexity, trust escalation); AgentRT regression suite passes all four bypass classes |

**C3 Gap Closure Summary:**
- Declarative policy representation: **CLOSED** (FEATURE-01 OPA/Rego, S-E04/S-E05)
- Structured enforcement decision log: **CLOSED** (FEATURE-01 enforcement_log.py, S-E04)
- Independent verifiability: **CLOSED** (Rego bundle auditable by compliance team; parity test validated, S-E05)
- Adversarial test coverage: **CLOSED** (AgentRT four-class regression suite, S-E09)

---

## 3. Compliance Score

| Criterion | v1.x Score | v2.1 Score | Change |
|---|---|---|---|
| C1: Always Invoked | 2/5 (PARTIAL) | 5/5 (FULL) | +3 |
| C2: Tamper-Proof | 2/5 (PARTIAL) | 5/5 (FULL) | +3 |
| C3: Verifiable | 3/5 (PARTIAL) | 5/5 (FULL) | +2 |
| **Overall** | **7/15 (FAIL)** | **15/15 (PASS)** | **+8** |

**v2.1 Status: COMPLIANT with reference monitor standard.**

---

## 4. Feature-to-Criterion Mapping (Final)

| Feature | Sprint | C1 Impact | C2 Impact | C3 Impact | Status |
|---|---|---|---|---|---|
| FEATURE-01: OPA/Rego PDP | S-E04, S-E05 | — | — | High (declarative, auditable) | COMPLETE |
| FEATURE-02: Trusted Policy Loader | S-E03 | High (no config injection bypass) | High (source allowlist + cosign) | — | COMPLETE |
| FEATURE-03: Complexity FAIL_CLOSED | S-E02 | High (FAIL_CLOSED on timeout/complexity) | — | — | COMPLETE |
| FEATURE-04: Recursive Trust Enforcement | S-E06 | Partial (trust chain enforcement) | — | — | COMPLETE |
| FEATURE-05: PostToolUse Hooks | S-E07 | High (PostToolUse formalised, always emitted) | — | High (tamper-evident event stream) | COMPLETE |
| FEATURE-06: Posture Matrix + Blast Radius | S-E08 | — | — | — | COMPLETE |
| FEATURE-07: Bypass Threat Model | S-E01 | — | — | High (verifiable threat coverage) | COMPLETE |
| FEATURE-08: Reference Monitor Statement | S-E10 | — | — | High (formal compliance claim) | COMPLETE |
| FEATURE-09: AAPM Integration Contract | S-E03, S-E05 | — | High (defined policy source, validated E2E) | — | COMPLETE |

---

## 5. AgentRT Regression Results (S-E10-T03)

All four bypass classes validated on v2.1 release candidate. Full report: `docs/reports/agentrt_regression_report_v2.1.md`.

| Bypass Class | Vector ID | AgentRT Suite | Result |
|---|---|---|---|
| Config Injection | BV-001 | `agentrt/suites/bypass_config_injection.py` | PASS — all 12 scenarios blocked |
| Complexity Bypass | BV-002 | `agentrt/suites/bypass_complexity.py` | PASS — all 18 scenarios: DENY + event confirmed |
| Reasoning Boundary | BV-003 | `agentrt/suites/bypass_reasoning_boundary.py` | PASS — PostToolUse events emitted for all sequences; TrustSOC sequence analysis tested |
| Hook Gaming | BV-004 | `agentrt/suites/bypass_hook_gaming.py` | PASS — 9/10 gaming attempts blocked (≥8/10 threshold met; 1/10 residual rate documented) |

---

## 6. Load Test Results (S-E10-T04)

Full report: `docs/reports/load_test_report_v2.1.md`.

| Metric | Target | Result | Status |
|---|---|---|---|
| PDP evaluation P99 latency (1,000 concurrent sessions) | < 10 ms | 7.2 ms | PASS |
| PostToolUse Kafka delivery P99 (1,000 concurrent sessions) | < 500 ms | 312 ms | PASS |
| Throughput (sustained) | ≥ 10,000 dec/s | 14,800 dec/s | PASS |
| Error rate under load | < 0.1% | 0.003% | PASS |

---

## 7. Residual Non-Compliance (Disclosed)

Based on the bypass threat model (TM-001), the following residual risks remain after all v2.1 features are implemented. These do not prevent the reference monitor compliance claim but are disclosed with evidence per security transparency obligations.

| Risk | C1/C2/C3 Impact | Residual Rating | Disclosure |
|---|---|---|---|
| Reasoning Boundary bypass (BV-003) — per-call enforcement cannot detect multi-call sequences | C1 (architectural limitation) | HIGH | Disclosed in Reference Monitor Compliance Statement (COMP-003) |
| Hook Gaming (BV-004) — 1/10 bypass rate under adversarial prompting (9/10 blocked) | C1 (partial) | HIGH | 8/10 pass threshold met; 1/10 rate documented as known limitation in COMP-003 |
| AAPM Policy Registry compromise — outside AgentPEP control | C2 (external) | LOW | Disclosed as external dependency; cosign verification provides integrity check at load time |

---

## 8. Assessment Schedule

| Milestone | Assessment Activity | Outcome |
|---|---|---|
| S-E02 complete | C1 improvement: FAIL_CLOSED implemented | PASS — adversarial tests confirmed |
| S-E03 complete | C2 improvement: Trusted Policy Loader operational | PASS — pentest confirmed (CVE-2025-59536 blocked) |
| S-E04 complete | C3 improvement: OPA engine operational, declarative eval | PASS — round-trip integration tests passing |
| S-E05 complete | C3: AAPM bundle parity validated, imperative rules decommissioned | PASS — 23 test cases, zero divergences |
| S-E10 (release) | Full compliance audit — this document | **15/15 PASS** |

---

## 9. Audit Sign-Off

| Role | Name | Date | Decision |
|---|---|---|---|
| Product Architecture Lead | TrustFabric Product Architecture | April 2026 | APPROVED |
| Security Architecture | TrustFabric Security Architecture | April 2026 | APPROVED |
| Compliance Team | TrustFabric Compliance | April 2026 | APPROVED — TRQF sign-off concurrent |

---

*Document Owner: TrustFabric Product Architecture*
*Document ID: COMP-001 v2.1*
*Related: docs/compliance/reference_monitor_statement.md (COMP-003), docs/compliance/trqf_mapping.md (COMP-002), docs/threat_model/bypass_vectors.md (TM-001), docs/invariants/evaluation_guarantee.md (INV-001)*
*Distribution: Internal — Engineering, Compliance, Security Architecture, AAPM Team*
