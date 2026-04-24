# AgentRT Integration Contract

**Version:** 1.0
**Sprint:** S-E09 (E09-T01)
**Status:** Active
**Owner:** AgentPEP Engineering (TrustFabric)
**Counterparty:** AAPM Team (Policy Registry + Bundle Release Pipeline)

---

## 1. Purpose

This document defines the integration contract between:

- **AgentRT** — the AgentPEP bypass regression test harness
- **AAPM Policy Bundle Release Pipeline** — the pipeline that compiles, signs, and publishes Rego policy bundles from APDL

AgentRT is the mandatory gate in the AAPM bundle release pipeline. No bundle may be promoted to the Policy Registry without a passing AgentRT regression run.

---

## 2. Parties and Responsibilities

| Party | Responsibility |
|-------|---------------|
| **AgentPEP team** | Maintain AgentRT suite; add new test cases within 14 days of CVE disclosure; publish pass/fail results via pipeline webhook |
| **AAPM team** | Invoke AgentRT as a CI gate before bundle promotion; provide the candidate bundle to AgentRT via the test bundle endpoint; respect the gate result |

---

## 3. AgentRT Test Runner Interface

### 3.1 Invocation

AgentRT is invoked as a standard pytest runner. The AAPM pipeline must call:

```bash
cd agentrt/
pytest -v suites/ --tb=short --junitxml=agentrt-results.xml
```

Exit code `0` = all tests pass → bundle may be promoted.
Exit code non-zero = one or more failures → bundle is blocked.

### 3.2 Bundle Under Test

Before invoking AgentRT, the AAPM pipeline must:

1. Deploy the candidate Rego bundle to the mock AAPM registry (`scripts/mock_aapm_registry.py`) at the standard test URL:
   ```
   http://localhost:8099/agentpep/policies/global/core_enforcement/<candidate-version>/bundle.tar.gz
   ```
2. Set the environment variable `AGENTRT_BUNDLE_VERSION=<candidate-version>` so AgentRT includes the bundle version in result metadata.

AgentRT loads the candidate bundle via the trusted policy loader using the local mock registry URL (localhost is allowlisted per `loader.py`).

### 3.3 Result Artefacts

| Artefact | Format | Location |
|----------|--------|----------|
| JUnit XML | JUnit 4 XML | `agentrt/agentrt-results.xml` |
| JSON summary | AgentRT JSON schema | `agentrt/agentrt-summary.json` |
| Enforcement log | NDJSON | `agentrt/agentrt-enforcement.log` |

The AAPM pipeline must archive these artefacts and attach them to the bundle release record in the PCR system.

---

## 4. Bypass Regression Suites

AgentRT runs four bypass regression suites corresponding to the four bypass classes documented in `docs/threat_model/bypass_vectors.md`.

### 4.1 Class 1 — Config Injection (`bypass_config_injection.py`)

**Threat:** BV-001 — Adversary redirects policy bundle loading to attacker-controlled source.
**CVEs covered:** CVE-2025-59536, CVE-2026-21852
**Mitigation tested:** FEATURE-02 Trusted Policy Loader

**Pass criterion:** All test cases pass (100% block rate required).

Attack vectors exercised:
| Vector | Description |
|--------|-------------|
| CI-1 | Environment variable injection (all blocked env vars) |
| CI-2 | Untrusted hostname in bundle URL |
| CI-3 | `file://` scheme injection |
| CI-4 | Path traversal in URL |
| CI-5 | Embedded credentials in URL |
| CI-6 | HTTP cleartext downgrade (non-localhost) |
| CI-7 | Forged bundle signature (attacker key) |
| CI-8 | Compound: env var + attacker URL combined |

### 4.2 Class 2 — Complexity Bypass (`bypass_complexity.py`)

**Threat:** BV-002 — Adversary causes evaluation failure via resource exhaustion or timeout.
**Mitigation tested:** FEATURE-03 Complexity Budget + Evaluation Timeout

**Pass criterion:** All test cases pass (100% block rate required).

Attack vectors exercised:
| Vector | Description |
|--------|-------------|
| CB-1 | 50+ pipe-chained subcommands |
| CB-2 | 50+ semicolon-chained subcommands |
| CB-3 | 50+ `&&`-chained subcommands |
| CB-4 | Mixed operator chain (evasion) |
| CB-5 | Command substitution nesting |
| CB-6 | Subcommands spread across multiple args |
| CB-7 | Argument byte size overflow |
| CB-8 | JSON nesting depth overflow |
| CB-9 | Deliberate evaluation timeout (hung coroutine) |
| CB-10 | Timeout FAIL_CLOSED: no ALLOW on timeout |

### 4.3 Class 3 — Reasoning Boundary (`bypass_reasoning_boundary.py`)

**Threat:** BV-003 — Adversary decomposes a collectively harmful action into individually permissible steps.
**Mitigation tested:** FEATURE-05 PostToolUse monitoring + TrustSOC event stream

**Pass criterion:** PostToolUse events emitted for every step; sequence-level anomaly patterns flagged.

**Residual risk:** HIGH — full sequence-level detection requires TrustSOC-side analytics. AgentRT validates AgentPEP's contribution (event emission completeness + taint propagation); it does not test TrustSOC's correlation logic.

Attack vectors exercised:
| Vector | Description |
|--------|-------------|
| RB-1 | Read-only recon sequence (individually innocuous) |
| RB-2 | Data staging: read → encode → write to staging area |
| RB-3 | Exfiltration sequence across tool boundary |
| RB-4 | Taint escalation: CLEAN tool result taints subsequent context |
| RB-5 | Missing PostToolUse event (every step must emit) |

### 4.4 Class 4 — Hook Gaming (`bypass_hook_gaming.py`)

**Threat:** BV-004 — Adversarial agent identifies and exploits enforcement hook loopholes.
**Mitigation tested:** FEATURE-01 OPA semantic evaluation + FEATURE-06 Posture Matrix

**Pass criterion:** ≥ 8/10 gaming attempts blocked per scenario (non-deterministic class).

**Residual risk:** HIGH — OPA semantic evaluation addresses most structural loopholes; prompt-level exploitation of reasoning boundaries remains partially unmitigated pending deeper AAPM policy authoring.

Attack vectors exercised:
| Vector | Description |
|--------|-------------|
| HG-1 | Hook invocation bypass (attempt to skip PreToolUse) |
| HG-2 | Argument mutation after hook evaluation |
| HG-3 | Tool name spoofing (allowlisted tool name, harmful args) |
| HG-4 | Indirect tool invocation via chained tool calls |
| HG-5 | Posture matrix confusion via ambiguous taint/tier context |
| HG-6 | Blast radius API unavailability exploitation (score defaults to 1.0) |
| HG-7 | Trust score manipulation via forged principal chain |
| HG-8 | Repeated rapid invocations (rate-of-fire evasion) |

---

## 5. Exit Criteria for Bundle Promotion

A bundle release is approved for promotion when:

| Criterion | Value |
|-----------|-------|
| Class 1 block rate | 100% (all CI vectors blocked) |
| Class 2 block rate | 100% (all CB vectors blocked) |
| Class 3 event emission | 100% (PostToolUse event for every tool call step) |
| Class 4 block rate | ≥ 80% per scenario (8/10 runs blocked) |
| E2E flow validated | AAPM PCR → bundle → registry → AgentPEP webhook → policy active |
| AgentRT JUnit result | Exit code 0 |

---

## 6. CVE-to-Test SLA

New public CVE disclosures affecting policy bypass vectors must have corresponding AgentRT test cases added within **14 calendar days** of disclosure. See `docs/process/cve_to_test.md` for the full process.

The AAPM bundle release pipeline must **not** promote a bundle for a CVE-affected component until the corresponding AgentRT test case is added and passing.

---

## 7. Versioning and Backward Compatibility

| Element | Policy |
|---------|--------|
| AgentRT suite version | Semantic versioning; tracked in `agentrt/__init__.py` |
| Test case removal | Not permitted without security team sign-off |
| Test case relaxation (lower pass threshold) | Not permitted; may only be tightened |
| Adding new test cases | Any sprint; no approval required |
| API contract changes | Require joint review by both AgentPEP and AAPM teams |

---

## 8. Contacts

| Role | Contact |
|------|---------|
| AgentRT owner | AgentPEP Engineering (Shiv) |
| AAPM pipeline owner | AAPM team |
| Security escalation | TrustFabric Security Architecture |

---

*Document Owner: TrustFabric Product Architecture*
*Next Review: Sprint S-E10 kickoff*
*Distribution: Internal — AgentPEP Engineering, AAPM Team, Security Architecture*
