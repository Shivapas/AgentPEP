# Reference Monitor Compliance — Current-State Assessment

**Document ID:** COMP-001
**Status:** Draft — S-E01 deliverable
**Sprint:** S-E01 (E01-T04)
**Owner:** TrustFabric Product Architecture
**Assessment Date:** April 2026
**Next Assessment:** Sprint S-E10 (release candidate audit)

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

AgentPEP's target is to satisfy all three criteria by v2.1 (Sprint S-E10).

---

## 2. Current-State Assessment (AgentPEP v1.x)

### Criterion C1: Always Invoked

**Score: PARTIAL — 2/5**

| Evidence Point | Status | Gap |
|---|---|---|
| PreToolUse interceptor exists and is registered | PASS | — |
| Interceptor is invoked for all tool call types | PARTIAL | Some SDK integrations may bypass interceptor via direct tool invocation; framework-specific registration required |
| No known code path bypasses the interceptor | PARTIAL | Working-directory policy override (CVE-2025-59536 pattern) can silently replace enforcement rules, functionally bypassing the monitor |
| Evaluation failure defaults to DENY (FAIL_CLOSED) | FAIL | Current code has permissive fallback paths on timeout and exception (complexity bypass exploits this) |
| PostToolUse enforcement exists | FAIL | PostToolUse is not formalised; no guarantee every tool call produces a PostToolUse event |

**Gap:** The evaluation failure path (FAIL_CLOSED requirement) is the critical gap. An adversary can trigger a permissive outcome by causing evaluation timeout or exception. This is the primary reference monitor compliance failure in v1.x.

### Criterion C2: Tamper-Proof

**Score: PARTIAL — 2/5**

| Evidence Point | Status | Gap |
|---|---|---|
| Policy source allowlisted to trusted registry | FAIL | Policy can be loaded from working directory, environment variable, or CLI flag |
| Policy bundle integrity verified before load | FAIL | No cosign signature verification on loaded policies |
| Policy public key is pinned in binary | FAIL | No key pinning; key (if any) is runtime-configurable |
| Enforcement cannot be disabled by agent-accessible config | FAIL | Agent-writable env vars and config files can modify enforcement behaviour |
| Imperative rule code not modifiable at runtime | PASS | Python code is not hot-reloaded; requires process restart |

**Gap:** The policy loading path is the primary tamper vector. An attacker with write access to the agent's environment (working directory, environment variables) can inject a permissive policy. CVE-2025-59536 directly exploits this gap.

### Criterion C3: Verifiable

**Score: PARTIAL — 3/5**

| Evidence Point | Status | Gap |
|---|---|---|
| Enforcement logic is declarative and auditable | FAIL | Policy expressed as imperative Python code; requires code-level audit |
| All enforcement decisions are logged | PARTIAL | Audit log exists but does not record bundle version, evaluation latency, or structured reason codes |
| Policy decisions traceable to specific rule | PARTIAL | Rule matching logged informally; no structured rule ID in decision log |
| Independent verification possible | FAIL | Imperative code requires reviewer to trace execution logic; not independently auditable |
| Test coverage ≥ 90% on enforcement path | PARTIAL | Coverage exists but adversarial scenarios (timeout, exception, complexity) are not systematically tested |

**Gap:** The imperative policy representation makes independent verification impractical. A declarative OPA/Rego engine with structured decision logs is required for C3 compliance.

---

## 3. Overall Compliance Score

| Criterion | v1.x Score | v2.1 Target |
|---|---|---|
| C1: Always Invoked | 2/5 (PARTIAL) | 5/5 (FULL) |
| C2: Tamper-Proof | 2/5 (PARTIAL) | 5/5 (FULL) |
| C3: Verifiable | 3/5 (PARTIAL) | 5/5 (FULL) |
| **Overall** | **7/15 (FAIL)** | **15/15 (PASS)** |

**Current Status: NON-COMPLIANT with reference monitor standard.**

---

## 4. Feature-to-Criterion Mapping

| Feature | Sprint | C1 Impact | C2 Impact | C3 Impact |
|---|---|---|---|---|
| FEATURE-01: OPA/Rego PDP | S-E04 | — | — | High (declarative, auditable) |
| FEATURE-02: Trusted Policy Loader | S-E03 | Partial (no bypass via config inject) | High (source allowlist + cosign) | — |
| FEATURE-03: Complexity FAIL_CLOSED | S-E02 | High (FAIL_CLOSED on timeout/complexity) | — | — |
| FEATURE-04: Recursive Trust Enforcement | S-E06 | Partial (trust chain enforcement) | — | — |
| FEATURE-05: PostToolUse Hooks | S-E07 | High (PostToolUse formalised, always emitted) | — | High (event stream for audit) |
| FEATURE-06: Posture Matrix + Blast Radius | S-E08 | — | — | — |
| FEATURE-07: Bypass Threat Model | S-E01 | — | — | High (verifiable threat coverage) |
| FEATURE-08: Reference Monitor Statement | S-E10 | — | — | High (formal compliance claim) |
| FEATURE-09: AAPM Integration Contract | S-E03 | — | High (defined policy source) | — |

---

## 5. Critical Path to C1 Compliance

**The Evaluation Guarantee Invariant (INV-001) is the single most important change for C1 compliance.**

Current state: Evaluation failure (timeout, exception) → permissive fallback → C1 violated.
Required state: Evaluation failure → DENY → C1 maintained even under adversarial conditions.

Implementation: FEATURE-03 (Sprint S-E02). The invariant is defined in `docs/invariants/evaluation_guarantee.md`.

---

## 6. Critical Path to C2 Compliance

**FEATURE-02 (Trusted Policy Loader) is the critical path item for C2 compliance.**

Current state: Policy loadable from working directory or env var → attacker can replace policy → C2 violated.
Required state: Policy loadable only from AAPM Policy Registry with cosign verification → no agent-accessible path to modify enforcement.

Implementation: FEATURE-02 (Sprint S-E03).

---

## 7. Critical Path to C3 Compliance

**FEATURE-01 (OPA/Rego PDP) is the critical path item for C3 compliance.**

Current state: Imperative Python rules → no independent verifiability → C3 violated.
Required state: Declarative Rego policies evaluated by OPA engine + structured enforcement decision log with bundle version → independently verifiable.

Implementation: FEATURE-01 (Sprint S-E04) + FEATURE-05 (Sprint S-E07).

---

## 8. Residual Non-Compliance after v2.1

Based on the bypass threat model (TM-001), the following residual risks remain after all v2.1 features are implemented:

| Risk | C1/C2/C3 Impact | Disclosure Required |
|---|---|---|
| Reasoning Boundary bypass (BV-003) — per-call enforcement cannot detect multi-call sequences | C1 (partial) | Yes — in Reference Monitor Compliance Statement |
| Hook Gaming (BV-004) — 2/10 bypass rate under adversarial prompting | C1 (partial) | Yes — 8/10 pass threshold documented |

These residual risks do not prevent the reference monitor compliance claim but must be disclosed with evidence in the compliance statement (S-E10-T02).

---

## 9. Assessment Schedule

| Milestone | Assessment Activity | Target Date |
|---|---|---|
| S-E02 complete | Verify C1 improvement: FAIL_CLOSED implemented | After Sprint S-E02 |
| S-E03 complete | Verify C2 improvement: Trusted Policy Loader operational | After Sprint S-E03 |
| S-E04 complete | Verify C3 improvement: OPA engine operational, declarative eval | After Sprint S-E04 |
| S-E10 (release) | Full compliance audit with code-level evidence | Q3 2026 |

---

*Document Owner: TrustFabric Product Architecture*
*Related: docs/invariants/evaluation_guarantee.md, docs/threat_model/bypass_vectors.md, docs/compliance/trqf_mapping.md*
