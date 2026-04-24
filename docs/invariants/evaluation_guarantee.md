# Evaluation Guarantee Invariant

**Design Principle ID:** INV-001
**Status:** Accepted
**Sprint:** S-E01
**Owner:** TrustFabric Product Architecture
**Date:** April 2026

---

## Statement

> **Every tool call that reaches the PreToolUse interceptor MUST receive a policy evaluation decision before any tool execution proceeds. On any failure — timeout, engine error, policy unavailability, or evaluation exception — the interceptor MUST default to DENY. There is no permissive fallback.**

This is a named, inviolable design invariant for AgentPEP v2.x and all future versions.

---

## Rationale

AgentPEP is a **reference monitor**: a tamper-proof, always-invoked enforcement layer at the AI agent tool-call boundary. The classical reference monitor definition requires three properties:

1. **Always invoked** — every access attempt passes through the monitor
2. **Tamper-proof** — the monitor itself cannot be bypassed or modified by subjects it controls
3. **Verifiable** — the monitor's correctness can be demonstrated with sufficient confidence

The Evaluation Guarantee Invariant is the mechanism that enforces the **"always invoked"** property in the presence of operational failures. Without this invariant, an adversary can construct inputs that cause the evaluation engine to time out, exhaust resources, or throw exceptions — and if those conditions result in a permissive fallback, the reference monitor property is broken.

The invariant also enforces **FAIL_CLOSED** semantics: correctness is defined as *denying access when correctness cannot be established*, not *allowing access optimistically*.

---

## Scope

This invariant applies to:

- The **PreToolUse interceptor** (primary enforcement point)
- The **OPA/Rego PDP** (policy evaluation engine, introduced in FEATURE-01)
- The **complexity budget checker** (FEATURE-03)
- The **evaluation timeout handler** (FEATURE-03)
- Any future interceptor or evaluation gate added to AgentPEP

This invariant does **not** govern:
- PostToolUse event emission (observability path, not an enforcement decision)
- AAPM policy bundle loading (governed by FEATURE-02 Trusted Policy Loader invariants)

---

## Failure Modes Covered

| Failure Mode | Without Invariant | With Invariant |
|---|---|---|
| OPA engine timeout | Risk: permissive fallback | DENY — tool call blocked |
| OPA engine internal exception | Risk: unhandled exception bypasses enforcement | DENY — tool call blocked |
| Policy bundle unavailable at eval time | Risk: evaluation skipped | DENY — tool call blocked |
| Complexity budget exceeded | Risk: partial evaluation returns permissive result | DENY — tool call blocked |
| Evaluation result malformed / unrecognisable | Risk: treated as ALLOW | DENY — tool call blocked |
| Network timeout to OPA sidecar (if sidecar mode) | Risk: request proceeds unevaluated | DENY — tool call blocked |

---

## Implementation Requirements

Any implementation that satisfies this invariant MUST:

1. Wrap the entire evaluation path in a try/except block; catch all exception types.
2. On any caught exception: log the failure, emit a `EVALUATION_FAILURE` event, and return `DENY`.
3. Implement an evaluation timeout (default: 50ms; configurable down to 10ms, not configurable above 200ms).
4. On timeout expiry: return `DENY` immediately without waiting for any partial result.
5. Never expose a configuration parameter that produces `ALLOW` on evaluation failure. The DENY-on-failure behaviour must not be operator-overridable.
6. Include the failure reason in the enforcement decision log entry.

### Pseudocode

```python
async def evaluate_with_guarantee(request: AuthzRequest) -> Decision:
    try:
        async with asyncio.timeout(EVAL_TIMEOUT_SECONDS):
            result = await pdp_client.evaluate(request)
            if not is_valid_decision(result):
                emit_event(EVALUATION_FAILURE, reason="malformed_response")
                return Decision.DENY
            return result.decision
    except asyncio.TimeoutError:
        emit_event(EVALUATION_FAILURE, reason="timeout")
        return Decision.DENY
    except Exception as exc:
        emit_event(EVALUATION_FAILURE, reason=f"exception:{type(exc).__name__}")
        return Decision.DENY
```

---

## Verification

The invariant is verified by:

1. **Unit tests** — each failure mode in the table above has a dedicated test that asserts `DENY` is returned and `EVALUATION_FAILURE` event is emitted. See `tests/test_complexity_budget.py` (S-E02) and `tests/adversarial/test_eval_timeout_bypass.py` (S-E02).
2. **Adversarial tests** — AgentRT suite includes timeout-trigger and engine-crash scenarios that verify DENY under stress.
3. **Code review gate** — any PR that introduces a permissive fallback path in the evaluation chain is rejected.
4. **Reference monitor compliance audit** — S-E10 audit verifies this invariant is met with code-level evidence.

---

## Change Control

This invariant may only be changed by:

- A named ADR approved by the Security Architecture team
- A corresponding update to `docs/compliance/reference_monitor_assessment.md`
- Notification to the AAPM team (integration contract impact assessment)

Any weakening of this invariant (introduction of a permissive fallback) constitutes a **security regression** and must be treated as a Severity 1 issue.

---

*Document Owner: TrustFabric Product Architecture*
*Related: FEATURE-03 (Complexity FAIL_CLOSED), FEATURE-01 (OPA PDP), docs/compliance/reference_monitor_assessment.md*
