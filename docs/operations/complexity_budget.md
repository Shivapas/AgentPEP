# Complexity Budget — Operator Runbook

**Sprint S-E02 — FEATURE-03**
**Owner:** TrustFabric Platform Engineering
**Linked invariant:** Evaluation Guarantee Invariant (`docs/invariants/evaluation_guarantee.md`)

---

## Overview

The Complexity Budget is a pre-evaluation gate that blocks tool calls whose
argument structure exceeds configurable limits.  It implements the
**Evaluation Guarantee Invariant**: *every tool call must be evaluable within
finite, bounded resources; if it is not, the decision is unconditionally DENY*.

There is **no permissive fallback**.  No operator configuration can produce
ALLOW on a budget exceeded or evaluation timeout.

---

## Configuration Reference

All parameters are set via environment variables prefixed `AGENTPEP_`.

| Setting | Environment Variable | Default | Description |
|---------|----------------------|---------|-------------|
| `complexity_budget_enabled` | `AGENTPEP_COMPLEXITY_BUDGET_ENABLED` | `true` | Enable/disable the complexity gate entirely |
| `complexity_budget_max_arg_bytes` | `AGENTPEP_COMPLEXITY_BUDGET_MAX_ARG_BYTES` | `65536` | Maximum serialised byte size of `tool_args` JSON (64 KB) |
| `complexity_budget_max_subcommand_count` | `AGENTPEP_COMPLEXITY_BUDGET_MAX_SUBCOMMAND_COUNT` | `10` | Maximum shell metacharacter count across all string values |
| `complexity_budget_max_nesting_depth` | `AGENTPEP_COMPLEXITY_BUDGET_MAX_NESTING_DEPTH` | `10` | Maximum dict/list nesting depth of `tool_args` |
| `complexity_budget_eval_timeout_s` | `AGENTPEP_COMPLEXITY_BUDGET_EVAL_TIMEOUT_S` | `5.0` | Hard evaluation timeout in seconds; expiry → DENY |

### Disabling the gate

Setting `AGENTPEP_COMPLEXITY_BUDGET_ENABLED=false` disables all three
dimension checks and the evaluation timeout guard.  **This is not recommended
in production** as it removes the primary mitigation for the complexity-based
bypass class.

---

## Budget Dimensions

### 1. Argument Byte Size (`max_arg_bytes`)

The gate serialises `tool_args` to compact JSON and measures the byte length.
Requests exceeding `max_arg_bytes` are denied immediately.

**Rationale:** Extremely large argument payloads can:
- Cause memory pressure during evaluation
- Slow regex-based scanners below their latency SLA
- Hide embedded payloads in fields that scanners don't fully traverse

**Tuning guidance:**
- Standard REST API payloads: 4–16 KB is typical
- File content tools (e.g., `file.write`): increase to 512 KB if needed
- Never exceed 10 MB; prefer streaming APIs for large content

### 2. Subcommand Count (`max_subcommand_count`)

The gate counts shell metacharacters (`|`, `;`, `&&`, `||`, `&`, `` ` ``,
`$()`) recursively across all string values in `tool_args`.

**Rationale:** Compound commands with many subcommands can:
- Obscure the actual operation from policy rules that match on `tool_name`
- Exhaust evaluation time via combinatorial rule expansion
- Bypass audit trails by embedding secondary commands in a single logged call

**Tuning guidance:**
- Default of 10 is permissive for legitimate use cases (most shell pipelines
  use 1–4 subcommands)
- If your agent legitimately generates complex pipelines, raise to 25 maximum
- Values above 25 should require a security review

### 3. Nesting Depth (`max_nesting_depth`)

The gate walks the `tool_args` dict/list structure and measures the maximum
nesting depth.

**Rationale:** Deeply nested structures can:
- Cause stack overflows in recursive evaluators
- Degrade JSON schema validation performance exponentially
- Hide policy-relevant values below the depth that scanners inspect

**Tuning guidance:**
- Default of 10 covers virtually all legitimate API payloads
- Structured document tools may need 15–20
- Values above 20 should require a security review

---

## Evaluation Timeout (`eval_timeout_s`)

The `EvalTimeoutGuard` wraps the full policy evaluation coroutine.  If
evaluation does not complete within `eval_timeout_s` seconds, the guard
cancels the coroutine and returns **DENY**.

This is distinct from the adaptive timeout in the main policy evaluator
(which supports `FAIL_OPEN` mode).  The complexity budget timeout is
**always FAIL_CLOSED** and cannot be overridden via operator config.

**Tuning guidance:**
- Default of 5.0 s is generous for a single policy evaluation
- Lower to 2.0 s in high-throughput production deployments
- Do not raise above 10.0 s without investigating the root cause of slow evaluations

---

## Event: `COMPLEXITY_EXCEEDED`

When any budget dimension is exceeded, a `COMPLEXITY_EXCEEDED` event is
emitted.  In Sprint S-E02 this is a **stub** — the event is logged
synchronously.  Full OCSF schema and Kafka transport are formalised in
Sprint S-E07.

### Event fields (stub schema)

```json
{
  "class_uid": 4003,
  "class_name": "COMPLEXITY_EXCEEDED",
  "category_uid": 4,
  "category_name": "FINDINGS",
  "activity_id": 2,
  "activity_name": "DENY",
  "severity_id": 3,
  "severity": "HIGH",
  "time": <epoch_ms>,
  "metadata": { "product": { "name": "AgentPEP" } },
  "actor": { "agent_id": "...", "session_id": "..." },
  "resources": [{ "type": "tool_call", "name": "<tool_name>" }],
  "finding_info": {
    "title": "Complexity budget exceeded — request denied",
    "violations": [
      { "dimension": "subcommand_count", "limit": 10, "actual": 52 }
    ]
  },
  "decision": "DENY",
  "evaluation_guarantee_invariant": true
}
```

### Searching for events

In structured logs (JSON), filter on:

```
event_class = "COMPLEXITY_EXCEEDED"
```

Or for timeout events:

```
event_class = "EVAL_TIMEOUT"
```

---

## Operational Playbook

### Alert: High volume of `COMPLEXITY_EXCEEDED` events

1. **Check agent logs** for the session IDs in the events — are these known
   agents or potentially adversarial traffic?
2. **Review `actual` vs `limit`** in the violation payload — if actual values
   are only slightly above the limit, consider raising the limit after security
   review.
3. **Check for attack patterns** — payloads with 50+ subcommands or extreme
   nesting are adversarial indicators, not legitimate use.

### Alert: `EVAL_TIMEOUT` events on fast hardware

1. **Check MongoDB latency** — slow rule fetches degrade evaluation time.
2. **Check Redis rule cache hit rate** — a cold cache increases evaluation time
   (see `evaluation_timeout_cold_s` vs `evaluation_timeout_cached_s`).
3. **Check OPA engine latency** (Sprint S-E04 onwards) — OPA evaluation
   should be sub-millisecond; P99 > 10 ms indicates a problem.

### Raising a limit

1. Open a change request documenting the legitimate use case.
2. Raise the specific limit in the deployment's environment configuration.
3. Monitor for a 48-hour window post-change — alert on any new
   `COMPLEXITY_EXCEEDED` events above the new limit.

### Emergency: disable complexity gate

If the complexity gate is causing false positives in production:

```bash
export AGENTPEP_COMPLEXITY_BUDGET_ENABLED=false
```

This disables all three dimension checks **but not** the evaluation timeout.
The evaluation timeout (`EvalTimeoutGuard`) is always active and cannot be
disabled via operator config — it is part of the Evaluation Guarantee
Invariant.

---

## Bypass Vectors Mitigated

This feature eliminates the **Complexity Bypass** class (Class 2) from the
bypass threat model.  See `docs/threat_model/bypass_vectors.md` for the full
MITRE ATLAS mapping.

| Sub-vector | Mitigation |
|------------|------------|
| Compound shell command (50+ subcommands) | `max_subcommand_count` gate |
| Oversized argument payload | `max_arg_bytes` gate |
| Deeply nested structure causing scanner degradation | `max_nesting_depth` gate |
| Hung evaluation via pathological input | `eval_timeout_s` (always FAIL_CLOSED) |

---

## Exit Criteria Checklist (Sprint S-E02)

- [x] All budget parameters implemented and tested
- [x] Timeout FAIL_CLOSED implemented and tested
- [x] Adversarial compound command test: DENY confirmed
- [x] Adversarial timeout test: DENY confirmed
- [x] No operator configuration can produce ALLOW on budget exceeded
