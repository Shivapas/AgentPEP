# AgentPEP Imperative Enforcement Rule Inventory

**Sprint S-E05 — E05-T01**
**Owner:** TrustFabric Platform Engineering
**Status:** Delivered to AAPM team for APDL authoring
**Date:** April 2026

---

## Purpose

This document inventories all existing AgentPEP imperative enforcement rules
as input to the AAPM team's APDL authoring work.  For each rule class, the
table records:

- The enforcement check performed
- The condition that triggers DENY / ESCALATE / MODIFY
- The current implementation location
- The OPA input fields required to replicate the rule in Rego / APDL

AAPM should translate these rules to APDL in the order listed.  Section 7
(OPA Engine Stub) must be superseded first — it is the blocking dependency for
the S-E05 parity test.

---

## Rule Class Overview

| Class | Rule Count | Bypass Class Mitigated | Current Location |
|-------|-----------|------------------------|------------------|
| 1. Kill Switch | 1 | Hook Gaming | `app/services/kill_switch.py` |
| 2. Complexity Budget Gate | 3 + timeout | Complexity Bypass | `app/enforcement/complexity_budget.py` |
| 3. Protected Path Guard | N patterns | Reasoning Boundary | `app/services/protected_path_guard.py` |
| 4. Session-level Checks | 4 | Hook Gaming | `app/services/mission_plan_service.py` |
| 5. Rate Limiting | 2 | Resource Exhaustion | `app/services/rate_limiter.py` |
| 6. Content Scanning | 2 | Reasoning Boundary | `app/services/network_dlp_scanner.py`, `app/services/scan_mode_router.py` |
| 7. Trust Validation | 3 | Config Injection | `app/services/confused_deputy.py`, `app/services/trust_degradation_engine.py` |
| 8. Core RBAC Rule Matching | Variable | All classes | `app/services/rule_matcher.py` |
| 9. OPA Engine Stub | 3 | Config Injection, Complexity | `app/pdp/engine.py` (`RegoNativeEvaluator`) |

---

## Class 1: Kill Switch

**Description:** Global emergency deny-all, activated by a privileged operator
command.  When active, every tool call request is denied regardless of any
other policy rule.

**AAPM Rego / APDL equivalent:** `deny_all_active` flag in bundle data.json.

| Trigger | Decision | OPA Input Fields Required |
|---------|----------|---------------------------|
| `kill_switch_activated == true` | DENY | `kill_switch_active` (bool) |

**Current implementation:** `app/services/kill_switch.py::KillSwitchService.is_activated`

**Priority:** Include in first AAPM bundle as the deny-all mechanism used by
the emergency bundle test (E05-T08).

---

## Class 2: Complexity Budget Gate

**Description:** Pre-evaluation gate that blocks requests whose argument
structure exceeds configured limits.  Implements the Evaluation Guarantee
Invariant.  Three dimensions checked; any failure → unconditional DENY.

**AAPM Rego / APDL equivalent:** These checks must run as input validation
*before* the main policy rules.  OPA does not have a direct timeout mechanism;
the timeout guard (`EvalTimeoutGuard`) is implemented in AgentPEP's Go/Python
layer and does not need APDL translation.

| Dimension | Trigger | Decision | Config Field |
|-----------|---------|----------|--------------|
| Argument byte size | `arg_bytes > max_arg_bytes` | DENY + COMPLEXITY_EXCEEDED event | `complexity_budget_max_arg_bytes` (default 65536) |
| Subcommand count | `subcommand_count > max_subcommand_count` | DENY + COMPLEXITY_EXCEEDED event | `complexity_budget_max_subcommand_count` (default 10) |
| Nesting depth | `nesting_depth > max_nesting_depth` | DENY + COMPLEXITY_EXCEEDED event | `complexity_budget_max_nesting_depth` (default 10) |
| Eval timeout | OPA evaluation exceeds `eval_timeout_s` | DENY (FAIL_CLOSED) | `pdp_eval_timeout_s` (default 5.0 s) |

**AAPM note:** The argument metrics (byte size, subcommand count, nesting
depth) must be pre-computed by AgentPEP before the OPA evaluation and passed
as fields in the OPA `input` document.  AAPM Rego rules should read these
pre-computed values; they should not attempt to re-compute them from
`input.tool_args`.

**OPA input fields required:**
```json
{
  "tool_args_byte_size": 4096,
  "tool_args_subcommand_count": 2,
  "tool_args_nesting_depth": 3,
  "complexity_budget_max_arg_bytes": 65536,
  "complexity_budget_max_subcommand_count": 10,
  "complexity_budget_max_nesting_depth": 10
}
```

**Current implementation:** `app/enforcement/complexity_budget.py`

---

## Class 3: Protected Path Guard

**Description:** Blocks agent operations on security-critical file paths
(e.g., AgentPEP config files, SSH keys, `/etc/shadow`).  Checked before
RBAC rule matching.

**AAPM Rego / APDL equivalent:** Path pattern matching rule.  Patterns are
operator-configurable and should be sourced from bundle data.json.

| Trigger | Decision | OPA Input Fields Required |
|---------|----------|---------------------------|
| `path` matches a protected pattern AND operation is write/delete/modify | DENY | `tool_args.path`, `operation_type` ("read"\|"write"\|"delete"\|"modify") |

**Pattern examples:**
```
/etc/agentpep/**
~/.ssh/**
**/.env
**/agentpep/config/**
```

**Current implementation:** `app/services/protected_path_guard.py`

---

## Class 4: Session-level Plan Constraints

**Description:** When a Mission Plan is bound to a session, tool calls must
satisfy the plan's scope, delegation, and budget constraints before reaching
RBAC evaluation.  Evaluated in priority order.

**AAPM Rego / APDL equivalent:** Plan-scoped rules in a separate package
(`agentpep.plan`), keyed by `plan_id`.

| Sub-check | Trigger | Decision | OPA Input Fields Required |
|-----------|---------|----------|---------------------------|
| Checkpoint Filter | Tool matches `requires_checkpoint` pattern AND no prior approval | ESCALATE | `tool_name`, `plan.requires_checkpoint[]`, `has_checkpoint_approval` |
| Budget Gate | Plan expired OR delegation count > `max_delegations` | DENY | `plan.max_delegations`, `plan.delegation_count`, `plan.expires_at` |
| Delegates Filter | `agent_id` not in `plan.delegates_to` (glob-aware) | DENY | `agent_id`, `plan.delegates_to[]` |
| Scope Filter | Tool not in `plan.allowed_tools` | DENY | `tool_name`, `plan.allowed_tools[]` |

**Current implementation:** `app/services/scope_filter.py`, `app/services/plan_budget_gate.py`

---

## Class 5: Rate Limiting

**Description:** Two-tier rate limiting: global per-tenant ceiling and
per-rule per-role limits.  Both use sliding or fixed windows.

**AAPM Rego / APDL equivalent:** Rate limit data should be in bundle
data.json; AgentPEP maintains the sliding window counters externally (Redis)
and passes the current count as an OPA input field.

| Check | Trigger | Decision | OPA Input Fields Required |
|-------|---------|----------|---------------------------|
| Global tenant rate limit | Tenant request rate exceeds global ceiling | DENY | `tenant_request_count`, `tenant_rate_limit_ceiling` |
| Per-rule rate limit | Agent-role-tool rate exceeds rule limit | DENY | `rule_request_count`, `rule.rate_limit.max_calls`, `rule.rate_limit.window_s` |

**Current implementation:** `app/services/rate_limiter.py`

---

## Class 6: Content Scanning

**Description:** Two scanning stages run on `tool_args` values before core
access control.

### 6a. DLP Pre-scan (Network DLP)

Detects API keys, tokens, credentials, PII, and financial data in tool
arguments.  CRITICAL/HIGH severity findings → ESCALATE.

| Trigger | Decision | OPA Input Fields Required |
|---------|----------|---------------------------|
| Credential found in `tool_args` (severity CRITICAL or HIGH) | ESCALATE | `dlp_max_severity` ("CRITICAL"\|"HIGH"\|"MEDIUM"\|"LOW"\|"NONE") |

**Current implementation:** `app/services/network_dlp_scanner.py`

### 6b. CIS Injection Pre-scan

Detects injection patterns (prompt injection, command injection, etc.) in
concatenated tool argument values.  CRITICAL/HIGH findings → ESCALATE.

| Trigger | Decision | OPA Input Fields Required |
|---------|----------|---------------------------|
| Injection signature matched (severity CRITICAL or HIGH) | ESCALATE | `cis_max_severity`, `cis_matched_categories[]` |

**Current implementation:** `app/services/scan_mode_router.py`

---

## Class 7: Trust Validation

### 7a. Confused-deputy Check

Validates delegation chains: depth limits, legitimate delegation patterns,
implicit delegation detection.

| Trigger | Decision | OPA Input Fields Required |
|---------|----------|---------------------------|
| Delegation depth > `max_delegation_depth` | DENY | `delegation_hops`, `max_delegation_depth` (default 5) |
| Implicit delegation detected (agent acts beyond its grant) | ESCALATE | `principal_chain`, `granted_permissions[]` |

**Current implementation:** `app/services/confused_deputy.py`

### 7b. Context Authority Check

Blocks privileged tool decisions when session context is majority-untrusted.

| Trigger | Decision | OPA Input Fields Required |
|---------|----------|---------------------------|
| `untrusted_context_ratio > 0.5` AND tool requires taint-check | ESCALATE | `untrusted_context_ratio`, `rule.taint_check` |

**Current implementation:** `app/services/context_authority.py`

### 7c. Trust Degradation Engine

Locks sessions whose trust ceiling has fallen below the floor threshold.

| Trigger | Decision | OPA Input Fields Required |
|---------|----------|---------------------------|
| `session.trust_ceiling < floor` | DENY (locked) or DEFER | `session_trust_ceiling`, `session_trust_locked` |

**Current implementation:** `app/services/trust_degradation_engine.py`

---

## Class 8: Core RBAC Rule Matching

**Description:** First-match, priority-ordered evaluation of operator-defined
rules stored in MongoDB.  Each rule specifies a target agent role, a tool
pattern (glob or regex), and an action.

**AAPM Rego / APDL equivalent:** Rules should be stored in bundle data.json
as a sorted list and evaluated with first-match semantics.  The `rule_id`
of the matched rule must appear in the enforcement decision log.

### 8a. Role + Tool Pattern Matching

| Condition | Behaviour |
|-----------|-----------|
| Agent role in `rule.agent_role` (or `"*"`) AND tool matches `rule.tool_pattern` | First-match; fall through if no match |
| No matching rule | DENY (deny-by-default) |

**OPA input fields:**
```json
{
  "agent_roles": ["analyst", "reader"],
  "tool_name": "read_file",
  "tool_args": {}
}
```

### 8b. Per-rule Arg Validators

After a rule matches, validator pipeline runs on `tool_args`:

| Validator Type | Trigger | Decision |
|---------------|---------|----------|
| JSON schema | `tool_args` fails schema | DENY |
| Blocklist | `arg_value` in blocklist | DENY |
| Allowlist | `arg_value` not in allowlist | DENY |
| Regex | `arg_value` does not match pattern | DENY |

### 8c. Taint Check

Run when `rule.taint_check == true` and request includes taint node IDs.

| Taint Level | Decision |
|-------------|----------|
| QUARANTINE (any node) | DENY |
| UNTRUSTED (any node, no QUARANTINE) | ESCALATE |
| All TRUSTED / CLEAN | Proceed with matched action |

### 8d. Risk Scoring

Risk score computed from taint flags, tool sensitivity, delegation depth, and
rule risk threshold.  Score > threshold → ESCALATE (overrides ALLOW).

| Trigger | Decision | OPA Input Fields |
|---------|----------|------------------|
| `risk_score > rule.risk_threshold` (or global `escalation_threshold`) | ESCALATE | `risk_score`, `rule.risk_threshold` |

### 8e. Step-up Auth

When `rule.step_up_auth` is set, an ALLOW would be upgraded to STEP_UP,
requiring additional authentication factors before execution proceeds.

### 8f. PII Redaction (MODIFY)

When PII is detected in `tool_args` and agent clearance is below "PII",
decision is MODIFY with redacted arguments.

---

## Class 9: OPA Engine Stub (Superceded by S-E05)

**Description:** The `RegoNativeEvaluator` in `app/pdp/engine.py` is the
Python stub implementation used in Sprint S-E04 before the real AAPM bundle
was available.  It implements a minimal rule set.

**Status: DECOMMISSIONED in Sprint S-E05** — replaced by the first
AAPM-compiled Rego bundle (`agentpep-core-v1.0.0`).

### Stub Rules (to be replicated exactly in v1 Rego bundle for parity)

| Rule | Trigger | Decision |
|------|---------|----------|
| Taint gate | `taint_level != "CLEAN"` | DENY, reason: TAINTED_INPUT |
| Trust floor | `trust_score < 0.0` (effectively unreachable) | DENY, reason: INSUFFICIENT_TRUST |
| Read-only HOMEGROWN allow | `tool_name in READ_ONLY_TOOLS AND deployment_tier == "HOMEGROWN"` | ALLOW, reason: TOOL_ALLOWED |
| Default | Everything else | DENY, reason: TOOL_NOT_PERMITTED |

**READ_ONLY_TOOLS set:**
```python
{"read_file", "list_dir", "search_code", "get_file_contents", "list_files"}
```

**OPA input fields required for parity bundle:**
```json
{
  "tool_name": "read_file",
  "deployment_tier": "HOMEGROWN",
  "taint_level": "CLEAN",
  "trust_score": 1.0
}
```

---

## Phased APDL Translation Roadmap

AAPM should translate rules in the following order to match AgentPEP sprint
dependency requirements:

| Phase | Rules | Needed By | Notes |
|-------|-------|-----------|-------|
| **Phase 1** (S-E05 blocker) | Class 9 (OPA stub) — exact parity | S-E05 parity test | Must produce identical decisions to `RegoNativeEvaluator` |
| **Phase 2** (S-E06 prep) | Class 1 (kill switch), Class 7 (trust) | S-E06 recursive trust | Trust degradation feeds into S-E06 trust score |
| **Phase 3** (S-E07 prep) | Class 2 (complexity), Class 6 (scanning) | S-E07 PostToolUse | Reason codes must match OCSF schema |
| **Phase 4** (S-E08 prep) | Class 3 (protected path), Class 5 (rate limit), Class 8 (RBAC) | S-E08 posture matrix | Full RBAC replaces MongoDB rules |

---

## OPA Input Document — Full Field Reference (PRD v2.1 §5.1)

```json
{
  "agent_id": "agent-abc123",
  "session_id": "sess-xyz789",
  "request_id": "req-00001",
  "tool_name": "read_file",
  "tool_args": { "path": "/tmp/data.json" },
  "taint_level": "CLEAN",
  "trust_score": 0.85,
  "principal_chain": ["root-agent", "sub-agent-1"],
  "deployment_tier": "ENTERPRISE",
  "blast_radius_score": 0.0,
  "bundle_version": "1.0.0",
  "timestamp_ms": 1714000000000,

  "_precomputed": {
    "tool_args_byte_size": 256,
    "tool_args_subcommand_count": 0,
    "tool_args_nesting_depth": 1,
    "dlp_max_severity": "NONE",
    "cis_max_severity": "NONE",
    "risk_score": 0.05,
    "session_trust_ceiling": 0.9,
    "session_trust_locked": false,
    "untrusted_context_ratio": 0.0
  }
}
```

---

## Delivery

This document is the AgentPEP team deliverable for E05-T01.  Handoff to AAPM
team requires:

- [ ] AAPM team confirms receipt and assigns APDL author
- [ ] Phase 1 (OPA stub parity) APDL authoring scheduled within AAPM Sprint 9
- [ ] First signed Rego bundle delivered to Policy Registry for S-E05-T03

**Questions to AAPM team:**
1. Will the bundle `data.json` carry the operator-configurable complexity
   budget thresholds, or should AgentPEP continue to read these from its own
   config?  (Recommendation: bundle data.json for consistency.)
2. Should the protected path patterns (Class 3) be in the bundle or remain
   in AgentPEP's local config?  (Recommendation: bundle for centralised
   authoring.)
3. Confirm the `reason_code` string vocabulary APDL will emit — it must
   match the `ReasonCode` enum in `app/pdp/response_parser.py`.
