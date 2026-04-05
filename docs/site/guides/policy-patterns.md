# Policy Patterns

Common policy configurations for real-world use cases.

## Pattern 1: Deny by Default with Allowlist

```json
[
  {"name": "allow-reads", "agent_role": ["*"], "tool_pattern": "read_*", "action": "ALLOW", "priority": 10},
  {"name": "allow-search", "agent_role": ["*"], "tool_pattern": "search_*", "action": "ALLOW", "priority": 10},
  {"name": "deny-all", "agent_role": ["*"], "tool_pattern": "*", "action": "DENY", "priority": 999}
]
```

## Pattern 2: Role-Based Tiered Access

```json
[
  {"name": "reader-read-only", "agent_role": ["reader"], "tool_pattern": "read_*", "action": "ALLOW", "priority": 10},
  {"name": "writer-read-write", "agent_role": ["writer"], "tool_pattern": "read_*", "action": "ALLOW", "priority": 10},
  {"name": "writer-write", "agent_role": ["writer"], "tool_pattern": "write_*", "action": "ALLOW", "priority": 10},
  {"name": "admin-all", "agent_role": ["admin"], "tool_pattern": "*", "action": "ALLOW", "priority": 5},
  {"name": "deny-all", "agent_role": ["*"], "tool_pattern": "*", "action": "DENY", "priority": 999}
]
```

## Pattern 3: Argument Validation

Restrict `send_email` to approved domains:

```json
{
  "name": "email-domain-restriction",
  "agent_role": ["writer"],
  "tool_pattern": "send_email",
  "action": "ALLOW",
  "priority": 10,
  "arg_validators": [
    {
      "arg_name": "to",
      "regex_pattern": "^[^@]+@(company\\.com|approved-partner\\.com)$"
    }
  ]
}
```

## Pattern 4: Risk-Adaptive Access

Allow operations below a risk threshold, escalate above it:

```json
[
  {"name": "low-risk-allow", "agent_role": ["*"], "tool_pattern": "write_*", "action": "ALLOW", "risk_threshold": 0.5, "priority": 10},
  {"name": "high-risk-escalate", "agent_role": ["*"], "tool_pattern": "write_*", "action": "ESCALATE", "risk_threshold": 1.0, "priority": 20}
]
```

## Pattern 5: Taint-Aware Blocking

Block tool calls when arguments contain untrusted data:

```json
{
  "name": "block-tainted-writes",
  "agent_role": ["*"],
  "tool_pattern": "write_*",
  "action": "DENY",
  "taint_check": true,
  "priority": 5
}
```

## Pattern 6: Rate Limiting

Limit email sending to 10 per minute:

```json
{
  "name": "rate-limit-emails",
  "agent_role": ["writer"],
  "tool_pattern": "send_email",
  "action": "ALLOW",
  "rate_limit": {"count": 10, "window_s": 60},
  "priority": 10
}
```

## Pattern 7: Escalate Deletions for Human Approval

```json
{
  "name": "escalate-deletions",
  "agent_role": ["*"],
  "tool_pattern": "delete_*",
  "action": "ESCALATE",
  "priority": 1
}
```

## Pattern 8: Dry-Run for New Policies

Test a policy without enforcing it:

```json
{
  "name": "proposed-new-restriction",
  "agent_role": ["writer"],
  "tool_pattern": "modify_*",
  "action": "DRY_RUN",
  "priority": 15
}
```

Review dry-run decisions in the audit log, then change action to DENY when ready.
