# Intercept API

The core decision engine endpoint. Every tool call is evaluated here.

## POST /v1/intercept

Evaluate a tool call request against the policy stack.

### Request

```json
{
  "session_id": "session-123",
  "agent_id": "my-agent",
  "tool_name": "send_email",
  "tool_args": {
    "to": "user@example.com",
    "subject": "Hello"
  },
  "delegation_chain": ["agent-a", "agent-b"],
  "taint_node_ids": [],
  "dry_run": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `session_id` | string | Yes | Session identifier |
| `agent_id` | string | Yes | Agent making the tool call |
| `tool_name` | string | Yes | Name of the tool being called |
| `tool_args` | object | No | Arguments passed to the tool |
| `delegation_chain` | string[] | No | Chain of agents that delegated this call |
| `delegation_hops` | DelegationHop[] | No | Structured delegation chain with authority |
| `taint_node_ids` | UUID[] | No | Taint nodes associated with arguments |
| `dry_run` | boolean | No | If true, log but don't enforce |

### Response

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "decision": "ALLOW",
  "matched_rule_id": "660e8400-e29b-41d4-a716-446655440001",
  "risk_score": 0.15,
  "taint_flags": [],
  "reason": "Matched rule: allow-read-operations",
  "escalation_id": null,
  "latency_ms": 3
}
```

### Decision Values

| Decision | Meaning |
|----------|---------|
| `ALLOW` | Tool call permitted |
| `DENY` | Tool call blocked |
| `ESCALATE` | Requires human review |
| `DRY_RUN` | Logged but not enforced |
| `TIMEOUT` | Policy evaluation timed out |

### Example

```bash
curl -X POST http://localhost:8000/v1/intercept \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '{
    "session_id": "test",
    "agent_id": "my-agent",
    "tool_name": "send_email",
    "tool_args": {"to": "user@example.com"}
  }'
```
