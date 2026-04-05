# Delegation Model

The Confused-Deputy Detector validates agent-to-agent delegation chains,
preventing privilege escalation through multi-hop delegation.

## The Problem

When Agent A delegates to Agent B, and Agent B delegates to Agent C,
Agent C might gain permissions that Agent A never intended to grant.
This is the "confused deputy" attack pattern applied to AI agents.

## How AgentPEP Detects It

Every delegation hop is tracked:

```json
{
  "delegation_hops": [
    {
      "agent_id": "orchestrator",
      "granted_tools": ["*"],
      "authority_source": "user"
    },
    {
      "agent_id": "email-agent",
      "granted_tools": ["send_email"],
      "authority_source": "role:writer"
    },
    {
      "agent_id": "sub-agent",
      "granted_tools": ["send_email", "delete_email"],
      "authority_source": "agent:email-agent"
    }
  ]
}
```

## Validation Rules

1. **Chain depth limit** — Max delegation depth per agent profile (default: 5)
2. **Tool scope narrowing** — Each hop can only narrow tools, never expand
3. **Authority source validation** — Each hop must cite a valid authority
4. **Implicit delegation detection** — Flags when delegation wasn't explicit

## Security Alerts

When violations are detected:

| Alert Type | Description |
|------------|-------------|
| `PRIVILEGE_ESCALATION` | Agent gained tools beyond what was delegated |
| `CHAIN_DEPTH_EXCEEDED` | Delegation chain too deep |
| `UNAUTHORIZED_DELEGATION` | Agent delegated without authority |
| `IMPLICIT_DELEGATION` | Delegation occurred without explicit grant |
| `AUTHORITY_VIOLATION` | Cited authority doesn't grant claimed tools |

## Configuration

Per-agent delegation limits:

```json
{
  "agent_id": "orchestrator",
  "max_delegation_depth": 3,
  "allowed_tools": ["*"]
}
```

## Integration

Include delegation hops in the intercept request:

```python
response = await client.evaluate(
    agent_id="sub-agent",
    tool_name="send_email",
    delegation_chain=["orchestrator", "email-agent", "sub-agent"],
)
```
