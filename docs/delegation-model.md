# Delegation Model & Confused-Deputy Detector

> Sprint 7 — APEP-054 through APEP-062

## Overview

The Confused-Deputy Detector prevents privilege escalation through agent delegation chains. When Agent A delegates work to Agent B, the detector ensures Agent B never gains more authority than Agent A was originally granted.

## Data Model

### DelegationHop

Each hop in a delegation chain records:

| Field | Type | Description |
|---|---|---|
| `agent_id` | `str` | Agent at this hop |
| `granted_tools` | `list[str]` | Glob patterns of tools this agent was granted |
| `authority_source` | `str` | Origin of authority: `user`, `role:<id>`, or `agent:<id>` |
| `timestamp` | `datetime` | When the delegation occurred |

### DelegationChain

A full chain from originating user to current agent:

```json
{
  "session_id": "sess-abc",
  "hops": [
    {"agent_id": "orchestrator", "granted_tools": ["file_*", "db_read"], "authority_source": "user"},
    {"agent_id": "file-worker", "granted_tools": ["file_read"], "authority_source": "agent:orchestrator"}
  ],
  "max_depth": 5
}
```

## Validation Pipeline

The detector runs **before** the standard PolicyEvaluator rule matching, ensuring delegation violations are caught early.

### 1. Chain Depth Enforcement (APEP-057)

Configurable maximum depth (default: 5 hops). The limit can be overridden per-agent via `AgentProfile.max_delegation_depth`.

- Chains exceeding the limit produce a `CHAIN_DEPTH_EXCEEDED` security alert and a `DENY` decision.

### 2. Authority Validation (APEP-056)

Each hop's `granted_tools` must be a subset of the previous hop's grants:

```
user → Agent-A (file_*) → Agent-B (file_read)  ✅  Narrowing
user → Agent-A (file_read) → Agent-B (file_read, admin_delete)  ❌  Escalation
```

Authority sources are validated:
- `user` — always valid (direct user delegation)
- `role:<role_id>` — valid only if the role exists and is enabled
- `agent:<agent_id>` — valid only if the agent profile exists and is enabled
- Anything else — rejected

### 3. Implicit Delegation Detection (APEP-058)

Detects when Agent B acts on data written by Agent A without an explicit delegation chain. This catches "confused deputy" attacks where a malicious agent writes instructions to a shared workspace that a victim agent executes.

Pattern detected:
1. Agent A calls a write tool (`*write*`, `*create*`, `*update*`, etc.) in the session
2. Agent B calls an action tool with no delegation chain
3. Alert type: `IMPLICIT_DELEGATION`, decision: `ESCALATE`

## Security Alerts (APEP-059)

All violations emit `SecurityAlertEvent` records to the `security_alerts` MongoDB collection:

| Alert Type | Severity | Trigger |
|---|---|---|
| `PRIVILEGE_ESCALATION` | CRITICAL | Child hop claims more tools than parent |
| `CHAIN_DEPTH_EXCEEDED` | HIGH | Chain exceeds max depth |
| `AUTHORITY_VIOLATION` | HIGH | Invalid authority source |
| `UNAUTHORIZED_DELEGATION` | HIGH | Agent not authorized to delegate |
| `IMPLICIT_DELEGATION` | MEDIUM | Shared workspace write → action without chain |

## API Usage

Send structured delegation hops via the `/v1/intercept` endpoint:

```json
POST /v1/intercept
{
  "session_id": "sess-123",
  "agent_id": "worker-agent",
  "tool_name": "file_read",
  "delegation_hops": [
    {
      "agent_id": "orchestrator",
      "granted_tools": ["file_*"],
      "authority_source": "user"
    },
    {
      "agent_id": "worker-agent",
      "granted_tools": ["file_read"],
      "authority_source": "agent:orchestrator"
    }
  ]
}
```

The legacy `delegation_chain` field (list of agent ID strings) is still supported for backward compatibility but does not trigger authority validation.

## Configuration

### Chain Depth Limit

Per-agent via `AgentProfile`:

```json
{
  "agent_id": "orchestrator",
  "max_delegation_depth": 3
}
```

Default: 5 hops (set in `ConfusedDeputyDetector` constructor).

### Monitoring

Security alerts are stored in MongoDB `security_alerts` collection with a 90-day TTL. Query them via:

```python
from app.services.confused_deputy import security_alert_emitter

alerts = await security_alert_emitter.get_alerts(
    session_id="sess-123",
    alert_type=SecurityAlertType.PRIVILEGE_ESCALATION,
)
```
