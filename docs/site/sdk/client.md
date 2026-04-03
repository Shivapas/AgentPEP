# AgentPEPClient

The main client for communicating with the AgentPEP server. Supports both
async and sync usage patterns.

## Constructor

```python
AgentPEPClient(
    base_url: str = "http://localhost:8000",
    api_key: str | None = None,
    timeout: float = 5.0,
    fail_open: bool = False,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `base_url` | `str` | `http://localhost:8000` | AgentPEP server URL |
| `api_key` | `str \| None` | `None` | API key (sent as `X-API-Key` header) |
| `timeout` | `float` | `5.0` | Request timeout in seconds |
| `fail_open` | `bool` | `False` | Allow tool call when server is unreachable |

## Async Methods

### `evaluate()`

Evaluate a tool call against the policy engine.

```python
response = await client.evaluate(
    agent_id="my-agent",
    tool_name="send_email",
    tool_args={"to": "user@example.com"},
    session_id="session-123",
    delegation_chain=["agent-a", "agent-b"],
    dry_run=False,
)
```

Returns: `PolicyDecisionResponse`

### `enforce()`

Evaluate and raise `PolicyDeniedError` if not ALLOW/DRY_RUN.

```python
response = await client.enforce(
    agent_id="my-agent",
    tool_name="send_email",
    tool_args={"to": "user@example.com"},
)
```

### `health_check()`

Verify server connectivity.

```python
health = await client.health_check()
# {"status": "ok", "version": "0.1.0"}
```

### `label_taint()`

Label data with a taint source.

```python
from agentpep.models import TaintSource

node = await client.label_taint(
    session_id="session-1",
    source=TaintSource.WEB,
    value="user input",
)
```

### `propagate_taint()`

Propagate taint from parent nodes.

```python
output = await client.propagate_taint(
    session_id="session-1",
    parent_node_ids=[str(node.node_id)],
    source=TaintSource.TOOL_OUTPUT,
)
```

### `aclose()`

Close the async HTTP client. Call when done.

## Sync Methods

Every async method has a sync counterpart with `_sync` suffix:

- `evaluate_sync()` — Same as `evaluate()` but synchronous
- `enforce_sync()` — Same as `enforce()` but synchronous
- `health_check_sync()` — Same as `health_check()` but synchronous
- `label_taint_sync()` — Same as `label_taint()` but synchronous
- `propagate_taint_sync()` — Same as `propagate_taint()` but synchronous
- `close()` — Close the sync HTTP client

## Error Handling

```python
from agentpep.exceptions import (
    PolicyDeniedError,
    AgentPEPConnectionError,
    AgentPEPTimeoutError,
)

try:
    await client.enforce(agent_id="agent", tool_name="tool")
except PolicyDeniedError as e:
    print(f"Denied: {e.tool_name} — {e.reason} (decision: {e.decision})")
except AgentPEPConnectionError:
    print("Cannot reach server")
except AgentPEPTimeoutError:
    print("Request timed out")
```

## Fail-Open Mode

!!! warning
    Only use `fail_open=True` in development. In production, use `fail_open=False`
    (the default) to ensure deny-by-default behavior.

```python
# Development: allow tool calls when server is down
client = AgentPEPClient(fail_open=True)

# Production: deny tool calls when server is down
client = AgentPEPClient(fail_open=False)
```
