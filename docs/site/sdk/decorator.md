# @enforce Decorator

Wrap any function so every call is policy-checked before execution.

## Usage

```python
from agentpep import enforce, AgentPEPClient

client = AgentPEPClient(base_url="http://localhost:8000")

@enforce(client=client, agent_id="my-agent")
async def send_email(to: str, subject: str, body: str):
    await smtp.send(to, subject, body)
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `client` | `AgentPEPClient \| OfflineEvaluator` | Yes | Client or offline evaluator |
| `agent_id` | `str` | Yes | Agent identifier for policy evaluation |
| `role` | `str \| None` | No | Override agent role |
| `tool_name` | `str \| None` | No | Override tool name (defaults to function name) |

## Behavior

1. Before the decorated function runs, the decorator calls `client.enforce()`
2. If the policy returns **ALLOW** or **DRY_RUN**, the function executes normally
3. If the policy returns **DENY**, **ESCALATE**, or **TIMEOUT**, a `PolicyDeniedError` is raised
4. The function never executes if the policy denies the call

## Sync and Async

The decorator works with both sync and async functions:

```python
# Async function
@enforce(client=client, agent_id="agent")
async def async_operation():
    ...

# Sync function
@enforce(client=client, agent_id="agent")
def sync_operation():
    ...
```

## With Offline Evaluator

```python
from agentpep.offline import OfflineEvaluator, OfflineRule
from agentpep.models import PolicyDecision

evaluator = OfflineEvaluator(rules=[
    OfflineRule(tool_pattern="read_*", action=PolicyDecision.ALLOW, priority=10),
    OfflineRule(tool_pattern="*", action=PolicyDecision.DENY, priority=999),
])

@enforce(evaluator, agent_id="test-agent")
def read_file(path: str) -> str:
    return open(path).read()
```
