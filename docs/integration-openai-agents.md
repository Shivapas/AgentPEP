# OpenAI Agents SDK Integration Guide

AgentPEP integrates with the [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) via lifecycle hooks, intercepting every tool call before execution for policy enforcement.

## Installation

```bash
pip install agentpep-sdk[openai-agents]
```

## Quick Start

```python
from agents import Agent, Runner
from agentpep import AgentPEPClient
from agentpep.integrations.openai_agents import AgentPEPHooks

# 1. Create the AgentPEP client
client = AgentPEPClient(
    base_url="http://localhost:8000",
    api_key="your-api-key",
)

# 2. Create the hooks
hooks = AgentPEPHooks(
    client=client,
    agent_id="my-openai-agent",
    session_id="user-session-123",
)

# 3. Attach hooks to the agent
agent = Agent(
    name="my-openai-agent",
    instructions="You are a helpful assistant.",
    hooks=hooks,
)

# 4. Run the agent — tool calls are now policy-enforced
result = await Runner.run(agent, "Send an email to user@example.com")
```

## How It Works

The `AgentPEPHooks` class implements the OpenAI Agents SDK `AgentHooks` protocol:

| Hook Method       | Behaviour                                                        |
|-------------------|------------------------------------------------------------------|
| `on_tool_start`   | Evaluates tool call against AgentPEP policy. Raises `PolicyDeniedError` if denied. |
| `on_tool_end`     | No-op (present for protocol completeness).                       |
| `on_start`        | No-op.                                                           |
| `on_end`          | No-op.                                                           |
| `on_handoff`      | No-op.                                                           |

Before every tool execution, `on_tool_start` sends the tool name and arguments to the AgentPEP Intercept API. If the decision is `DENY` or `ESCALATE`, a `PolicyDeniedError` is raised, preventing the tool from running.

## Schema Mapping (APEP-159)

The `map_openai_tool_call` function converts OpenAI tool call data into AgentPEP's `ToolCallRequest` format:

```python
from agentpep.integrations.openai_agents import map_openai_tool_call

# JSON string arguments (as returned by the model)
name, args = map_openai_tool_call(tool, '{"to": "user@example.com"}')
# → ("send_email", {"to": "user@example.com"})

# Dict arguments
name, args = map_openai_tool_call(tool, {"path": "/tmp/data.txt"})
# → ("read_file", {"path": "/tmp/data.txt"})
```

## Configuration Options

### AgentPEPHooks

| Parameter          | Type                                   | Default     | Description |
|-------------------|----------------------------------------|-------------|-------------|
| `client`          | `AgentPEPClient`                       | required    | AgentPEP client instance |
| `agent_id`        | `str`                                  | required    | Agent identifier for policy evaluation |
| `session_id`      | `str`                                  | `"default"` | Session identifier |
| `delegation_chain`| `list[str] \| None`                    | `None`      | Delegation chain for confused-deputy detection |
| `on_decision`     | `Callable[[PolicyDecisionResponse], None] \| None` | `None` | Callback invoked with each decision |

### Delegation Chain Support

For multi-agent workflows with handoffs, pass a delegation chain to enable confused-deputy detection:

```python
hooks = AgentPEPHooks(
    client=client,
    agent_id="sub-agent",
    delegation_chain=["orchestrator", "planner", "sub-agent"],
)
```

### Decision Callback

Monitor policy decisions in real time:

```python
def log_decision(response):
    print(f"Tool: {response.reason}, Decision: {response.decision.value}")

hooks = AgentPEPHooks(
    client=client,
    agent_id="my-agent",
    on_decision=log_decision,
)
```

## Standalone Guard

For custom agent runners, use `enforce_tool` to check individual tool calls:

```python
from agentpep.integrations.openai_agents import enforce_tool

guard = enforce_tool(client, agent_id="my-agent")

# Check before calling
await guard(tool_name="send_email", tool_args={"to": "user@example.com"})
```

## Error Handling

```python
from agentpep.exceptions import PolicyDeniedError

try:
    result = await Runner.run(agent, "Delete the database")
except PolicyDeniedError as e:
    print(f"Blocked: {e.tool_name} — {e.reason} (decision: {e.decision})")
```

## Fail-Open Mode

For non-critical environments, configure the client to allow tool calls when AgentPEP is unreachable:

```python
client = AgentPEPClient(
    base_url="http://localhost:8000",
    fail_open=True,  # Allow calls if server is down
)
```
