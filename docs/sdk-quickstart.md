# AgentPEP SDK — Quickstart Guide

## Installation

```bash
pip install agentpep-sdk

# With LangChain integration
pip install agentpep-sdk[langchain]

# With CrewAI integration
pip install agentpep-sdk[crewai]

# With Semantic Kernel integration
pip install agentpep-sdk[semantic-kernel]

# With FastAPI middleware
pip install agentpep-sdk[fastapi]
```

## Quick Start

### 1. Create a Client

```python
from agentpep import AgentPEPClient

client = AgentPEPClient(
    base_url="http://localhost:8000",
    api_key="your-api-key",
    timeout=5.0,
    fail_open=False,  # Set True for development
)
```

### 2. Evaluate a Tool Call

```python
# Async
response = await client.evaluate(
    agent_id="my-agent",
    tool_name="send_email",
    tool_args={"to": "user@example.com", "subject": "Hello"},
    session_id="session-123",
)
print(response.decision)  # ALLOW, DENY, ESCALATE, etc.

# Sync
response = client.evaluate_sync(
    agent_id="my-agent",
    tool_name="send_email",
    tool_args={"to": "user@example.com"},
)
```

### 3. Enforce (Evaluate + Raise on Deny)

```python
# Raises PolicyDeniedError if not ALLOW/DRY_RUN
response = await client.enforce(
    agent_id="my-agent",
    tool_name="send_email",
    tool_args={"to": "user@example.com"},
)
```

## `@enforce` Decorator

Wrap any function so every call is policy-checked before execution:

```python
from agentpep import enforce, AgentPEPClient

client = AgentPEPClient(base_url="http://localhost:8000", api_key="...")

@enforce(client=client, agent_id="my-agent", role="WriterAgent")
async def send_email(to: str, subject: str, body: str):
    """Only executes if AgentPEP returns ALLOW."""
    await smtp_client.send(to, subject, body)

# Sync functions work too
@enforce(client=client, agent_id="my-agent")
def read_file(path: str) -> str:
    return open(path).read()
```

## FastAPI Middleware

Enforce policy on all incoming requests to a FastAPI application:

```python
from fastapi import FastAPI
from agentpep import AgentPEPClient
from agentpep.middleware import AgentPEPMiddleware

app = FastAPI()
client = AgentPEPClient(base_url="http://localhost:8000", api_key="...")

app.add_middleware(
    AgentPEPMiddleware,
    client=client,
    exclude_paths={"/health", "/ready", "/metrics"},
)
```

Requests must include an `X-Agent-Id` header. The middleware uses the request
path as the tool name. Requests without `X-Agent-Id` pass through unchecked.

## LangChain Integration

Wrap LangChain tools with AgentPEP policy enforcement:

```python
from agentpep import AgentPEPClient
from agentpep.integrations.langchain import AgentPEPToolWrapper

client = AgentPEPClient(base_url="http://localhost:8000")

# Wrap each tool
safe_tools = [
    AgentPEPToolWrapper(
        wrapped_tool=tool,
        client=client,
        agent_id="lc-agent",
    )
    for tool in raw_tools
]

# Use with any LangChain agent
agent = create_react_agent(llm, safe_tools, prompt)
```

## LangGraph Integration

### Pre-execution Hook

Insert a policy check node before any tool-calling node:

```python
from langgraph.graph import StateGraph
from agentpep import AgentPEPClient
from agentpep.integrations.langgraph import agentpep_pre_hook

client = AgentPEPClient(base_url="http://localhost:8000")

graph = StateGraph(State)
graph.add_node("check_policy", agentpep_pre_hook(
    client, agent_id="lg-agent", tool_name="send_email"
))
graph.add_node("send_email", send_email_node)
graph.add_edge("check_policy", "send_email")
```

### ToolNode Guard

Guard all tool calls from an AIMessage:

```python
from agentpep.integrations.langgraph import enforce_tool_node

tool_guard = enforce_tool_node(client, agent_id="lg-agent")
graph.add_node("tool_guard", tool_guard)
graph.add_node("tools", tool_node)
graph.add_edge("tool_guard", "tools")
```

## Local Offline Mode

For development and testing without a running AgentPEP server:

```python
from agentpep.offline import OfflineEvaluator, OfflineRule
from agentpep.models import PolicyDecision

evaluator = OfflineEvaluator(rules=[
    OfflineRule(tool_pattern="read_*", action=PolicyDecision.ALLOW, priority=10),
    OfflineRule(tool_pattern="write_*", action=PolicyDecision.ALLOW, priority=20),
    OfflineRule(tool_pattern="delete_*", action=PolicyDecision.DENY, priority=10),
])

# Use with @enforce decorator
from agentpep import enforce

@enforce(evaluator, agent_id="dev-agent")
def read_file(path: str) -> str:
    return open(path).read()

# Or evaluate directly
response = evaluator.evaluate(agent_id="dev", tool_name="read_file")
assert response.decision == PolicyDecision.ALLOW
```

### Load Rules from Dicts

```python
rules = [
    {"tool_pattern": "read_*", "action": "ALLOW", "priority": 10},
    {"tool_pattern": "delete_*", "action": "DENY", "priority": 5},
    {"tool_pattern": "*", "action": "DENY", "priority": 999},
]
evaluator = OfflineEvaluator.from_dict_list(rules)
```

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
    print(f"Denied: {e.tool_name} — {e.reason}")
except AgentPEPConnectionError:
    print("Cannot reach AgentPEP server")
except AgentPEPTimeoutError:
    print("Request timed out")
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `base_url` | `http://localhost:8000` | AgentPEP server URL |
| `api_key` | `None` | API key for `X-API-Key` header |
| `timeout` | `5.0` | Request timeout in seconds |
| `fail_open` | `False` | Allow on server unreachable (dev only) |
