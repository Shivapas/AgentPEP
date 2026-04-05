# LangGraph Integration

Insert policy enforcement nodes into LangGraph workflows.

## Installation

```bash
pip install agentpep-sdk[langchain]
```

## Pre-execution Hook

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

## ToolNode Guard

Guard all tool calls from an `AIMessage` in a single node:

```python
from agentpep.integrations.langgraph import enforce_tool_node

tool_guard = enforce_tool_node(client, agent_id="lg-agent")
graph.add_node("tool_guard", tool_guard)
graph.add_node("tools", tool_node)
graph.add_edge("tool_guard", "tools")
```

## How It Works

- **Pre-hook**: Evaluates a single tool call before the tool node executes
- **Tool guard**: Iterates over all tool calls in the current `AIMessage` and
  evaluates each one. If any call is denied, the guard raises `PolicyDeniedError`
  before any tool executes.
