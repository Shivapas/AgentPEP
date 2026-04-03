# SDK Overview

The AgentPEP Python SDK provides a simple interface for integrating policy
enforcement into AI agent applications.

## Architecture

```
Your Application
├── @enforce decorator      ← Wrap any function with policy checks
├── AgentPEPClient          ← HTTP client for the Intercept API
├── AgentPEPMiddleware      ← FastAPI middleware integration
├── OfflineEvaluator        ← Local testing without a server
└── Integrations
    ├── LangChain           ← Tool wrapper for LangChain agents
    └── LangGraph           ← Pre-hook and guard nodes
```

## Core Components

| Component | Purpose | Import |
|-----------|---------|--------|
| [AgentPEPClient](client.md) | HTTP client (async + sync) | `from agentpep import AgentPEPClient` |
| [@enforce](decorator.md) | Function decorator | `from agentpep import enforce` |
| [AgentPEPMiddleware](middleware.md) | FastAPI middleware | `from agentpep.middleware import AgentPEPMiddleware` |
| [OfflineEvaluator](offline.md) | Local testing | `from agentpep.offline import OfflineEvaluator` |
| [LangChain](integrations/langchain.md) | Tool wrapper | `from agentpep.integrations.langchain import AgentPEPToolWrapper` |
| [LangGraph](integrations/langgraph.md) | Graph hooks | `from agentpep.integrations.langgraph import agentpep_pre_hook` |

## Exception Hierarchy

```
AgentPEPError (base)
├── PolicyDeniedError       ← Tool call denied by policy
├── AgentPEPConnectionError ← Server unreachable
└── AgentPEPTimeoutError    ← Request timed out
```

## Quick Example

```python
from agentpep import AgentPEPClient, enforce

client = AgentPEPClient(
    base_url="http://localhost:8000",
    api_key="your-key",
)

# Verify connection
health = await client.health_check()
assert health["status"] == "ok"

# Enforce policy on a function
@enforce(client=client, agent_id="my-agent")
async def send_email(to: str, subject: str):
    await smtp.send(to, subject)

# Raises PolicyDeniedError if not allowed
await send_email("user@example.com", "Hello")
```
