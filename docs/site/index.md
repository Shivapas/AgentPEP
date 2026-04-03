# AgentPEP Documentation

**AgentPEP** is a deterministic authorization engine for AI agent systems. It operates
as the last line of defense at the tool-call execution boundary, intercepting and
evaluating every action against a layered policy stack before execution.

## Key Features

- **Role-Based Access Control (RBAC)** with hierarchical role inheritance
- **Taint-Aware Data Flow Tracking** from untrusted sources through processing pipelines
- **Confused-Deputy Detection** across agent delegation chains
- **Risk-Adaptive Access Control** with configurable thresholds per agent/role
- **Full Audit Logging** with forensic replay capability
- **Sub-5ms Evaluation Latency** for real-time authorization decisions

## Quick Links

| Resource | Description |
|----------|-------------|
| [Quickstart](getting-started/quickstart.md) | Get running in 5 minutes |
| [SDK Reference](sdk/overview.md) | Python SDK documentation |
| [API Reference](api/conventions.md) | REST API documentation |
| [Policy Patterns](guides/policy-patterns.md) | Common policy examples |
| [Deployment Guide](guides/deployment.md) | Deploy to GCP/AWS |

## How It Works

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  AI Agent    │────▶│  AgentPEP       │────▶│  Tool Execution  │
│  (LangChain, │     │  Intercept API  │     │  (only if ALLOW) │
│   LangGraph, │     │                 │     │                  │
│   custom)    │     │  ┌───────────┐  │     └──────────────────┘
│              │     │  │ Policy    │  │
│              │     │  │ Evaluator │  │     ┌──────────────────┐
│              │     │  ├───────────┤  │────▶│  Audit Log       │
│              │     │  │ Taint     │  │     │  (every decision │
│              │     │  │ Tracker   │  │     │   is recorded)   │
│              │     │  ├───────────┤  │     └──────────────────┘
│              │     │  │ Confused  │  │
│              │     │  │ Deputy    │  │
│              │     │  │ Detector  │  │
│              │     │  └───────────┘  │
└─────────────┘     └─────────────────┘
```

## Installation

```bash
pip install agentpep-sdk
```

## Minimal Example

```python
from agentpep import AgentPEPClient, enforce

client = AgentPEPClient(
    base_url="http://localhost:8000",
    api_key="your-api-key",
)

@enforce(client=client, agent_id="my-agent")
async def send_email(to: str, subject: str, body: str):
    """This function only executes if the policy returns ALLOW."""
    await smtp_client.send(to, subject, body)
```
