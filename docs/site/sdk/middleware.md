# FastAPI Middleware

Enforce AgentPEP policies on all incoming requests to a FastAPI application.

## Installation

```bash
pip install agentpep-sdk[fastapi]
```

## Usage

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

## How It Works

1. The middleware intercepts every incoming HTTP request
2. It reads the `X-Agent-Id` header to identify the calling agent
3. It uses the request path as the tool name
4. It calls `client.enforce()` to check the policy
5. If ALLOW: the request proceeds normally
6. If DENY/ESCALATE: returns 403 Forbidden with the denial reason

## Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-Agent-Id` | Yes | Agent identifier for policy evaluation |

Requests without the `X-Agent-Id` header pass through unchecked.

## Excluded Paths

Paths in `exclude_paths` bypass policy evaluation entirely. Common excludes:

- `/health` — Liveness probe
- `/ready` — Readiness probe
- `/metrics` — Prometheus metrics
