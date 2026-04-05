# Quickstart

Get AgentPEP running and enforce your first policy in under 5 minutes.

## Prerequisites

- Python 3.11+
- Docker and Docker Compose (for the server)

## Step 1: Start the Server

```bash
git clone https://github.com/Shivapas/agentpep.git
cd agentpep
docker compose up -d
```

This starts:

- **Backend API** on `http://localhost:8000`
- **Policy Console** on `http://localhost:5173`
- **MongoDB** on `localhost:27017`

Verify the server is running:

```bash
curl http://localhost:8000/health
# {"status": "ok", "version": "0.1.0"}
```

## Step 2: Install the SDK

```bash
pip install agentpep-sdk
```

## Step 3: Verify Connectivity

```python
from agentpep import AgentPEPClient

client = AgentPEPClient(base_url="http://localhost:8000")

# Check server health
health = client.health_check_sync()
print(health)  # {"status": "ok", "version": "0.1.0"}
```

## Step 4: Evaluate Your First Tool Call

```python
response = client.evaluate_sync(
    agent_id="my-agent",
    tool_name="read_document",
    tool_args={"doc_id": "123"},
)
print(f"Decision: {response.decision}")
# Decision: DENY (default deny-by-default behavior)
```

## Step 5: Add a Policy Rule

```bash
curl -X POST http://localhost:8000/v1/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "allow-reads",
    "agent_role": ["*"],
    "tool_pattern": "read_*",
    "action": "ALLOW",
    "priority": 10
  }'
```

Now re-evaluate:

```python
response = client.evaluate_sync(
    agent_id="my-agent",
    tool_name="read_document",
    tool_args={"doc_id": "123"},
)
print(f"Decision: {response.decision}")
# Decision: ALLOW
```

## Step 6: Use the @enforce Decorator

```python
from agentpep import enforce

@enforce(client=client, agent_id="my-agent")
def read_document(doc_id: str) -> dict:
    return {"doc_id": doc_id, "content": "Hello, world!"}

# This succeeds — policy returns ALLOW for read_*
result = read_document("123")
print(result)
```

## Next Steps

- [Installation options](installation.md) — LangChain, FastAPI middleware
- [Your first policy](first-policy.md) — Write real-world policies
- [SDK Reference](../sdk/overview.md) — Full SDK documentation
- [API Reference](../api/conventions.md) — REST API documentation
