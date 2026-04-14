# ToolTrust Migration Guide

## Overview

This guide helps existing AgentPEP SDK users migrate to the new **ToolTrustSession** API introduced in Sprint 43. The `ToolTrustSession` class provides a plan-aware, high-level interface that wraps the existing `AgentPEPClient` with MissionPlan lifecycle management.

**The existing `@enforce` decorator and `AgentPEPClient` continue to work unchanged.** The `ToolTrustSession` is an additive API — it does not replace existing functionality.

## What's New

| Feature | Before (v1.0) | After (v1.1 with ToolTrustSession) |
|---------|---------------|-------------------------------------|
| Authorization model | Implicit sessions with RBAC | + Explicit MissionPlan authorization |
| SDK surface | `@enforce` decorator, `AgentPEPClient` | + `ToolTrustSession` with `issue_plan`, `delegate`, `audit` |
| Delegation | Reactive confused-deputy detection | + Proactive `delegates_to` whitelist via `delegate()` |
| Scope testing | Manual API calls | + `agentpep scope simulate` CLI + Scope Simulator UI |
| Pattern library | Write scope patterns from scratch | + 30+ curated enterprise templates |
| Audit | Flat audit log | + Plan-scoped receipt tree via `audit()` |

## Migration Steps

### Step 1: Install the Updated SDK

```bash
pip install agentpep>=1.1.0
```

### Step 2: Choose Your Migration Path

#### Path A: Keep Using `@enforce` (No Changes Required)

If your agents use the `@enforce` decorator without MissionPlans, **no changes are needed**. The decorator continues to work exactly as before:

```python
from agentpep import enforce

@enforce(agent_id="my-agent", session_id="session-1")
async def read_file(path: str) -> str:
    return open(path).read()
```

#### Path B: Adopt ToolTrustSession for Plan-Aware Workflows

If you want to use MissionPlans for explicit authorization, replace manual API calls with `ToolTrustSession`:

**Before (manual plan management):**

```python
import httpx
from agentpep import AgentPEPClient

client = AgentPEPClient(base_url="http://localhost:8000")

# Manually create plan
async with httpx.AsyncClient(base_url="http://localhost:8000") as http:
    resp = await http.post("/v1/plans", json={
        "action": "Analyze Q3 reports",
        "issuer": "alice@corp.com",
        "scope": ["read:internal:finance.*"],
    })
    plan = resp.json()

    # Manually bind session
    await http.post(f"/v1/plans/{plan['plan_id']}/bind", json={
        "session_id": "session-1",
        "agent_id": "analyst-bot",
    })

# Evaluate tool call
result = await client.evaluate(
    agent_id="analyst-bot",
    tool_name="db.read.internal.finance.q3",
    session_id="session-1",
)
```

**After (ToolTrustSession):**

```python
from agentpep import ToolTrustSession

async with ToolTrustSession(
    base_url="http://localhost:8000",
    session_id="session-1",
    agent_id="analyst-bot",
) as session:
    # Issue plan and auto-bind session
    plan = await session.issue_plan(
        action="Analyze Q3 reports",
        issuer="alice@corp.com",
        scope=["read:internal:finance.*"],
    )

    # Evaluate tool call
    result = await session.evaluate(
        tool_name="db.read.internal.finance.q3",
    )
```

### Step 3: Use `delegate()` for Sub-Agent Workflows

**Before (manual delegation):**

```python
# Check delegates_to whitelist manually
plan_detail = await http.get(f"/v1/plans/{plan_id}")
delegates_to = plan_detail.json()["delegates_to"]
if child_agent_id not in delegates_to:
    raise PermissionError("Agent not authorized")

# Evaluate with delegation chain
result = await client.evaluate(
    agent_id=child_agent_id,
    tool_name="api.get.external.summary",
    session_id="session-1",
    delegation_chain=["analyst-bot", child_agent_id],
)
```

**After (ToolTrustSession.delegate):**

```python
async with ToolTrustSession(...) as session:
    plan = await session.issue_plan(
        action="Analyze and summarize",
        issuer="alice@corp.com",
        scope=["read:internal:*", "read:external:*"],
        delegates_to=["summary-bot"],
    )

    # Delegate to child agent (whitelist check built in)
    result = await session.delegate(
        child_agent_id="summary-bot",
        tool_name="api.get.external.summary",
    )

    if not result.allowed:
        print(f"Delegation denied: {result.reason}")
```

### Step 4: Use `audit()` for Plan-Scoped Receipt Trees

```python
async with ToolTrustSession(...) as session:
    plan = await session.issue_plan(...)

    # ... perform operations ...

    # Fetch receipt tree
    tree = await session.audit()
    print(f"Plan {tree.plan_id}: {tree.total} receipts, valid={tree.chain_valid}")
```

### Step 5: Test Scope Patterns Before Deployment

#### Using the CLI

```bash
# Simulate tool calls against scope patterns
agentpep scope simulate \
    --scope "read:internal:finance.*" \
    --checkpoint "write:secret:*" \
    --tool-name db.read.internal.finance.q3 file.write.secret.key

# Load scope from a plan YAML file
agentpep scope simulate \
    --plan plan.yaml \
    --tool-name db.read.internal.finance.q3
```

#### Using the Console UI

Navigate to the **Scope Simulator** page in the AgentPEP console to interactively test scope patterns against tool names and see detailed match information.

#### Using the Pattern Library

Browse the **Pattern Library** in the console to find curated enterprise scope patterns. The library includes 30+ templates organized by category (Data Access, Secrets, Deployment, Compliance, etc.) with recommended checkpoint patterns.

## API Reference

### ToolTrustSession

```python
class ToolTrustSession:
    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str | None = None,
        timeout: float = 5.0,
        fail_open: bool = False,
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> None: ...

    async def issue_plan(
        self,
        *,
        action: str,
        issuer: str,
        scope: list[str] | None = None,
        requires_checkpoint: list[str] | None = None,
        delegates_to: list[str] | None = None,
        budget: dict | None = None,
        human_intent: str = "",
    ) -> PlanInfo: ...

    async def evaluate(
        self,
        *,
        agent_id: str | None = None,
        tool_name: str,
        tool_args: dict | None = None,
        delegation_chain: list[str] | None = None,
        dry_run: bool = False,
    ) -> PolicyDecisionResponse: ...

    async def enforce(
        self,
        *,
        agent_id: str | None = None,
        tool_name: str,
        tool_args: dict | None = None,
        delegation_chain: list[str] | None = None,
    ) -> PolicyDecisionResponse: ...

    async def delegate(
        self,
        *,
        child_agent_id: str,
        tool_name: str,
        tool_args: dict | None = None,
    ) -> DelegationResult: ...

    async def audit(self) -> AuditTree: ...
    async def budget_status(self) -> dict: ...
    async def revoke_plan(self) -> dict: ...
    async def close(self) -> None: ...
```

### CLI: `agentpep scope simulate`

```
agentpep scope simulate [OPTIONS] --tool-name TOOL_NAME [TOOL_NAME ...]

Options:
  --plan FILE           Load scope/checkpoint from a plan YAML file
  --scope PATTERN ...   Inline scope patterns (verb:namespace:resource)
  --checkpoint PATTERN  Inline checkpoint patterns
  --action TEXT         Action description
  --tool-name NAME ...  Tool names to simulate (required)
  --json                Output as JSON
```

## FAQ

**Q: Do I need to change my existing `@enforce` decorators?**
A: No. The `@enforce` decorator continues to work. `ToolTrustSession` is additive.

**Q: Can I use `ToolTrustSession` without MissionPlans?**
A: `ToolTrustSession` is designed around plans. For plan-free usage, continue using `AgentPEPClient` directly.

**Q: How do I test scope patterns before deploying?**
A: Use `agentpep scope simulate` from the CLI, the Scope Simulator UI in the console, or the `POST /v1/scope/simulate` API endpoint.

**Q: Where do I find enterprise scope templates?**
A: Browse the Pattern Library in the console (`/v1/scope/patterns`) or use `GET /v1/scope/patterns` from the API. Over 30 curated templates are included.
