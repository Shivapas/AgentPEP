# Policy Authoring Workshop Guide (APEP-212)

## Workshop Overview

**Duration:** 60 minutes
**Audience:** Beta customer technical teams (developers, DevOps, security)
**Prerequisites:** SDK installed, API key provisioned, basic Python knowledge

---

## Agenda

| Time | Topic | Format |
|------|-------|--------|
| 0:00–0:15 | Policy Model Overview | Presentation |
| 0:15–0:40 | Hands-on Policy Authoring | Lab |
| 0:40–0:50 | Taint Tracking Walkthrough | Demo |
| 0:50–0:60 | Q&A and Feedback | Discussion |

---

## Part 1: Policy Model Overview (15 min)

### Core Concepts

**AgentPEP** enforces policies at the tool-call boundary. Every time an AI agent
attempts to use a tool (send email, read file, query database), AgentPEP intercepts
the request and evaluates it against your policy stack.

### Decision Flow

```
Agent Tool Call → AgentPEP Intercept → Policy Evaluation → Decision
                                                            ├─ ALLOW  → Tool executes
                                                            ├─ DENY   → Tool blocked
                                                            ├─ ESCALATE → Human review
                                                            └─ DRY_RUN  → Log only
```

### Policy Rule Anatomy

```json
{
  "name": "block-dangerous-file-writes",
  "agent_role": ["writer"],
  "tool_pattern": "write_file",
  "action": "DENY",
  "risk_threshold": 0.7,
  "arg_validators": [
    {
      "arg_name": "path",
      "blocklist": ["/etc/*", "/root/*", "~/.ssh/*"]
    }
  ],
  "priority": 10,
  "enabled": true
}
```

### Key Principles

1. **Deny by default** — No rule match = DENY
2. **First-match semantics** — Rules evaluated by priority (lower = higher priority)
3. **Glob patterns** — `write_*`, `*.delete`, `db.query.*`
4. **Role-based** — Rules target specific agent roles
5. **Taint-aware** — Rules can check if data is tainted (untrusted source)

---

## Part 2: Hands-on Policy Authoring (25 min)

### Exercise 1: Allow/Deny Basics

Create a policy that allows read operations but denies delete operations.

```python
from agentpep import AgentPEPClient

client = AgentPEPClient(
    base_url="https://<your-tenant>.beta.agentpep.io",
    api_key="<your-key>",
)

# Test: Should be ALLOW
response = await client.evaluate(
    agent_id="workshop-agent",
    tool_name="read_document",
    tool_args={"doc_id": "123"},
)
print(f"read_document: {response.decision}")  # ALLOW

# Test: Should be DENY
response = await client.evaluate(
    agent_id="workshop-agent",
    tool_name="delete_document",
    tool_args={"doc_id": "123"},
)
print(f"delete_document: {response.decision}")  # DENY
```

### Exercise 2: Role-Based Access

Configure different permissions for different agent roles:

- `reader` — Can only use `read_*` tools
- `writer` — Can use `read_*` and `write_*` tools
- `admin` — Can use all tools

### Exercise 3: Argument Validation

Create a policy that allows `send_email` but only to approved domains:

```json
{
  "name": "restrict-email-domains",
  "agent_role": ["writer"],
  "tool_pattern": "send_email",
  "action": "ALLOW",
  "arg_validators": [
    {
      "arg_name": "to",
      "regex_pattern": "^[^@]+@(company\\.com|partner\\.com)$"
    }
  ],
  "priority": 5
}
```

### Exercise 4: Dry-Run Mode

Test policies without blocking real operations:

```python
response = await client.evaluate(
    agent_id="workshop-agent",
    tool_name="send_email",
    tool_args={"to": "external@unknown.com"},
    dry_run=True,
)
# Returns DRY_RUN instead of DENY — logs the decision for review
print(f"Dry run result: {response.decision}")
```

### Exercise 5: Using the @enforce Decorator

```python
from agentpep import enforce

@enforce(client=client, agent_id="workshop-agent")
async def send_notification(user_id: str, message: str):
    """This function is policy-guarded automatically."""
    print(f"Sending to {user_id}: {message}")

# Raises PolicyDeniedError if not allowed
await send_notification("user-1", "Hello from the workshop!")
```

---

## Part 3: Taint Tracking Walkthrough (10 min)

### Demo: Tracking Untrusted Data

```python
from agentpep.models import TaintSource

# Label data from an untrusted source
node = await client.label_taint(
    session_id="workshop-session",
    source=TaintSource.WEB,
    value="user-provided search query",
)
print(f"Taint level: {node.taint_level}")  # UNTRUSTED

# Propagate taint through a transformation
output_node = await client.propagate_taint(
    session_id="workshop-session",
    parent_node_ids=[str(node.node_id)],
    source=TaintSource.TOOL_OUTPUT,
)
# Output inherits UNTRUSTED from parent
print(f"Propagated taint: {output_node.taint_level}")
```

### Key Takeaway

Taint tracking ensures that data from untrusted sources (web scraping, user
prompts, emails) is flagged throughout the processing pipeline. Policy rules
with `taint_check: true` will DENY tool calls when tainted data is detected.

---

## Part 4: Q&A and Feedback (10 min)

### Feedback Questions

1. What was the most confusing part of policy authoring?
2. What policy patterns would you like to see pre-built?
3. Any tools or integrations you need that aren't supported?
4. How would you rate the documentation clarity (1–5)?

### Next Steps

- Review the full [API Reference](../api-conventions.md)
- Explore the [SDK Quickstart Guide](../sdk-quickstart.md)
- Join the beta support Slack channel
- Schedule a follow-up session for advanced topics (delegation chains, custom sanitisation gates)
