# Taint Tracking Guide

AgentPEP tracks data provenance through your AI agent pipeline, flagging
untrusted data as it flows from external sources through transformations.

## Concepts

**Taint** is a label on data indicating its trustworthiness:

- `TRUSTED` — Data from verified, controlled sources
- `UNTRUSTED` — Data from external, unverified sources
- `QUARANTINE` — Data flagged for injection patterns

**Taint propagation** follows the conservative rule: if any parent is
untrusted, the output is untrusted.

## Labelling Sources

```python
from agentpep import AgentPEPClient
from agentpep.models import TaintSource

client = AgentPEPClient(base_url="http://localhost:8000")

# Label web-scraped data (automatically UNTRUSTED)
web_node = await client.label_taint(
    session_id="session-1",
    source=TaintSource.WEB,
    value="scraped content",
)

# Label user prompt (automatically TRUSTED)
prompt_node = await client.label_taint(
    session_id="session-1",
    source=TaintSource.USER_PROMPT,
    value="user question",
)
```

## Tracking Propagation

When your agent combines data from multiple sources:

```python
# Agent combines web data with user prompt
output = await client.propagate_taint(
    session_id="session-1",
    parent_node_ids=[str(web_node.node_id), str(prompt_node.node_id)],
    source=TaintSource.TOOL_OUTPUT,
)
# output.taint_level == UNTRUSTED (inherits from web_node)
```

## Sanitisation Gates

Register functions that can downgrade taint:

```bash
curl -X POST http://localhost:8000/v1/taint/sanitisation-gates \
  -H "Content-Type: application/json" \
  -d '{
    "name": "HTML Escape",
    "function_pattern": "html_escape*",
    "downgrades_from": "UNTRUSTED",
    "downgrades_to": "TRUSTED"
  }'
```

Apply sanitisation:

```bash
curl -X POST http://localhost:8000/v1/taint/sanitise \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "session-1",
    "node_id": "<tainted-node-uuid>",
    "sanitiser_function": "html_escape"
  }'
```

## Cross-Agent Propagation

When data crosses agent boundaries:

```python
cross_node = await client.propagate_taint(
    session_id="session-2",
    parent_node_ids=[str(web_node.node_id)],
    source=TaintSource.CROSS_AGENT,
)
```

## Policy Integration

Enable taint checking in policy rules:

```json
{
  "name": "block-tainted-database-writes",
  "agent_role": ["writer"],
  "tool_pattern": "db_write_*",
  "action": "DENY",
  "taint_check": true,
  "priority": 5
}
```

When `taint_check: true`, the evaluator inspects taint nodes associated with
the tool call arguments. If any node is `UNTRUSTED` or `QUARANTINE`, the rule
triggers.
