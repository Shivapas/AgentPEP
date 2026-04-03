# Taint API

Endpoints for taint source labelling, propagation, sanitisation, and
cross-agent tracking.

## POST /v1/taint/label

Label data with a taint source.

```json
{
  "session_id": "session-1",
  "source": "WEB",
  "value": "user search query",
  "taint_level": null
}
```

Sources `WEB`, `EMAIL`, `TOOL_OUTPUT`, and `AGENT_MSG` are automatically
classified as `UNTRUSTED`.

## POST /v1/taint/propagate

Propagate taint from parent nodes to a new output.

```json
{
  "session_id": "session-1",
  "parent_node_ids": ["uuid-1", "uuid-2"],
  "source": "TOOL_OUTPUT",
  "value": "processed output"
}
```

The new node inherits the highest taint level from its parents.

## POST /v1/taint/propagate/tool-chain

Propagate taint through a tool call chain (multi-hop tracking).

```json
{
  "session_id": "session-1",
  "parent_node_ids": ["uuid-1"],
  "source": "TOOL_OUTPUT",
  "tool_call_id": "call-123",
  "agent_id": "agent-1"
}
```

## POST /v1/taint/propagate/cross-agent

Propagate taint across agent boundaries.

```json
{
  "source_session_id": "session-1",
  "source_node_ids": ["uuid-1"],
  "target_session_id": "session-2",
  "target_agent_id": "agent-2"
}
```

## POST /v1/taint/sanitise

Apply sanitisation to downgrade a node's taint level.

```json
{
  "session_id": "session-1",
  "node_id": "uuid-1",
  "sanitiser_function": "html_escape"
}
```

## GET /v1/taint/session/{session_id}

Get the full taint graph for a session.

## GET /v1/taint/session/{session_id}/visualisation

Get the taint graph as nodes and edges for UI rendering.

## Taint Levels

| Level | Description |
|-------|-------------|
| `TRUSTED` | Data from verified sources |
| `UNTRUSTED` | Data from external/unverified sources |
| `QUARANTINE` | Data flagged for injection patterns |

## Taint Sources

| Source | Auto-Level | Description |
|--------|------------|-------------|
| `USER_PROMPT` | TRUSTED | Direct user input |
| `SYSTEM_PROMPT` | TRUSTED | System configuration |
| `WEB` | UNTRUSTED | Web-scraped data |
| `EMAIL` | UNTRUSTED | Email content |
| `TOOL_OUTPUT` | UNTRUSTED | Output from tool execution |
| `AGENT_MSG` | UNTRUSTED | Inter-agent messages |
| `CROSS_AGENT` | UNTRUSTED | Data crossing agent boundary |
| `SANITISED` | TRUSTED | Output of sanitisation gate |
