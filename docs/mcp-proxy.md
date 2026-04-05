# MCP Tool Call Intercept Proxy

The MCP proxy is a transparent intermediary that sits between any MCP-compliant
agent (client) and an MCP tool server. It intercepts `tools/call` requests,
evaluates them against the AgentPEP policy stack, and either forwards (ALLOW)
or blocks (DENY/ESCALATE) the call before it reaches the upstream server.

```
Agent  -->  AgentPEP MCP Proxy  -->  Target MCP Server
                |
                +-- Parse JSON-RPC envelope
                +-- Evaluate via policy engine
                +-- Track taint per session
                +-- Forward or deny
```

## Quick Start

### 1. Configure the Agent Profile

Add MCP proxy configuration to the agent's profile in MongoDB:

```json
{
  "agent_id": "my-agent",
  "name": "My Agent",
  "roles": ["reader"],
  "allowed_tools": ["*"],
  "mcp_proxy": {
    "enabled": true,
    "upstream_url": "http://localhost:3000/mcp",
    "allowed_tools": ["read_*", "search_*"],
    "timeout_s": 30.0,
    "max_concurrent_sessions": 10,
    "taint_tracking_enabled": true
  },
  "enabled": true
}
```

### 2. Start a Proxy Session

```bash
curl -X POST http://localhost:8000/v1/mcp/session/start \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "my-agent",
    "upstream_url": "http://localhost:3000/mcp"
  }'
```

Response:

```json
{
  "session_id": "mcp-a1b2c3d4e5f6",
  "agent_id": "my-agent",
  "upstream_url": "http://localhost:3000/mcp",
  "status": "active"
}
```

### 3. Proxy Tool Calls

Send MCP JSON-RPC messages through the proxy:

```bash
curl -X POST http://localhost:8000/v1/mcp/proxy \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "mcp-a1b2c3d4e5f6",
    "message": {
      "jsonrpc": "2.0",
      "id": 1,
      "method": "tools/call",
      "params": {
        "name": "read_file",
        "arguments": {"path": "/tmp/data.txt"}
      }
    }
  }'
```

If **ALLOW**: the upstream server's response is returned as-is.

If **DENY**: a JSON-RPC error is returned:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "Tool call denied by policy: ...",
    "data": {
      "decision": "DENY",
      "tool_name": "read_file",
      "matched_rule_id": "..."
    }
  }
}
```

### 4. End the Session

```bash
curl -X POST http://localhost:8000/v1/mcp/session/end \
  -H "Content-Type: application/json" \
  -d '{"session_id": "mcp-a1b2c3d4e5f6"}'
```

The taint graph is persisted to MongoDB for forensic replay.

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/v1/mcp/session/start` | POST | Start a new MCP proxy session |
| `/v1/mcp/session/end` | POST | End a session and persist taint graph |
| `/v1/mcp/session/{id}` | GET | Get session status |
| `/v1/mcp/sessions` | GET | List all active sessions |
| `/v1/mcp/proxy` | POST | Proxy a single JSON-RPC message |
| `/v1/mcp/proxy/batch` | POST | Proxy a batch of JSON-RPC messages |

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `AGENTPEP_MCP_PROXY_ENABLED` | `false` | Global MCP proxy feature flag |
| `AGENTPEP_MCP_PROXY_DEFAULT_TIMEOUT_S` | `30.0` | Default upstream timeout |

### AgentProfile MCP Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `mcp_proxy.enabled` | bool | `false` | Enable MCP proxy for this agent |
| `mcp_proxy.upstream_url` | string | `""` | Target MCP server URL |
| `mcp_proxy.allowed_tools` | list[str] | `[]` | MCP tool glob patterns (empty = use profile-level) |
| `mcp_proxy.timeout_s` | float | `30.0` | Upstream request timeout |
| `mcp_proxy.max_concurrent_sessions` | int | `10` | Max concurrent proxy sessions |
| `mcp_proxy.taint_tracking_enabled` | bool | `true` | Enable taint tracking for MCP sessions |

## How It Works

### Message Flow

1. **Parse**: The proxy parses incoming JSON-RPC 2.0 messages and classifies
   them as `tools/call`, `tools/list`, notifications, or responses.

2. **Intercept**: Only `tools/call` requests are intercepted for policy
   evaluation. All other message types are forwarded transparently.

3. **Evaluate**: The tool name and arguments are submitted to the policy
   evaluator, which checks RBAC rules, taint flags, delegation chains, and
   risk thresholds.

4. **Forward or Block**:
   - **ALLOW** / **DRY_RUN**: Forward the original message to upstream.
   - **DENY**: Return a JSON-RPC error with code `-32001`.
   - **ESCALATE**: Return a JSON-RPC error with code `-32002`.
   - **TIMEOUT**: Return a JSON-RPC error with code `-32001`.

5. **Track**: Tool outputs are registered as taint nodes in the session's
   taint graph, with taint propagating from inputs to outputs.

### Error Codes

| Code | Constant | Meaning |
|---|---|---|
| `-32001` | `MCP_ERROR_POLICY_DENIED` | Tool call denied by policy |
| `-32002` | `MCP_ERROR_POLICY_ESCALATED` | Tool call requires human escalation |
| `-32003` | `MCP_ERROR_UPSTREAM_FAILED` | Upstream MCP server unreachable or errored |
| `-32004` | `MCP_ERROR_SESSION_UNKNOWN` | Unknown proxy session ID |

### Session Taint Tracking

Each MCP proxy session maintains its own taint graph. When a tool call is
allowed and forwarded, the tool's output is registered as a taint node that
inherits the highest taint level from its input nodes. This enables:

- Detection of untrusted data flowing through tool chains
- QUARANTINE escalation when injection patterns are detected in tool outputs
- Forensic replay of data lineage after session end (persisted to MongoDB)

## MongoDB Collections

| Collection | Purpose | TTL |
|---|---|---|
| `mcp_proxy_sessions` | Session metadata (agent, status, tool count) | 30 days |
| `taint_graphs` | Persisted taint DAGs for forensic replay | 30 days |
| `audit_decisions` | Policy decisions for MCP tool calls | Configurable |
