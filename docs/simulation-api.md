# Policy Simulation Engine — Documentation

Sprint 19: APEP-151 through APEP-157

## Overview

The Policy Simulation Engine provides a full DRY_RUN evaluation API that evaluates tool call requests against the complete policy stack (RBAC, taint tracking, delegation chain validation) **without enforcement**. This enables:

- **Pre-deployment validation** of policy changes
- **CI/CD integration** for automated policy regression testing
- **Interactive debugging** via the simulation console UI
- **Policy comparison** across versions

## Simulation API

### POST /v1/simulate

Evaluate a tool call request against the full policy stack without enforcement.

**Request Body:**

```json
{
  "session_id": "sim-session",
  "agent_id": "agent-assistant",
  "tool_name": "file.read",
  "tool_args": {"path": "/data/report.csv"},
  "delegation_chain": [],
  "delegation_hops": [],
  "taint_node_ids": [],
  "policy_version": "current",
  "policy_rules": null
}
```

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | Session identifier (default: "sim-session") |
| `agent_id` | string | **Required.** Agent making the tool call |
| `tool_name` | string | **Required.** Tool being invoked |
| `tool_args` | object | Tool arguments (default: {}) |
| `delegation_hops` | array | Structured delegation chain for confused-deputy checks |
| `taint_node_ids` | array | UUIDs of taint nodes associated with arguments |
| `policy_version` | string | Label for the policy version being evaluated |
| `policy_rules` | array | Optional explicit rule set to evaluate against |

**Response:**

```json
{
  "request_id": "uuid",
  "decision": "ALLOW",
  "matched_rule_id": "uuid",
  "matched_rule_name": "allow-file-read",
  "risk_score": 0.5,
  "taint_eval": {"checked": false},
  "chain_result": {"checked": false},
  "resolved_roles": ["default"],
  "steps": [
    {"step": "implicit_delegation_check", "passed": true, "detail": "..."},
    {"step": "role_resolution", "passed": true, "detail": "..."},
    {"step": "rule_fetch", "passed": true, "detail": "..."},
    {"step": "rule_match", "passed": true, "detail": "..."},
    {"step": "taint_check", "passed": true, "detail": "..."}
  ],
  "reason": "Matched rule: allow-file-read (priority 10)",
  "latency_ms": 2,
  "policy_version": "current"
}
```

### POST /v1/simulate/compare

Run the same request against two policy rule sets and diff the results.

**Request Body:**

```json
{
  "agent_id": "agent-assistant",
  "tool_name": "file.read",
  "tool_args": {"path": "/data/report.csv"},
  "version_a_label": "v1.0",
  "version_a_rules": [{"name": "...", "agent_role": ["*"], "tool_pattern": "file.*", "action": "ALLOW", "priority": 10, "enabled": true}],
  "version_b_label": "v1.1",
  "version_b_rules": [{"name": "...", "agent_role": ["reader"], "tool_pattern": "file.*", "action": "ALLOW", "priority": 10, "enabled": true}]
}
```

**Response:**

```json
{
  "decision_changed": true,
  "matched_rule_changed": true,
  "risk_score_changed": false,
  "version_a": { "...full simulation result..." },
  "version_b": { "...full simulation result..." },
  "changes": [
    {"field": "decision", "from": "ALLOW", "to": "DENY"}
  ]
}
```

## Test Vector Library

### GET /v1/simulate/vectors

List available test vectors. Supports filtering by category and tag.

**Query Parameters:**
- `category` — Filter by category (benign, privilege_escalation, injection, data_exfiltration, confused_deputy, taint_bypass)
- `tag` — Filter by tag

### GET /v1/simulate/vectors/categories

List all available test vector categories.

### GET /v1/simulate/vectors/{vector_id}

Get a specific test vector by its ID (e.g., TV-001).

### POST /v1/simulate/vectors/run

Run a suite of test vectors against the current policy configuration.

**Query Parameters:**
- `category` — Run vectors from a specific category
- `tag` — Run vectors matching a specific tag

**Request Body (optional):**
- `vector_ids` — List of specific vector IDs to run

**Response:**

```json
{
  "total": 5,
  "passed": 4,
  "failed": 1,
  "results": [
    {
      "vector_id": "TV-001",
      "name": "Simple read operation",
      "category": "benign",
      "expected_decision": "ALLOW",
      "actual_decision": "ALLOW",
      "passed": true,
      "reason": "Matched rule: allow-read (priority 10)",
      "latency_ms": 1
    }
  ]
}
```

## Test Vector Format

Each test vector is a JSON object:

```json
{
  "vector_id": "TV-001",
  "name": "Simple read operation",
  "category": "benign",
  "description": "Basic file read by a reader agent",
  "request": {
    "agent_id": "agent-reader",
    "tool_name": "file.read",
    "tool_args": {"path": "/data/report.csv"}
  },
  "expected_decision": "ALLOW",
  "tags": ["read", "file"]
}
```

### Categories

| Category | Description |
|----------|-------------|
| `benign` | Normal operations that should be allowed |
| `privilege_escalation` | Attempts to access unauthorized tools |
| `injection` | Prompt injection and role hijack payloads |
| `data_exfiltration` | Attempts to exfiltrate data |
| `confused_deputy` | Delegation chain abuse scenarios |
| `taint_bypass` | Attempts to bypass taint detection |

## CI/CD Integration

### GitHub Action

AgentPEP includes a GitHub Action workflow (`.github/workflows/policy-simulation.yml`) that automatically runs the simulation test vector suite on pull requests that modify policy-related files.

**Triggered on changes to:**
- `backend/app/models/policy.py`
- `backend/app/services/policy_evaluator.py`
- `backend/app/services/rule_matcher.py`
- `backend/app/services/simulation_engine.py`
- `backend/app/api/v1/simulate.py`
- `policy/**`

### Manual Integration

Run the test vector suite in your CI pipeline:

```bash
# Run all test vectors
curl -X POST http://localhost:8000/v1/simulate/vectors/run

# Run specific category
curl -X POST "http://localhost:8000/v1/simulate/vectors/run?category=injection"

# Run specific vectors
curl -X POST http://localhost:8000/v1/simulate/vectors/run \
  -H "Content-Type: application/json" \
  -d '["TV-010", "TV-020", "TV-030"]'
```

### Interpreting Results

The suite returns a `TestVectorSuiteResult` with pass/fail counts. In CI, fail the build if `failed > 0`:

```bash
RESULT=$(curl -s -X POST http://localhost:8000/v1/simulate/vectors/run)
FAILED=$(echo "$RESULT" | jq '.failed')
if [ "$FAILED" -gt 0 ]; then
  echo "Policy simulation suite failed: $FAILED vectors failed"
  exit 1
fi
```

## Simulation Console UI

The frontend includes two simulation screens:

1. **Simulate** (`/simulate`) — Build a tool call request interactively and run it against the current policy stack. View the full evaluation trace including role resolution, rule matching, taint evaluation, and delegation chain validation.

2. **Compare** (`/simulate/compare`) — Enter two sets of policy rules and run the same request against both. View a side-by-side diff of the results.
