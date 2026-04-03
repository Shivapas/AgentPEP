# Console API

Endpoints that power the Policy Console UI.

## GET /v1/stats

Dashboard statistics.

```json
{
  "policy_rules": 12,
  "decisions_today": 1543,
  "active_agents": 5,
  "deny_rate": 0.082,
  "avg_latency_ms": 4,
  "escalations_pending": 2
}
```

## GET /v1/audit

Query the audit decision log.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `decision` | string | - | Filter by decision type (ALLOW, DENY, etc.) |
| `agent_id` | string | - | Filter by agent ID |
| `tool_name` | string | - | Filter by tool name (substring match) |
| `limit` | int | 50 | Max results (1-500) |
| `offset` | int | 0 | Pagination offset |

```json
{
  "items": [...],
  "total": 1543
}
```

## GET /v1/rules

List all policy rules sorted by priority.

```json
{
  "items": [...],
  "total": 12
}
```

## GET /v1/agents

List all agent profiles.

```json
{
  "items": [...],
  "total": 5
}
```

## POST /v1/ux-survey

Submit a UX survey (SUS) response.

```json
{
  "responses": [4, 2, 5, 1, 4, 2, 5, 1, 4, 2],
  "score": 82.5,
  "additional_feedback": "Great product!",
  "timestamp": "2026-04-01T12:00:00Z"
}
```
