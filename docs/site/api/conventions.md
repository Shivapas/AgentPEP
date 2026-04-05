# API Conventions

## Base URL

```
http://localhost:8000   (development)
https://<tenant>.beta.agentpep.io  (beta)
```

## Versioning

All API endpoints are prefixed with `/v1/`. Breaking changes will result in a new version prefix.

## Authentication

When `AGENTPEP_AUTH_ENABLED=true`, all requests (except `/health`) require an API key:

```
X-API-Key: your-api-key-here
```

## Request/Response Format

- Content-Type: `application/json`
- All timestamps are ISO 8601 UTC (e.g., `2026-04-01T12:00:00Z`)
- Enums use `UPPER_SNAKE_CASE`
- UUIDs are string-formatted (e.g., `"550e8400-e29b-41d4-a716-446655440000"`)

## Error Responses

All errors follow a consistent format:

```json
{
  "detail": "Human-readable error message"
}
```

HTTP status codes:

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 204 | No Content (successful deletion) |
| 400 | Bad Request |
| 401 | Unauthorized (missing/invalid API key) |
| 403 | Forbidden (policy denied) |
| 404 | Not Found |
| 422 | Validation Error |
| 429 | Rate Limited |
| 500 | Internal Server Error |

## Rate Limiting

Rate-limited responses include:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 30
```
