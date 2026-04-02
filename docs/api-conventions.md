# API Conventions

## Versioning

All API endpoints are versioned under `/v1/`. Breaking changes require a new version prefix (`/v2/`).

## Request / Response Format

- All request and response bodies use JSON (`application/json`)
- UUIDs are formatted as lowercase hyphenated strings
- Timestamps are ISO 8601 UTC (`2026-04-02T12:00:00Z`)
- Enums are UPPER_SNAKE_CASE strings

## Authentication

- API key via `X-API-Key` header (required)
- mTLS for service-to-service communication (optional, configurable)

## Error Responses

All errors return a consistent JSON structure:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Human-readable description",
    "details": {}
  }
}
```

## HTTP Status Codes

| Code | Usage |
|------|-------|
| 200 | Successful policy evaluation |
| 400 | Invalid request payload |
| 401 | Missing or invalid API key |
| 403 | Forbidden (tenant isolation) |
| 422 | Validation error (Pydantic) |
| 500 | Internal server error |
| 503 | MongoDB unavailable (readiness) |

## Naming Conventions

- Endpoints: `kebab-case` nouns (e.g., `/v1/intercept`, `/v1/policy-rules`)
- Query params: `snake_case`
- JSON fields: `snake_case`
