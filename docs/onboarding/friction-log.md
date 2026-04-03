# Beta Friction Log (APEP-213)

Track integration friction points reported by beta customers. Each entry should
capture the issue, customer impact, and resolution status.

## Template

```
### FRICTION-NNN: <short title>
- **Customer:** <tenant-id>
- **Severity:** P0 / P1 / P2 / P3
- **Category:** SDK | API | Console | Docs | Deployment
- **Description:** <what happened>
- **Expected:** <what the customer expected>
- **Resolution:** <how it was fixed or workaround>
- **Status:** Open / In Progress / Resolved
- **Related:** APEP-215 friction item #N
```

## Logged Issues

### FRICTION-001: SDK error messages lack actionable detail
- **Customer:** tenant-alpha
- **Severity:** P1
- **Category:** SDK
- **Description:** `PolicyDeniedError` only shows "DENY" without indicating which rule matched or why
- **Expected:** Error message includes matched rule name and denial reason
- **Resolution:** Enhanced error response to include `matched_rule_id` and detailed `reason` field
- **Status:** Resolved (APEP-215 #1)

### FRICTION-002: No example policies for common use cases
- **Customer:** tenant-alpha
- **Severity:** P2
- **Category:** Docs
- **Description:** Customer needed to write policies from scratch without reference examples
- **Expected:** Library of example policies for common patterns (email, file access, API calls)
- **Resolution:** Added policy examples to documentation site
- **Status:** Resolved (APEP-216)

### FRICTION-003: Policy Console shows placeholder values
- **Customer:** tenant-bravo
- **Severity:** P1
- **Category:** Console
- **Description:** Dashboard shows "--" for all metrics; no real data displayed
- **Expected:** Live metrics from the backend API
- **Resolution:** Connected Dashboard to backend API with live polling
- **Status:** Resolved (APEP-214/215)

### FRICTION-004: No way to test policies without live agent
- **Customer:** tenant-bravo
- **Severity:** P2
- **Category:** SDK
- **Description:** Customer wanted to validate policy rules before deploying to production
- **Expected:** Dry-run or offline testing capability
- **Resolution:** Documented OfflineEvaluator and dry_run mode in quickstart
- **Status:** Resolved (APEP-216)

### FRICTION-005: API returns 500 on malformed tool_args
- **Customer:** tenant-alpha
- **Severity:** P1
- **Category:** API
- **Description:** Sending non-dict `tool_args` causes unhandled server error
- **Expected:** 422 validation error with clear message
- **Resolution:** Added input validation with descriptive error responses
- **Status:** Resolved (APEP-215 #2)

### FRICTION-006: No CORS headers for frontend integration
- **Customer:** tenant-charlie
- **Severity:** P1
- **Category:** API
- **Description:** Browser-based integrations blocked by missing CORS headers
- **Expected:** Configurable CORS policy for beta domains
- **Resolution:** Added CORS middleware with configurable origins
- **Status:** Resolved (APEP-215 #3)

### FRICTION-007: Rate limit errors lack Retry-After header
- **Customer:** tenant-bravo
- **Severity:** P2
- **Category:** API
- **Description:** When rate limited, response doesn't indicate when to retry
- **Expected:** Standard `Retry-After` header in 429 responses
- **Resolution:** Added Retry-After header to rate limit responses
- **Status:** Resolved (APEP-215 #4)

### FRICTION-008: Audit log not queryable
- **Customer:** tenant-alpha
- **Severity:** P2
- **Category:** API
- **Description:** No API to query past decisions for debugging
- **Expected:** Audit log query endpoint with filtering
- **Resolution:** Added GET /v1/audit endpoint with filtering
- **Status:** Resolved (APEP-215 #5)

### FRICTION-009: SDK timeout error not distinguishable from connection error
- **Customer:** tenant-charlie
- **Severity:** P3
- **Category:** SDK
- **Description:** Both timeout and connection errors produce similar messages
- **Expected:** Clear distinction between timeout vs connection failure
- **Resolution:** Already separate exception types; improved error messages
- **Status:** Resolved (APEP-215 #6)

### FRICTION-010: No health check in SDK
- **Customer:** tenant-bravo
- **Severity:** P2
- **Category:** SDK
- **Description:** No way to verify SDK can reach the server before first policy call
- **Expected:** `client.health_check()` method
- **Resolution:** Added `health_check()` and `health_check_sync()` methods to SDK client
- **Status:** Resolved (APEP-215 #7)
