# Backend Security & Code Review

**Date:** 2026-04-05
**Scope:** All 96 files in `/backend/` — core, API routes, services, middleware, models, tests
**Branch:** `claude/review-backend-UId1v`

## Executive Summary

Comprehensive review of the AgentPEP backend identified **~70 issues**: **13 CRITICAL**, **19 HIGH**, **22 MEDIUM**, **16 LOW**.

The most systemic problem is **missing authentication/authorization on nearly all API endpoints**. Beyond that, there are significant issues with secret management, race conditions, SSRF, and data integrity.

---

## CRITICAL (13)

### 1. No Authentication on Policy CRUD Endpoints
- **File:** `app/api/v1/policy.py:70-256`
- **Impact:** Unauthenticated users can create/update/delete roles and rules, reorder rules, and view conflicts.
- **Fix:** Add `Depends(get_current_user)` + role-based access control requiring Admin role.

### 2. No Authentication on Audit Endpoints
- **File:** `app/api/v1/audit.py:93-502`
- **Impact:** Entire audit log (decisions, exports, hash chain verification) exposed to unauthenticated access.
- **Fix:** Add authentication and restrict by tenant context + user role.

### 3. No Authentication on Escalation Endpoints
- **File:** `app/api/v1/escalation.py:60-181`
- **Impact:** Anyone can list, approve, or bulk-approve pending escalation tickets for dangerous tool calls.
- **Fix:** Add authentication; restrict resolution to users with "Escalations:Approve" permission.

### 4. No Authentication on Dashboard REST Endpoints
- **File:** `app/api/v1/dashboard.py:320-382`
- **Impact:** Security metrics exposed (WebSocket has auth but REST does not). Helps attackers understand detection sensitivity.
- **Fix:** Add authentication matching WebSocket protection.

### 5. No Authentication on Compliance Report Endpoints
- **File:** `app/api/v1/compliance.py:32-103`
- **Impact:** Report generation, download, and schedule management completely unauthenticated.
- **Fix:** Add auth + restrict to compliance officer role.

### 6. Hardcoded Default JWT Secret
- **File:** `app/core/config.py:43`
- **Impact:** Default `"change-me-in-production"` only logs a warning. Allows token forgery if env var unset.
- **Fix:** Raise exception on startup when `debug=False` and secret is default. Require min 32 chars.

### 7. Seed Endpoint with Default Credentials
- **File:** `app/api/v1/console_auth.py:126-149`
- **Impact:** `/v1/console/seed` creates `admin/admin` account. Hidden from docs but still callable.
- **Fix:** Remove endpoint or restrict to localhost + require explicit config flag.

### 8. Insecure gRPC Server
- **File:** `app/grpc_service.py:82`
- **Impact:** `add_insecure_port()` — all policy decisions transmitted without TLS.
- **Fix:** Use `add_secure_port()` with certificate loading.

### 9. OTLP Telemetry Unencrypted
- **File:** `app/core/observability.py:135`
- **Impact:** `insecure=True` sends tracing data (request metadata, decisions) unencrypted.
- **Fix:** Set `insecure=False` by default; only allow in dev.

### 10. CSRF Bypass on First POST
- **File:** `app/middleware/security.py:135-138`
- **Impact:** If no CSRF cookie exists, POST requests pass through completely unvalidated.
- **Fix:** Require CSRF token on all state-changing requests. Generate during login, not lazily on GET.

### 11. Rate Limit Bypass via X-Forwarded-For Spoofing
- **File:** `app/middleware/security.py:240-247`
- **Impact:** Trusts `X-Forwarded-For` without validating source. Attacker changes IP per request.
- **Fix:** Only trust header from configured trusted proxy IPs.

### 12. SSRF via Unvalidated MCP Upstream URL
- **File:** `app/services/mcp_proxy.py:66,219-251`
- **Impact:** No allowlist on `upstream_url`. Attacker can reach internal services via `file://`, `gopher://`, etc.
- **Fix:** Validate URL against allowlist of permitted hosts.

### 13. Race Condition in Rate Limiter Sliding Window
- **File:** `app/services/rate_limiter.py:69-81`
- **Impact:** Non-atomic `find_one_and_update` query allows concurrent requests to bypass rate limits.
- **Fix:** Use atomic counter per key or fixed-window with explicit bucket calculation.

---

## HIGH (19)

### 14. Auth Disabled by Default
- **File:** `app/core/config.py:39-40`
- **Impact:** `auth_enabled=False`, `mtls_enabled=False`. No enforcement in production mode.
- **Fix:** Default `auth_enabled=True` when `debug=False`.

### 15. API Keys Stored and Compared in Plaintext
- **File:** `app/middleware/auth.py:43-74`
- **Impact:** No format validation, no hashing, timing attack possible via MongoDB string comparison.
- **Fix:** Store `sha256(key)` in DB, use `secrets.compare_digest()`.

### 16. Tenant ID Spoofing
- **File:** `app/services/policy_evaluator.py:320-321`
- **Impact:** Falls back to `request.tenant_id` if `_authenticated_tenant_id` unset by middleware.
- **Fix:** Require `_authenticated_tenant_id` or raise; never fall back to request body.

### 17. `threading.Lock` in Async Context
- **File:** `app/services/audit_logger.py:57-88`
- **Impact:** Synchronous lock doesn't protect concurrent async tasks. Sequence/hash corruption possible.
- **Fix:** Use `asyncio.Lock()` with `async with`.

### 18. Silent Taint Bypass for Uninitialized Sessions
- **File:** `app/services/taint_graph.py:538-540`
- **Impact:** Returns empty list for unknown sessions — all taint checks silently pass.
- **Fix:** Log security alert or deny by default for uninitialized sessions.

### 19. Silent Taint Skip in MCP Session Tracker
- **File:** `app/services/mcp_session_tracker.py:116-126`
- **Impact:** Missing sessions return `[]` without warning; taint checks skipped.
- **Fix:** Log warning; consider deny-by-default.

### 20. TOCTOU Race in WebSocket Broadcast
- **File:** `app/services/escalation_manager.py:69-86`
- **Impact:** Connections removed between snapshot and send; dead connections linger.
- **Fix:** Send within the lock scope.

### 21. Elasticsearch Plaintext Credentials + Silent Data Loss
- **File:** `app/services/compliance/elastic_writer.py:61-62,134-145`
- **Impact:** Passwords in plaintext; bulk index partial failures silently dropped.
- **Fix:** Use env vars for secrets; implement dead-letter queue for failed records.

### 22. DNS Rebinding Bypasses Webhook SSRF Protection
- **File:** `app/models/policy.py:347-373`
- **Impact:** Validates IP at config time only. Attacker's domain resolves to internal IP at request time.
- **Fix:** Re-validate resolved IP immediately before making webhook HTTP request.

### 23. Invalid Escalation Timeout Actions Accepted
- **File:** `app/models/policy.py:289-292`
- **Impact:** `timeout_action` accepts `PENDING`/`TIMEOUT`, not just `APPROVED`/`DENIED`.
- **Fix:** Create separate `EscalationTimeoutAction` enum with only valid values.

### 24. Missing Email Validation in ConsoleUser
- **File:** `app/models/console_user.py:18-28`
- **Impact:** Any string accepted as email; no password hash constraints.
- **Fix:** Use `pydantic.EmailStr`; add `min_length` on `hashed_password`.

### 25. Proto Missing `tenant_id` Field
- **File:** `proto/intercept.proto:6-14`
- **Impact:** Proto and Python model out of sync. Multi-tenant rate limits break for gRPC clients.
- **Fix:** Add `string tenant_id = 5;` to `ToolCallRequest`.

### 26. No Validation on Rule Reorder
- **File:** `app/api/v1/policy.py:200-209`
- **Impact:** Missing IDs, duplicates, non-existent IDs silently accepted — corrupts rule ordering.
- **Fix:** Validate provided IDs match existing rules exactly.

### 27. Unvalidated Policy Version Restore
- **File:** `app/api/v1/policy.py:332-360`
- **Impact:** No approval, no audit log, no integrity check on restore.
- **Fix:** Require admin role, log action, verify version integrity.

### 28. API Keys Stored in Plaintext in MongoDB
- **File:** `app/api/v1/agents.py:240-295`
- **Impact:** Database compromise exposes all API keys.
- **Fix:** Store hash only; display key once on generation.

### 29. MCP Session Hijacking via Client-Supplied IDs
- **File:** `app/api/v1/mcp.py:79-140`
- **Impact:** No ownership verification on session IDs. Cross-agent session hijacking possible.
- **Fix:** Verify `existing.agent_id == request.agent_id` before reuse.

### 30. IDOR on Taint Session Endpoints
- **File:** `app/api/v1/taint.py:183-446`
- **Impact:** No ownership check. Any user can access/modify any session's taint graph.
- **Fix:** Implement session ownership verification.

### 31. No Pagination Cap on Audit Export
- **File:** `app/api/v1/audit.py:170-199`
- **Impact:** 50K records loaded into memory at once. Memory exhaustion under load.
- **Fix:** Implement streaming export with chunked responses.

### 32. Fixed 10-Thread gRPC Pool
- **File:** `app/grpc_service.py:69`
- **Impact:** Bottleneck under high throughput; blocks legitimate requests.
- **Fix:** Use `grpc.aio.server()` or appropriately sized pool.

---

## MEDIUM (22)

| # | File:Lines | Issue |
|---|-----------|-------|
| 33 | `services/rule_cache.py:74-76` | Incomplete Redis error handling — `_redis` not guaranteed `None` |
| 34 | `services/kafka_producer.py:58-77` | Fire-and-forget audit publishing — failures silently swallowed |
| 35 | `services/risk_scoring.py:37-55` | ReDoS potential in verb regex on adversarial input |
| 36 | `services/risk_scoring.py:111-120` | PII false positives — `\b\d{12,16}\b` matches timestamps |
| 37 | `services/confused_deputy.py:469-486` | Implicit delegation alert emission failure unhandled |
| 38 | `services/policy_evaluator.py:99-105` | Audit queue drops records on `QueueFull` — compliance data loss |
| 39 | `services/policy_evaluator.py:139-150` | Broad `except Exception` masks bugs |
| 40 | `services/jwt_auth.py:13,54-56` | In-memory token revocation — lost on restart, not shared |
| 41 | `services/compliance/report_scheduler.py:153` | SMTP 5s timeout too short |
| 42 | `services/compliance/splunk_forwarder.py:104` | Token visible in headers, could leak in logs |
| 43 | `middleware/security.py:198-228` | Rate limit check-then-append race |
| 44 | `middleware/security.py:49-59` | Hardcoded strict CSP — not configurable for dev |
| 45 | `models/simulation.py:13-30` | No size limits on `tool_args` or `policy_rules` |
| 46 | `db/mongodb.py:39-44` | No cleanup on abnormal termination |
| 47 | `Dockerfile:6` | Installs `.[dev]` in production image |
| 48 | `api/v1/policy.py:362-386` | No state machine for version transitions |
| 49 | `api/v1/policy.py:416-451` | No size limit on YAML import payload |
| 50 | `api/v1/agents.py:265-344` | No audit logging on API key operations |
| 51 | `api/v1/simulate.py:67-80` | No timeout on simulation evaluation |
| 52 | `api/v1/mcp.py:79-139` | No session TTL — disconnected sessions leak memory |
| 53 | `api/v1/console.py:43-91` | Stats endpoint unauthenticated |
| 54 | `main.py:140-157` | Middleware ordering — CSRF before auth |

## LOW (16)

| # | File:Lines | Issue |
|---|-----------|-------|
| 55 | `services/rule_matcher.py:92-96` | Invalid regex silently ignored |
| 56 | `services/mcp_message_parser.py:197-219` | `_parse_error` field never checked |
| 57 | `services/rule_cache.py:133-141` | `is_warm` not atomic |
| 58 | `core/observability.py:121-142` | OTLP always active even without endpoint |
| 59 | `core/structured_logging.py:114-137` | `root.handlers.clear()` may interfere with 3rd-party |
| 60 | `middleware/security.py:207-226` | Rate limit rejections not logged as metrics |
| 61 | `models/policy.py:91-98` | No upper bounds on `RateLimit.count`/`window_s` |
| 62 | `tests/conftest.py:29-103` | Inconsistent state cleanup — flakiness risk |
| 63 | `tests/test_intercept.py` | Missing edge cases: timeout, empty args, null values |
| 64 | `tests/test_rbac_engine.py` | No circular hierarchy tests |
| 65 | `tests/test_console.py` | No auth/authz tests |
| 66 | `api/v1/simulate.py:138` | Dead code: redundant HTTPException import |
| 67 | `api/v1/dashboard.py:56-59` | `utcnow()` vs `now(UTC)` inconsistency |
| 68 | `api/v1/escalation.py:188-215` | `CancelledError` silently swallowed |
| 69 | Multiple files | Inconsistent error message formatting |
| 70 | Multiple models | Inconsistent timezone handling |

---

## Recommended Fix Priority

### Immediate (before any deployment)
1. Add authentication to all API endpoints (#1-5)
2. Fix JWT secret handling — refuse startup with default (#6)
3. Remove or lock down `/v1/console/seed` (#7)
4. Enable TLS for gRPC (#8) and OTLP (#9)
5. Fix CSRF bypass (#10)

### High Priority
6. Hash API keys at rest (#15, #28)
7. Fix tenant ID spoofing (#16)
8. Use `asyncio.Lock` instead of `threading.Lock` (#17)
9. Validate webhook URLs at request time (#22)
10. Add session ownership checks for MCP and taint (#29, #30)

### Before Production
11. Validate X-Forwarded-For against trusted proxy list (#11)
12. Fix rate limiter race condition (#13)
13. Implement persistent token revocation (#40)
14. Add audit logging for key management (#50)
15. Remove dev dependencies from production Dockerfile (#47)
