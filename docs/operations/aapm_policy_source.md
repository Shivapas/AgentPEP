# AAPM as Policy Source — Operator Runbook

**Sprint S-E05 — E05-T10**
**Owner:** TrustFabric Platform Engineering
**Status:** Active from v2.1 onwards

---

## Overview

From Sprint S-E05 onwards, AgentPEP policy is **no longer authored locally**.
All enforcement rules are compiled by the AAPM team into signed Rego bundles
and published via the AAPM Policy Registry.  AgentPEP loads, verifies, and
enforces these bundles; it does not author, edit, or store rules.

This runbook covers:
- How AgentPEP receives bundles from AAPM
- Configuration reference for the bundle URL and polling interval
- Verifying the active bundle version
- Emergency deny-all procedure
- Bundle recovery (restoring a normal bundle after an emergency)
- Troubleshooting common issues

---

## Architecture Summary

```
AAPM Policy Registry
  └─ Publishes signed Rego bundle (bundle.tar.gz + bundle.tar.gz.sig)
       │
       ├─ Webhook push → AgentPEP /api/internal/policy/reload
       │     (immediate; primary delivery mechanism)
       │
       └─ Pull polling every 60 s (ETag-based conditional GET)
             (fallback; activates automatically when webhook is unavailable)

AgentPEP TrustedPolicyLoader
  └─ Verifies Ed25519 signature against pinned AAPM public key
  └─ Unpacks bundle; loads Rego modules into OPA engine
  └─ Updates bundle version tracker (reported in all enforcement events)

OPA Engine (RegoPyEvaluator)
  └─ Evaluates tool call requests against the active Rego bundle
  └─ Produces ALLOW / DENY / MODIFY decisions
```

---

## Configuration Reference

All parameters are set via environment variables prefixed `AGENTPEP_`.

### Bundle URL (required)

| Setting | Environment Variable | Default |
|---------|----------------------|---------|
| `policy_registry_bundle_url` | `AGENTPEP_POLICY_REGISTRY_BUNDLE_URL` | *(must be set)* |

The bundle URL must be on the AAPM registry allowlist
(`https://registry.trustfabric.internal/agentpep/policies/`).  Any other URL
is rejected at startup with a `SECURITY_VIOLATION` event.

**Example:**
```bash
export AGENTPEP_POLICY_REGISTRY_BUNDLE_URL=\
  https://registry.trustfabric.internal/agentpep/policies/global/core_enforcement/latest/bundle.tar.gz
```

### Polling Interval

| Setting | Environment Variable | Default |
|---------|----------------------|---------|
| `policy_poll_interval_s` | `AGENTPEP_POLICY_POLL_INTERVAL_S` | `60` |

Interval between polling attempts in seconds.  Reduce to `10` in staging
environments to speed up bundle update testing.

### Webhook HMAC Secret

| Setting | Environment Variable | Required |
|---------|----------------------|----------|
| *(webhook authentication)* | `AGENTPEP_WEBHOOK_HMAC_SECRET` | Yes (provisioned by AAPM onboarding) |

The webhook receiver (`POST /api/internal/policy/reload`) validates the
HMAC-SHA256 signature in the `X-AAPM-Signature` header.  Requests without a
valid signature are rejected with `403 Forbidden` and a `SECURITY_VIOLATION`
event.

### Debug / Development Override

| Setting | Environment Variable | Effect |
|---------|----------------------|--------|
| `debug` | `AGENTPEP_DEBUG` | Must be `true` for dev key path override |
| *(dev key path)* | `AGENTPEP_POLICY_DEV_PUBLIC_KEY_PATH` | Override pinned key (debug mode only) |

**Never set `AGENTPEP_DEBUG=true` in production.**

---

## Verifying the Active Bundle

### Via enforcement decision log

Every enforcement decision log entry (`GET /api/v1/pdp/decisions`) includes
the `bundle_version` field reflecting the version of the Rego bundle active
at the time of the decision.

```json
{
  "request_id": "req-abc123",
  "tool_name": "read_file",
  "decision": "ALLOW",
  "bundle_version": "1.0.0",
  "latency_ms": 1.2
}
```

### Via policy status endpoint

```bash
GET /api/internal/policy/status
```

Response:
```json
{
  "bundle_version": "1.0.0",
  "bundle_name": "core_enforcement",
  "tenant_id": "global",
  "loaded_at_ms": 1714000000000,
  "source_url": "https://registry.trustfabric.internal/..."
}
```

### Via structured logs

Filter on `event = "policy_bundle_loaded"`:
```
bundle_url=...  version=1.0.0  tenant_id=global  rego_file_count=1  elapsed_s=0.042
```

---

## Triggering a Manual Bundle Reload

To trigger an immediate reload without waiting for the 60-second poll:

```bash
# Using the webhook endpoint (requires HMAC-signed payload):
curl -X POST https://<agentpep-host>/api/internal/policy/reload \
  -H "Content-Type: application/json" \
  -H "X-AAPM-Signature: <hmac-sha256-of-body>" \
  -d '{
    "event": "bundle.published",
    "tenant_id": "global",
    "bundle_name": "core_enforcement",
    "version": "1.1.0",
    "bundle_url": "https://registry.trustfabric.internal/agentpep/policies/global/core_enforcement/1.1.0/bundle.tar.gz",
    "published_at": "2026-04-24T10:00:00Z"
  }'
```

The HMAC-SHA256 signature is computed over the raw JSON body using the shared
secret in `AGENTPEP_WEBHOOK_HMAC_SECRET`.

---

## Emergency Deny-All Procedure

When AAPM publishes an emergency deny-all bundle in response to a critical
security event:

### What happens automatically

1. AAPM publishes `bundle_type=emergency-deny-all` to the Policy Registry.
2. AgentPEP receives the bundle via webhook (immediately) or polling (within
   60 seconds).
3. TrustedPolicyLoader verifies the signature and loads the bundle.
4. All subsequent tool call decisions return DENY.
5. `bundle_version` in enforcement events reflects `emergency-*` version.

**SLA:** Emergency deny-all enforced within 5 minutes (60 s poll + 4 min
network latency budget).  Webhook delivery is immediate.

### Detecting the emergency state

```bash
GET /api/internal/policy/status
```

Response when emergency is active:
```json
{
  "bundle_version": "emergency-1.0.0",
  "bundle_name": "core_enforcement",
  ...
}
```

Or check the bundle manifest for `bundle_type == "emergency-deny-all"`.

### Impact

All agent tool calls will return DENY until a normal bundle is restored.
Affected agents will surface `TOOL_NOT_PERMITTED` errors.  This is intentional
— the emergency deny-all is a circuit breaker for critical security incidents.

### Recovery

AAPM restores the normal bundle by publishing a new version with
`bundle_type=v1-parity` (or later production bundle type).  AgentPEP
automatically loads it via webhook or poll.

**Operator action required:** None, unless the normal bundle is not received
within 10 minutes of the AAPM team's announcement.  If not received:

1. Check `GET /api/internal/policy/status` for current bundle version.
2. Check structured logs for `SECURITY_VIOLATION` or `policy_load_error`
   events.
3. Trigger a manual webhook (see above) pointing to the intended recovery
   bundle URL.

---

## Bundle Version Mismatch Alert

If enforcement decisions show bundle_version older than the version published
by AAPM:

1. Check `GET /api/internal/policy/status` for the loaded version.
2. Check for `policy_load_error` events in structured logs — a signature
   mismatch or HTTP error will prevent reload (FAIL_CLOSED).
3. Check that `AGENTPEP_WEBHOOK_HMAC_SECRET` matches the AAPM-provisioned
   secret — a mismatch causes webhook rejection.
4. Check network connectivity from AgentPEP pods to the AAPM registry URL.

---

## Previous (Pre-S-E05) Policy Configuration

**Deprecated as of Sprint S-E05.**

Before S-E05, policy rules were authored in AgentPEP's local configuration
and evaluated via `PolicyEvaluator` (rule matching against MongoDB rules).
This path is now superseded by the OPA Rego bundle evaluation.

If your deployment uses environment variables or YAML config files that
reference:
- `AGENTPEP_POLICY_URL`
- `AGENTPEP_POLICY_SOURCE`
- `AGENTPEP_POLICY_PATH`
- `AGENTPEP_POLICY_DIR`
- `OPA_BUNDLE_URL`

These are now **blocked at startup** with a `SECURITY_VIOLATION` event.
Remove them from your deployment configuration and use
`AGENTPEP_POLICY_REGISTRY_BUNDLE_URL` instead.

---

## Exit Criteria Checklist (Sprint S-E05)

- [x] First real AAPM-compiled bundle received and loaded successfully
- [x] Parity test: 100% decision match between old imperative rules and AAPM bundle
- [x] E2E integration flow validated: bundle load → enforcement active
- [x] Pull polling and webhook delivery both tested
- [x] Emergency deny-all bundle enforced within SLA (mechanism validated)
- [x] Imperative rule code decommissioned (`RegoNativeEvaluator` removed from production path)
- [x] Operator documentation updated to reflect AAPM as policy source (this document)
