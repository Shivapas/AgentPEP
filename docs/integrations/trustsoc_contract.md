# TrustSOC Integration Contract
## AgentPEP PostToolUse Event Stream → TrustSOC SIEM

**Version:** 1.0  
**Sprint:** S-E07 (E07-T08)  
**Status:** Signed-off  
**Author:** TrustFabric Product Architecture  
**Date:** April 2026  

---

## 1. Purpose

This document defines the integration contract between **AgentPEP** (event producer) and **TrustSOC** (SIEM consumer) for the PostToolUse event stream.  It specifies the Kafka topic, OCSF event schema, delivery SLA, authentication, HMAC verification, and escalation procedures.

---

## 2. Parties

| Party | Role | Contact |
|-------|------|---------|
| AgentPEP (TrustFabric) | Event producer | agentpep-team@trustfabric.internal |
| TrustSOC | SIEM consumer / alerting | trustsoc-team@trustfabric.internal |

---

## 3. Event Stream

### 3.1 Kafka Topic

| Parameter | Value |
|-----------|-------|
| Topic | `agentpep.posttooluse.events` |
| Partition key | `sequence_id` (derived from `ToolCallRequest.request_id`) |
| Serialization | JSON (UTF-8) |
| Compression | None (recommended: LZ4 at broker level) |
| Retention | 7 days (configurable by TrustSOC team) |
| Replication factor | 3 (production) |

### 3.2 When Events Are Emitted

A PostToolUse event is emitted for **every tool call evaluation** — both ALLOW decisions (where the tool ran) and DENY decisions (where the tool was blocked).  This guarantees TrustSOC receives a complete audit trail with no gaps.

### 3.3 Delivery SLA

| Metric | Target |
|--------|--------|
| Kafka publish latency (P99) | ≤ 500 ms after tool call completes |
| Missed events (transient Kafka failure) | Logged; not retried (fire-and-forget) |
| Event ordering | Per-session ordering guaranteed via partition key |

**Note:** PostToolUse event publication is non-blocking.  A Kafka failure logs a warning but never blocks the enforcement decision pipeline.

---

## 4. OCSF Event Schema

All events conform to the **TrustFabric OCSF Profile v1.0** (`profile: "TrustFabric/AgentPEP/v1.0"`).

### 4.1 PostToolUse Event (class_uid: 4001)

```json
{
  "class_uid": 4001,
  "class_name": "TOOL_ACTIVITY",
  "category_uid": 4,
  "category_name": "FINDINGS",
  "activity_id": 1,
  "activity_name": "EXECUTE",
  "severity_id": 1,
  "severity": "INFO",
  "type_uid": 400101,
  "time": 1714000000000,
  "start_time": 1713999999500,
  "metadata": {
    "version": "1.0.0",
    "product": {
      "name": "AgentPEP",
      "vendor_name": "TrustFabric"
    },
    "event_code": "POSTTOOLUSE",
    "profile": "TrustFabric/AgentPEP/v1.0",
    "bundle_version": "core_enforcement@sha256:abc123",
    "hmac_signature": "<HMAC-SHA256 hex digest>",
    "hmac_algorithm": "HMAC-SHA256"
  },
  "actor": {
    "agent_id": "agent-prod-001",
    "session_id": "sess-abc123",
    "tenant_id": "acme-corp",
    "delegation_chain": ["root-agent", "sub-agent-1", "agent-prod-001"]
  },
  "resources": [
    {
      "type": "tool_call",
      "name": "bash",
      "uid": "550e8400-e29b-41d4-a716-446655440000"
    }
  ],
  "observables": [
    {
      "name": "sequence_id",
      "value": "550e8400-e29b-41d4-a716-446655440000",
      "type": "Resource UID"
    }
  ],
  "finding_info": {
    "title": "PostToolUse event for tool 'bash'",
    "uid": "550e8400-e29b-41d4-a716-446655440000",
    "sequence_id": "550e8400-e29b-41d4-a716-446655440000",
    "related_events": ["550e8400-e29b-41d4-a716-446655440000"]
  },
  "decision": "ALLOW",
  "tool_outcome": "EXECUTED",
  "risk_score": 0.23,
  "taint_flags": ["UNTRUSTED"],
  "matched_rule_id": "rule-deny-shell-003",
  "latency_ms": 4,
  "tool_name": "bash",
  "tool_args_included": false,
  "tool_result_summary": null,
  "tool_result_error": null,
  "blast_radius_score": null
}
```

### 4.2 Activity ID Reference

| activity_id | activity_name | Meaning | severity_id |
|-------------|---------------|---------|-------------|
| 1 | EXECUTE | Tool ran after ALLOW decision | 1 (INFO) |
| 2 | DENY | Tool blocked before execution | 3 (HIGH) |
| 3 | ERROR | Tool ran but threw an exception | 3 (HIGH) |
| 4 | TIMEOUT | Tool or evaluation timed out | 3 (HIGH) |

### 4.3 type_uid Derivation

`type_uid = class_uid * 100 + activity_id`

| Outcome | type_uid |
|---------|----------|
| EXECUTE | 400101 |
| DENY | 400102 |
| ERROR | 400103 |
| TIMEOUT | 400104 |

### 4.4 Related Event Classes

| class_uid | class_name | Producer module |
|-----------|------------|-----------------|
| 4001 | TOOL_ACTIVITY (PostToolUse) | `app.events.post_tool_use_event` |
| 4002 | SECURITY_VIOLATION | `app.policy.events` |
| 4002 | TRUST_VIOLATION | `app.trust.events` |
| 4003 | COMPLEXITY_EXCEEDED | `app.enforcement.complexity_budget` |

All events in class 4002 and 4003 also carry `sequence_id` and HMAC signatures as of Sprint S-E07.

---

## 5. Sequence ID — Pre/PostToolUse Correlation

The `sequence_id` field (derived from `ToolCallRequest.request_id`) links the PreToolUse enforcement decision with the PostToolUse completion event for the same tool invocation.

TrustSOC consumers can join events on `sequence_id` to reconstruct the full lifecycle:

```
PreToolUse decision event  → sequence_id = "550e8400..."
PostToolUse completion event → sequence_id = "550e8400..."  (same UUID)
```

The `sequence_id` appears in:
- `finding_info.sequence_id`
- `finding_info.uid`
- `resources[0].uid`
- `observables[0].value`

---

## 6. Tamper-Evident Event Signing

### 6.1 HMAC-SHA256

Every AgentPEP OCSF event is signed with HMAC-SHA256 using a shared secret configured via `AGENTPEP_POSTTOOLUSE_HMAC_KEY`.

**Signing procedure:**
1. Serialize the event to canonical JSON (keys sorted, no extra whitespace).
2. Exclude `metadata.hmac_signature` and `metadata.hmac_algorithm` from the canonical body.
3. Compute `HMAC-SHA256(canonical_body, key)`.
4. Store hex digest as `metadata.hmac_signature`.

**Verification procedure (TrustSOC):**
1. Read and store `metadata.hmac_signature`.
2. Remove `hmac_signature` and `hmac_algorithm` from the metadata copy.
3. Re-serialize to canonical JSON.
4. Compute `HMAC-SHA256(canonical_body, shared_key)`.
5. Compare using constant-time comparison.

### 6.2 Key Distribution

The HMAC shared key is provided to TrustSOC via the organization's secrets management system (HashiCorp Vault, AWS Secrets Manager, or equivalent).  Keys are rotated quarterly or on any suspected compromise.

### 6.3 Unsigned Events

If `metadata.hmac_signature` is absent, the event is unsigned (AgentPEP was deployed without `AGENTPEP_POSTTOOLUSE_HMAC_KEY`).  TrustSOC **should** alert on unsigned events in production deployments.

---

## 7. blast_radius_score Field

The `blast_radius_score` field is present in all PostToolUse events but set to `null` until Sprint S-E08 integrates the AAPM Blast Radius Calculator API.

**From S-E08 onwards:**
- `blast_radius_score` is a float in `[0.0, 1.0]`
- Populated at session initialization from the AAPM Blast Radius API
- Propagated to all PostToolUse events for the session
- A score ≥ 0.75 triggers posture elevation in the enforcement matrix

TrustSOC **should** alert when `blast_radius_score >= 0.75` (even during the S-E08 placeholder period, when this condition cannot occur).

---

## 8. TrustSOC Alerting Recommendations

| Condition | Recommended Alert |
|-----------|-------------------|
| `class_name = "SECURITY_VIOLATION"` | P1 — Immediate SOC notification |
| `class_name = "TRUST_VIOLATION"` AND `reason = "PERMISSION_ESCALATION"` | P1 — Potential lateral movement |
| `class_name = "COMPLEXITY_EXCEEDED"` | P2 — Adversarial input investigation |
| `tool_outcome = "DENY"` AND `risk_score >= 0.8` | P2 — High-risk denial |
| `blast_radius_score >= 0.75` (from S-E08) | P1 — Elevated impact agent |
| `metadata.hmac_signature` absent in production | P1 — Unsigned event stream |
| `class_name = "TOOL_ACTIVITY"` AND `taint_flags` includes `"QUARANTINE"` | P2 — Quarantine-tainted tool call |

---

## 9. Kafka Consumer Configuration (TrustSOC)

```properties
# Recommended consumer group
group.id=trustsoc-agentpep-posttooluse

# Auto-offset reset (start from earliest for replay capability)
auto.offset.reset=earliest

# Disable auto-commit — commit only after SIEM ingestion confirmed
enable.auto.commit=false

# Session timeout (must be > max.poll.interval.ms)
session.timeout.ms=30000
max.poll.interval.ms=60000

# Max records per poll (tune based on SIEM ingestion capacity)
max.poll.records=500
```

---

## 10. Schema Versioning

| Schema Version | Sprint | Changes |
|----------------|--------|---------|
| 1.0.0 | S-E07 | Initial PostToolUse schema; HMAC signing; sequence_id; blast_radius_score placeholder |
| 1.1.0 | S-E08 (planned) | blast_radius_score populated; posture field added |

Schema changes are backwards-compatible within a minor version.  Breaking changes increment the major version and require a migration window.

---

## 11. Operational Procedures

### 11.1 Missing Events

If TrustSOC detects a gap in the PostToolUse event stream:

1. Check AgentPEP logs for `posttooluse_kafka_publish_error`.
2. Verify Kafka broker health and topic availability.
3. Check `agentpep.posttooluse.events` consumer group lag.
4. If gap exceeds 5 minutes, escalate to AgentPEP on-call.

### 11.2 HMAC Verification Failures

If TrustSOC detects events with invalid HMAC signatures:

1. Verify the shared key is current (not stale after rotation).
2. Check for event serialization changes in AgentPEP (see release notes).
3. If neither applies, escalate as a potential event stream tampering incident.

### 11.3 Schema Validation

TrustSOC should run the AgentPEP OCSF schema linter on sampled events:

```bash
python -m app.events.ocsf_linter <event.json>
```

Or import for programmatic use:

```python
from app.events.ocsf_linter import assert_valid
assert_valid(event)  # Raises OCSFLintError on violation
```

---

## 12. Sign-off

| Role | Name | Date |
|------|------|------|
| AgentPEP Engineering Lead | Shiv (TrustFabric) | April 2026 |
| TrustSOC Integration Lead | (TrustSOC team) | _Pending_ |
| Security Architecture | (Security Arch) | _Pending_ |

---

*Document Owner: TrustFabric Product Architecture*  
*Next Review: Sprint S-E08 kickoff (blast_radius_score activation)*  
*Distribution: Internal — AgentPEP Engineering, TrustSOC, Security Architecture*
