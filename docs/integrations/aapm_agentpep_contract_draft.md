# AAPM → AgentPEP Integration Contract (Draft)

**Document ID:** INT-001
**Status:** Draft — Pending AAPM Team Review
**Sprint:** S-E01 (E01-T06)
**Owner:** TrustFabric Product Architecture (AgentPEP)
**Counterparty:** AAPM Team (Policy Management)
**Date:** April 2026
**Review Required By:** End of Sprint S-E01

---

## 1. Purpose

This document defines the integration contract between the AAPM (AI Agent Policy Management) system and AgentPEP. It specifies the interface through which AAPM publishes signed Rego policy bundles and AgentPEP consumes them, including: registry endpoint, authentication, bundle naming, delivery mechanism, update latency SLAs, and emergency revocation procedures.

This contract governs Sprint S-E03 (Trusted Policy Loader) and Sprint S-E05 (first bundle parity test).

---

## 2. Architectural Boundary (Restatement)

```
AAPM (Policy Author + Lifecycle Manager)
│  Policy authoring: APDL language
│  PCR (Policy Change Request) workflow
│  Bundle compilation: APDL → Rego
│  Bundle signing: cosign (AAPM holds private key)
│  Bundle publication: pushes to Policy Registry
│  Audit trail: policy changes logged in AAPM
│  Blast Radius Calculator: Neo4j (AAPM Sprint 12)
│
│  PUBLISHES TO:
│         ↓
│   TrustFabric Policy Registry
│         ↓
▼
AgentPEP (Policy Consumer + Runtime Enforcer)
│  Policy loading: pulls from registry URL only
│  Integrity verification: cosign signature check (public key pinned)
│  Runtime evaluation: OPA/Rego engine (embedded)
│  Enforcement decision log: per-evaluation, includes bundle version
│  Emergency handling: loads emergency bundle within 5-minute SLA
```

AgentPEP does not author, compile, sign, version, or maintain an audit trail of policy bundles. AAPM does not evaluate tool calls or emit enforcement decision events. Neither system duplicates the other's responsibilities.

---

## 3. Policy Registry Endpoint

### 3.1 Base URL

```
https://registry.trustfabric.internal/agentpep/policies/
```

This URL is the **only** allowlisted policy source for AgentPEP. It is a compile-time constant in the AgentPEP binary. It cannot be overridden at runtime by operator configuration, environment variable, or CLI flag.

### 3.2 TLS Configuration

- TLS 1.3 minimum
- Server certificate pinned to TrustFabric internal CA
- Certificate rotation: AAPM team notifies AgentPEP team ≥14 days before rotation; AgentPEP releases binary update with new pinned cert

### 3.3 Authentication

- AgentPEP authenticates to the registry using a service account token issued by AAPM
- Token format: JWT signed by AAPM identity service
- Token rotation: 24-hour validity; AgentPEP auto-renews using a long-lived refresh token stored in the operator keystore
- AAPM provisions the initial service account and refresh token during AgentPEP onboarding

---

## 4. Bundle Naming Convention

### 4.1 Bundle Path Format

```
/agentpep/policies/{tenant_id}/{bundle_name}/{version}/bundle.tar.gz
```

**Fields:**
- `tenant_id`: UUID identifying the customer tenant (or `global` for platform-wide bundles)
- `bundle_name`: Logical policy bundle name (e.g., `core_enforcement`, `taint_rules`, `posture_matrix`)
- `version`: Semantic version string (e.g., `1.4.2`)

**Example:**
```
/agentpep/policies/global/core_enforcement/1.4.2/bundle.tar.gz
```

### 4.2 Latest Bundle Redirect

```
/agentpep/policies/{tenant_id}/{bundle_name}/latest/bundle.tar.gz
```

AgentPEP resolves `latest` at load time. The resolved version is stored in memory and reported in all enforcement decision events.

### 4.3 Bundle Format

- Archive format: `.tar.gz`
- Contents: Rego policy files, `data.json`, `.manifest`
- Signature: cosign signature file at same path with `.sig` suffix

```
bundle.tar.gz
bundle.tar.gz.sig
```

---

## 5. Bundle Delivery Mechanism

AgentPEP supports two delivery modes. Both are implemented; webhook is preferred and polling is the fallback.

### 5.1 Webhook Push (Primary)

AAPM pushes a notification to AgentPEP when a new bundle is published. AgentPEP then fetches the new bundle from the registry.

**Webhook endpoint (AgentPEP side):**
```
POST https://{agentpep_host}/api/internal/policy/reload
```

**Request payload:**
```json
{
  "event": "bundle.published",
  "tenant_id": "string",
  "bundle_name": "string",
  "version": "string",
  "bundle_url": "https://registry.trustfabric.internal/agentpep/policies/...",
  "published_at": "ISO8601",
  "signature_url": "https://registry.trustfabric.internal/agentpep/policies/.../.sig"
}
```

**Authentication:** AAPM signs webhook payload with a shared HMAC secret provisioned during onboarding. AgentPEP verifies HMAC before processing.

**AgentPEP response:**
- `202 Accepted` — bundle reload initiated; current bundle remains active until new bundle passes cosign verification
- `400 Bad Request` — malformed payload
- `403 Forbidden` — HMAC verification failure (AAPM investigates; SECURITY_VIOLATION event emitted by AgentPEP)

**Delivery guarantee:** AAPM retries webhook delivery with exponential backoff (2s, 4s, 8s, 16s) up to 5 attempts. If all attempts fail, AgentPEP picks up the update via polling (see 5.2).

### 5.2 Pull Polling (Fallback)

AgentPEP polls the registry every **60 seconds** for a new bundle version.

**Poll request:**
```
GET /agentpep/policies/{tenant_id}/{bundle_name}/latest/bundle.tar.gz
If-None-Match: {current_bundle_etag}
```

**Registry response:**
- `304 Not Modified` — bundle unchanged; no reload
- `200 OK` — new bundle available; AgentPEP proceeds with cosign verification and reload

**When polling is active:** Always running as a fallback. If webhook delivery succeeds, the next poll cycle finds the bundle already loaded (304 Not Modified) and is a no-op.

---

## 6. Bundle Rollout SLA

| Event | SLA |
|---|---|
| Normal policy update: PCR approved → bundle active in AgentPEP | 5 minutes |
| Emergency deny-all bundle: published → active in AgentPEP | 5 minutes |
| Webhook unavailable: new bundle → active via polling | 60 seconds (next poll cycle) |

**5-minute SLA definition:** Measured from AAPM bundle publication timestamp to AgentPEP enforcement decision log first recording the new bundle version. AAPM monitoring validates the publication timestamp; AgentPEP monitoring validates the first enforcement decision log entry.

---

## 7. Emergency Revocation Procedure

### 7.1 Emergency Deny-All Bundle

AAPM can publish a special `deny_all` bundle that causes AgentPEP to DENY all tool calls for the affected tenant.

**Trigger conditions:**
- Active security incident involving an AAPM-managed agent
- Policy corruption detected in the registry
- Directed by security leadership

**Procedure:**
1. AAPM security team publishes `deny_all` bundle to registry under tenant (or `global`)
2. AAPM sends webhook push to AgentPEP with `bundle_name: "deny_all"`
3. AgentPEP receives, verifies cosign signature, loads bundle within 5-minute SLA
4. All tool calls DENIED; `EMERGENCY_DENY_ALL` event emitted to TrustSOC
5. AAPM team monitors enforcement decision log to confirm bundle is active

**Recovery:** AAPM publishes the restored bundle; AgentPEP reloads via normal update flow.

### 7.2 Specific Rule Revocation

AAPM publishes an updated bundle with the specific rule removed or modified. Normal 5-minute SLA applies.

### 7.3 AgentPEP Emergency Contact

| Situation | Contact |
|---|---|
| AgentPEP webhook unreachable | AgentPEP oncall — pager alert triggered by AAPM webhook failure |
| AgentPEP not loading new bundle within SLA | AgentPEP oncall + TrustSOC alert |
| cosign verification failure on AAPM bundle | AgentPEP logs SECURITY_VIOLATION; AAPM team notified via event stream |

---

## 8. Blast Radius API Integration (S-E08 Dependency)

AAPM's Blast Radius Calculator (Neo4j, Sprint 12) exposes an API consumed by AgentPEP at session initialisation.

**Endpoint:**
```
GET https://api.aapm.trustfabric.internal/v1/blast-radius?session_id={session_id}&agent_id={agent_id}
```

**Response:**
```json
{
  "blast_radius_score": 0.73,
  "calculated_at": "ISO8601",
  "session_id": "string"
}
```

**FAIL_CLOSED behaviour (AgentPEP):** If the Blast Radius API is unavailable or returns an error, AgentPEP defaults `blast_radius_score = 1.0` (maximum blast radius), which elevates the posture to the most restrictive tier.

**Availability dependency:** This integration is blocked until AAPM Sprint 12 (Blast Radius Calculator) is complete. S-E08 cannot begin until AAPM Sprint 12 is confirmed delivered.

---

## 9. Open Items (Pending AAPM Review)

| Item | Owner | Required By |
|---|---|---|
| Confirm registry base URL | AAPM | S-E03 kickoff |
| Provision AgentPEP service account + refresh token | AAPM | S-E03 kickoff |
| Provide cosign public key for bundle verification | AAPM | S-E03 kickoff |
| Confirm webhook shared HMAC secret | AAPM + AgentPEP | S-E03 kickoff |
| Confirm Blast Radius API delivery date (AAPM Sprint 12 ETA) | AAPM | S-E07 retrospective |
| Mock AAPM registry for local development (pre-signed test bundle) | AAPM or AgentPEP (see S-E03-T10) | S-E03 kickoff |
| Confirm 5-minute rollout SLA is achievable from AAPM side | AAPM | S-E01 exit |
| Define monitoring contract: who alerts if bundle is not applied within SLA? | Joint | S-E05 |

---

## 10. Contract Acceptance

This contract draft requires review and acceptance by both teams before Sprint S-E03 begins.

| Role | Name | Status |
|---|---|---|
| AgentPEP Architecture Lead | Shiv | Authored — pending AAPM review |
| AAPM Integration Lead | TBD | Pending |
| TrustFabric Security Architecture | TBD | Pending |

---

*Document Owner: TrustFabric Product Architecture (AgentPEP)*
*Distribution: AgentPEP Team, AAPM Team, TrustFabric Security Architecture*
*Next Action: Share with AAPM team for review at Sprint S-E01 exit meeting*
