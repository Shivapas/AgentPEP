# Sprint S-E01 Decision Log

**Sprint:** S-E01 — Foundations: Threat Model, Design Invariants, Integration Design
**Status:** Draft — Updated as decisions are confirmed
**Owner:** TrustFabric Product Architecture (Shiv)
**Date:** April 2026

---

## Purpose

This log records the key decisions made during Sprint S-E01, including AAPM team coordination outcomes. It is the E01-T07 deliverable: *"Confirm AAPM team availability and sprint alignment: AAPM Policy Registry readiness, Blast Radius API ETA."*

---

## Decision Log

### DEC-001: Evaluation Guarantee Invariant — Accepted

**Date:** April 2026
**Decision:** The Evaluation Guarantee Invariant (INV-001) is accepted as a named, inviolable design principle for AgentPEP v2.x.
**Owner:** AgentPEP Architecture (Shiv)
**Status:** ACCEPTED
**Document:** `docs/invariants/evaluation_guarantee.md`

**Summary:** Any evaluation failure (timeout, exception, engine error, malformed response) defaults to DENY. No permissive fallback. This property cannot be overridden by operator configuration.

**Rationale:** FAIL_CLOSED is the correct default for a reference monitor. Permissive fallback on evaluation failure is the root cause of the complexity bypass class (BV-002) in the current v1.x implementation.

---

### DEC-002: OPA Deployment Model — Embedded Library

**Date:** April 2026
**Decision:** OPA will be integrated as an embedded library (in-process) rather than as a sidecar process.
**Owner:** AgentPEP Architecture (Shiv)
**Status:** ACCEPTED
**Document:** `docs/adr/ADR-001-opa-deployment-model.md`

**Summary:** Embedded library provides lower latency (no network hop), simpler operations (single deployable unit), and a smaller attack surface (no localhost port). The latency target (P99 < 10ms at 1,000 concurrent evaluations) will be validated in Sprint S-E04. If the embedded model fails the benchmark, ADR-001 will be formally amended to the sidecar model.

---

### DEC-003: AAPM Integration Contract — Draft Submitted for Review

**Date:** April 2026
**Decision:** Integration contract draft completed and submitted to AAPM team for review.
**Owner:** AgentPEP Architecture (Shiv) — authored; AAPM team review pending
**Status:** PENDING AAPM REVIEW
**Document:** `docs/integrations/aapm_agentpep_contract_draft.md`

**Key contract terms proposed:**
- Registry URL: `https://registry.trustfabric.internal/agentpep/policies/`
- Delivery: Webhook push (primary) + pull polling at 60s (fallback)
- Normal update SLA: 5 minutes (PCR approved → bundle active in AgentPEP)
- Emergency deny-all SLA: 5 minutes
- cosign public key: pinned in AgentPEP binary (AAPM to provide key)
- Bundle format: `.tar.gz` + `.sig` cosign signature

**Open items requiring AAPM confirmation:**
- Registry base URL confirmation
- AgentPEP service account provisioning
- cosign public key delivery
- Webhook HMAC secret
- Blast Radius API (AAPM Sprint 12) delivery date
- 5-minute SLA feasibility from AAPM side

---

### DEC-004: AAPM Team Availability — Coordination Status

**Date:** April 2026
**Decision:** AAPM team coordination initiated. Availability and sprint alignment to be confirmed at S-E01 exit meeting.
**Owner:** Shiv (AgentPEP) — coordination; AAPM Integration Lead (TBD) — response
**Status:** PENDING CONFIRMATION

**Items to confirm with AAPM team:**

| Item | Required By | Status |
|---|---|---|
| AAPM Policy Registry readiness (even stub) | S-E03 kickoff | Pending |
| cosign public key for bundle verification | S-E03 kickoff | Pending |
| AgentPEP service account + refresh token | S-E03 kickoff | Pending |
| AAPM Blast Radius API (Sprint 12) delivery date | S-E07 retrospective | **Critical — must confirm before S-E08 can be scheduled** |
| AAPM team sprint alignment (AAPM sprint calendar vs. AgentPEP sprint calendar) | S-E01 exit | Pending |
| PCR workflow operational for E2E test (S-E05) | S-E05 kickoff | Pending |
| Integration contract review and acceptance | S-E01 exit | Pending |

**Blast Radius API note:** AAPM Sprint 12 (Blast Radius Calculator) is a **hard block** on AgentPEP Sprint S-E08. If AAPM Sprint 12 is delayed beyond the S-E07 retrospective date, S-E08 will begin with the posture matrix implemented without blast radius elevation, and the elevation logic will be added as a follow-up task when the AAPM API is available.

---

### DEC-005: Portfolio Boundary — Accepted

**Date:** April 2026
**Decision:** The portfolio boundary between AgentPEP and AAPM is formally accepted as documented.
**Owner:** AgentPEP Architecture (Shiv) — authored; AAPM team acceptance pending
**Status:** PENDING AAPM ACCEPTANCE
**Document:** `docs/architecture/portfolio_boundary.md`

**Summary:** AAPM owns: policy authoring (APDL), PCR workflow, bundle compilation, cosign signing, Policy Registry, audit trail, Blast Radius Calculator. AgentPEP owns: policy loading, signature verification, OPA runtime evaluation, PreToolUse enforcement, PostToolUse event emission, trust degradation.

---

## Exit Criteria Status

| S-E01 Exit Criterion | Status |
|---|---|
| Evaluation Guarantee Invariant documented and accepted | COMPLETE — `docs/invariants/evaluation_guarantee.md` |
| All four bypass vectors documented with MITRE ATLAS IDs | COMPLETE — `docs/threat_model/bypass_vectors.md` |
| ADR-001 decided | COMPLETE — `docs/adr/ADR-001-opa-deployment-model.md` |
| AAPM integration contract draft reviewed and agreed with AAPM team | IN PROGRESS — draft complete; AAPM review pending |
| AAPM Blast Radius API delivery date confirmed | PENDING — confirmation required from AAPM |
| Portfolio boundary document accepted by both teams | IN PROGRESS — drafted; AAPM acceptance pending |

---

*Document Owner: TrustFabric Product Architecture*
*Updated: April 2026*
*Next Update: S-E01 exit meeting (after AAPM review)*
