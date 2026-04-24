# ADR-001: OPA Engine Deployment Model — Embedded Library vs. Sidecar

**Status:** Accepted
**Sprint:** S-E01 (E01-T05)
**Date:** April 2026
**Author:** TrustFabric Product Architecture
**Deciders:** Shiv (AgentPEP), TrustFabric Architecture Review

---

## Context

AgentPEP v2.x introduces an OPA/Rego Policy Decision Point (PDP) as the runtime policy evaluation engine (FEATURE-01). The OPA engine must be integrated into the AgentPEP deployment. There are two viable deployment models:

**Option A: Embedded Library** — OPA's Go WASM build or a Python-native OPA binding runs in-process with the AgentPEP backend. Policy evaluation is a function call, not a network hop.

**Option B: Sidecar Process** — OPA runs as a separate process alongside AgentPEP (either as a Docker sidecar, a systemd service, or a co-located process). AgentPEP communicates with OPA via HTTP (OPA's REST API on `localhost:8181`).

Both options are viable in production deployments of OPA. This decision determines the architectural approach for AgentPEP v2.x.

---

## Decision

**Accepted: Option A — Embedded Library (OPA Python SDK / WASM)**

---

## Rationale

### Latency Requirement

The PDP evaluation latency target is P99 < 10ms under 1,000 concurrent evaluations (FEATURE-01 acceptance criterion). Network round-trips to a sidecar process introduce additional latency:

- Sidecar (localhost HTTP): typically 1–5ms per call at low concurrency; degrades under high concurrent load due to TCP stack overhead, socket backlog, and serialisation.
- Embedded library (in-process function call): typically 0.1–2ms per call; constant regardless of network conditions.

The 10ms P99 target is achievable with either model at low concurrency, but the embedded library provides a larger safety margin for the P99 target under 1,000 concurrent evaluations. At P99 under load, the sidecar model carries medium-high risk of latency regression.

### Operational Complexity

The sidecar model introduces an additional process lifecycle:
- OPA process must be co-managed with AgentPEP (health checks, restarts, version alignment)
- OPA sidecar failure becomes a liveness dependency for AgentPEP (or requires additional fallback logic)
- Container orchestration (Docker Compose, Kubernetes) must define sidecar container, port, and health probe

The embedded library model keeps AgentPEP as a single deployable unit with no additional process dependencies. Given the solo-engineer constraint (one team member), reduced operational complexity is a significant factor.

### Security Model

Both models are equivalent from a policy enforcement perspective. However:
- Sidecar HTTP: policy evaluation traffic traverses a local network socket; while localhost, this adds an attack surface (port binding, socket access control)
- Embedded library: no network socket; policy evaluation is an in-process function call; attack surface is limited to process memory

The embedded library model has a marginally stronger security posture by eliminating the network hop.

### Fallback Path (Risk Mitigation)

The risk register identifies: *"OPA sidecar latency exceeds 10ms P99 — Medium likelihood, High impact — fall back to embedded library per ADR-001."*

Accepting the embedded library model as the primary deployment eliminates this fallback scenario entirely. The sidecar model would be revisited only if:
- A future requirement demands OPA to be shared across multiple AgentPEP instances
- The embedded WASM/library proves unsuitable for the target Python version or platform

### Benchmark Commitment

Sprint S-E04 (E04-T08) includes a latency benchmark: PDP decision latency under 100, 500, 1,000 concurrent evaluations; verify P99 < 10ms. If the embedded library fails this benchmark, the decision will be revisited with a formal ADR amendment.

---

## Trade-offs Accepted

| Trade-off | Accepted? | Rationale |
|---|---|---|
| Sidecar enables horizontal OPA scaling (shared across multiple AgentPEP replicas) | Not required now | Each AgentPEP instance carries its own OPA engine; acceptable given single-tenant deployment model |
| Embedded WASM may have language-binding constraints | Accepted | OPA's Python SDK (via `opa` PyPI package or WASM bridge) is maintained and production-ready |
| Sidecar allows OPA version updates without AgentPEP redeployment | Accepted trade-off | Policy updates come via AAPM bundle reload (not OPA version changes); OPA version is pinned per AgentPEP release |
| Embedded library increases AgentPEP binary/package size | Accepted | Size increase is modest (~10MB for WASM build); acceptable for enterprise deployment |

---

## Consequences

- AgentPEP S-E04 will integrate OPA via the Python SDK (`opa-python` or equivalent WASM binding)
- OPA version is pinned in `pyproject.toml` and updated explicitly per AgentPEP release
- No additional process, port, or container is required in the deployment configuration
- If the embedded model fails the S-E04 latency benchmark (P99 > 10ms at 1,000 concurrent), this ADR will be formally amended to Option B with a new latency analysis
- The `docker-compose.yml` in this repository will NOT include an OPA sidecar container

---

## Rejected Alternatives

### Option B: OPA Sidecar — Why Rejected

- Additional operational complexity for solo-engineer deployment
- Latency risk under high concurrency (network hop overhead)
- No scaling requirement that would justify the added complexity in the current deployment model
- Localhost HTTP introduces a small but unnecessary network attack surface

### Hybrid: Sidecar with Local Fallback — Why Rejected

- Complexity of maintaining two evaluation paths
- FAIL_CLOSED requirement means the embedded fallback becomes the guaranteed path on sidecar failure — effectively making the sidecar optional and therefore architecturally redundant

---

## References

- FEATURE-01: Runtime Policy Decision Point — PRD v2.1, Section 5.1
- `docs/invariants/evaluation_guarantee.md` — FAIL_CLOSED requirement on evaluation failure
- Sprint S-E04 task E04-T08 — Latency benchmark mandate
- Risk Register entry: *OPA sidecar latency exceeds 10ms P99*
- OPA Python SDK: https://www.openpolicyagent.org/docs/latest/python/
