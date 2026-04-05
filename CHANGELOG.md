# Changelog

All notable changes to AgentPEP are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/) and follows
the [Keep a Changelog](https://keepachangelog.com/) format.

---

## [1.0.0] — 2026-04-03

### General Availability Release

AgentPEP 1.0.0 is the first production-ready release of the deterministic
authorization engine for AI agent systems.

### Added

- **Intercept API (REST + gRPC):** Single decision endpoint that evaluates every
  agent tool call against a layered policy stack before execution.
- **RBAC Policy Engine:** Role-based access control with wildcard resource
  matching, time-window constraints, and environment-scoped rules.
- **Risk-Adaptive Access Control (RAdAC):** Dynamic risk scoring that adjusts
  allow/deny decisions based on real-time context signals.
- **Taint Tracking Engine:** Data-flow taint propagation across agent sessions
  with sanitisation gates, quarantine support, and full audit trail.
- **Confused-Deputy Detection:** Delegation chain analysis that prevents
  privilege escalation when agents invoke other agents.
- **Injection Signature Matching:** Pattern-based detection of prompt injection,
  SQL injection, path traversal, and command injection in tool-call arguments.
- **Policy Conflict Detection:** Automatic detection and reporting of
  contradictory or shadowed rules in the policy set.
- **Python SDK (`agentpep-sdk`):** Client library with `@enforce` decorator,
  FastAPI middleware, and async-first design.
- **LangChain Integration:** `AgentPEPToolWrapper` for transparent policy
  enforcement in LangChain tool chains.
- **LangGraph Integration:** `agentpep_guardrail_node` for inserting policy
  checks into LangGraph agent graphs.
- **Offline Policy Evaluation:** SDK-side rule evaluation for latency-sensitive
  paths when the server is unavailable.
- **Observability:** Prometheus metrics and OpenTelemetry tracing instrumented
  across all critical paths.
- **Authentication:** API key and mTLS authentication middleware.
- **Docker Compose:** Full local development stack with MongoDB, Kafka, and
  hot-reload for backend and frontend.
- **CI/CD:** GitHub Actions pipeline for lint, type-check, test, and build.
- **Frontend Dashboard:** React + TypeScript policy management UI (Vite, Tailwind).

### Performance

- Intercept API p50 latency ≤ 5 ms, p99 ≤ 25 ms (single node).
- Sustained throughput ≥ 10,000 decisions/second per node.
- Rule cache with ≥ 95% hit ratio under production workloads.

### Security

- OWASP Top 10 mitigations verified.
- Penetration test completed — all findings remediated.
- SOC 2 Type II audit completed.
- Zero critical/high dependency vulnerabilities.

---

*AgentPEP · TrustFabric Portfolio · © 2026*
