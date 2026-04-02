# ADR-001: Monorepo Structure

## Status

Accepted

## Context

AgentPEP consists of a Python backend (FastAPI), a React frontend (Policy Console), a Python SDK, and infrastructure configs. We need to decide how to organize the codebase.

## Decision

Use a monorepo with top-level directories:

- `backend/` — FastAPI application (policy engine, intercept API, audit)
- `frontend/` — React + Vite + Tailwind policy console
- `sdk/` — `agentpep-sdk` Python package
- `infra/` — Terraform, Helm charts, deployment configs
- `docs/` — ADRs, API conventions, contribution guide

Each module has its own `pyproject.toml` or `package.json` and independent CI jobs.

## Consequences

- Clear separation of concerns across modules
- Independent versioning per module
- CI can run jobs in parallel per module
- Developers need to be aware of cross-module dependencies
