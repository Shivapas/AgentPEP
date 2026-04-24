"""AgentPEP Policy Decision Point (PDP) — OPA Runtime Engine.

Sprint S-E04: OPA Runtime Engine — Core (FEATURE-01 Part A)

Components:
  - engine:           OPA embedded library wrapper (ADR-001: Option A)
  - request_builder:  PreToolUse context → structured OPA input JSON
  - response_parser:  OPA output → ALLOW / DENY / MODIFY + reason code
  - client:           PDP client with FAIL_CLOSED timeout enforcement
  - enforcement_log:  Structured log entry for every evaluation decision
"""
