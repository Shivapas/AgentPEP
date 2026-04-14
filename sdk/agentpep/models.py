"""Shared Pydantic models for the AgentPEP SDK."""

from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    DRY_RUN = "DRY_RUN"
    TIMEOUT = "TIMEOUT"
    # Sprint 33 — APEP-259/260: New decision types
    DEFER = "DEFER"
    MODIFY = "MODIFY"
    # Sprint 36 — APEP-288: STEP_UP requires additional authentication
    STEP_UP = "STEP_UP"


class TaintLevel(str, Enum):
    """Taint classification levels."""

    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    QUARANTINE = "QUARANTINE"


class TaintSource(str, Enum):
    """Source types for taint tracking."""

    USER_PROMPT = "USER_PROMPT"
    SYSTEM_PROMPT = "SYSTEM_PROMPT"
    WEB = "WEB"
    EMAIL = "EMAIL"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    AGENT_MSG = "AGENT_MSG"


class ToolCallRequest(BaseModel):
    """Request payload for the Intercept API."""

    request_id: UUID = Field(default_factory=uuid4)
    session_id: str = "default"
    agent_id: str
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    delegation_chain: list[str] = Field(default_factory=list)
    taint_node_ids: list[UUID] = Field(default_factory=list)
    dry_run: bool = False


class PolicyDecisionResponse(BaseModel):
    """Response from the Intercept API."""

    request_id: UUID
    decision: PolicyDecision
    matched_rule_id: UUID | None = None
    risk_score: float = 0.0
    taint_flags: list[str] = Field(default_factory=list)
    reason: str = ""
    escalation_id: UUID | None = None
    latency_ms: int = 0
    # Sprint 29 — APEP-232: Single-use execution token for ALLOW decisions
    execution_token: str | None = None
    # Sprint 32 — APEP-256: Cryptographically signed receipt
    receipt: str | None = None
    # Sprint 33 — APEP-259/260: DEFER and MODIFY decision support
    modified_args: dict[str, Any] | None = None
    defer_timeout_s: int = 60
    # Sprint 36 — APEP-287/288: DEFER reason and STEP_UP requirements
    step_up_requirements: list[str] | None = None
    step_up_challenge_id: str | None = None
    defer_reason: str | None = None


class TaintNodeResponse(BaseModel):
    """Response from the taint labelling API."""

    node_id: UUID
    session_id: str
    taint_level: TaintLevel
    source: TaintSource
    propagated_from: list[UUID] = Field(default_factory=list)
    value_hash: str | None = None


# --- Sprint 46 — APEP-364/370: Fetch Proxy SDK models ---


class FetchStatus(str, Enum):
    """Overall status of a fetch proxy request."""

    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    QUARANTINED = "QUARANTINED"
    SANITIZED = "SANITIZED"


class FetchSafeResponse(BaseModel):
    """Response from the GET /v1/fetch proxy endpoint (SDK model)."""

    fetch_id: UUID | None = None
    url: str = ""
    status: FetchStatus = FetchStatus.ALLOWED
    http_status: int = 0
    content_type: str = ""
    body: str = ""
    body_length: int = 0
    truncated: bool = False
    injection_detected: bool = False
    injection_finding_count: int = 0
    injection_highest_severity: str = "INFO"
    dlp_findings_count: int = 0
    dlp_blocked: bool = False
    taint_applied: str | None = None
    taint_node_id: str | None = None
    action_taken: str = "ALLOW"
    latency_ms: int = 0
