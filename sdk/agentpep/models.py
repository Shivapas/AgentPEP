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


class TaintNodeResponse(BaseModel):
    """Response from the taint labelling API."""

    node_id: UUID
    session_id: str
    taint_level: TaintLevel
    source: TaintSource
    propagated_from: list[UUID] = Field(default_factory=list)
    value_hash: str | None = None
