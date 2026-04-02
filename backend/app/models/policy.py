"""Pydantic models for policy rules, taint nodes, audit decisions, and agent profiles."""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# --- Enums ---


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    DRY_RUN = "DRY_RUN"
    TIMEOUT = "TIMEOUT"


class TaintLevel(str, Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    QUARANTINE = "QUARANTINE"


class TaintSource(str, Enum):
    USER_PROMPT = "USER_PROMPT"
    SYSTEM_PROMPT = "SYSTEM_PROMPT"
    WEB = "WEB"
    EMAIL = "EMAIL"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    AGENT_MSG = "AGENT_MSG"


# --- Agent Role (RBAC Hierarchy) ---


class AgentRole(BaseModel):
    """Role with multi-inheritance hierarchy for RBAC.

    Roles form a DAG where each role can inherit from multiple parent roles.
    Effective permissions are computed by merging the role's own permissions
    with all inherited permissions from ancestor roles.
    """

    role_id: str = Field(..., description="Unique role identifier (e.g., 'admin', 'reader')")
    name: str = Field(..., description="Human-readable role name")
    parent_roles: list[str] = Field(
        default_factory=list,
        description="List of parent role_ids this role inherits from",
    )
    allowed_tools: list[str] = Field(
        default_factory=list,
        description="Glob patterns of tools this role can access directly",
    )
    denied_tools: list[str] = Field(
        default_factory=list,
        description="Glob patterns of tools explicitly denied to this role",
    )
    max_risk_threshold: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Max risk score this role can tolerate"
    )
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# --- Policy Rule ---


class RateLimit(BaseModel):
    count: int = Field(..., gt=0, description="Max invocations per window")
    window_s: int = Field(..., gt=0, description="Window duration in seconds")


class ArgValidator(BaseModel):
    arg_name: str
    json_schema: dict[str, Any] | None = None
    regex_pattern: str | None = None
    allowlist: list[str] | None = None
    blocklist: list[str] | None = None


class PolicyRule(BaseModel):
    rule_id: UUID = Field(default_factory=uuid4)
    name: str
    agent_role: list[str]
    tool_pattern: str = Field(..., description="Glob or regex pattern for tool names")
    action: Decision
    taint_check: bool = False
    risk_threshold: float = Field(default=1.0, ge=0.0, le=1.0)
    rate_limit: RateLimit | None = None
    arg_validators: list[ArgValidator] = Field(default_factory=list)
    priority: int = Field(default=100, description="Lower = higher priority")
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# --- Taint Node ---


class TaintNode(BaseModel):
    node_id: UUID = Field(default_factory=uuid4)
    session_id: str
    taint_level: TaintLevel = TaintLevel.TRUSTED
    source: TaintSource
    propagated_from: list[UUID] = Field(default_factory=list)
    value_hash: str | None = Field(
        default=None, description="SHA-256 hash of the tracked value"
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)


# --- Audit Decision Log ---


class AuditDecision(BaseModel):
    decision_id: UUID = Field(default_factory=uuid4)
    session_id: str
    agent_id: str
    agent_role: str
    tool_name: str
    tool_args_hash: str = Field(..., description="SHA-256 of sanitised argument payload")
    taint_flags: list[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    delegation_chain: list[str] = Field(default_factory=list)
    matched_rule_id: UUID | None = None
    decision: Decision
    escalation_id: UUID | None = None
    latency_ms: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# --- Agent Profile ---


class AgentProfile(BaseModel):
    agent_id: str = Field(..., description="Unique agent identifier")
    name: str
    roles: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(
        default_factory=list, description="Glob patterns of allowed tools"
    )
    risk_budget: float = Field(default=1.0, ge=0.0, le=1.0)
    max_delegation_depth: int = Field(default=5, ge=1)
    session_limit: int = Field(default=100, ge=1)
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# --- Intercept API Schemas ---


class ToolCallRequest(BaseModel):
    request_id: UUID = Field(default_factory=uuid4)
    session_id: str
    agent_id: str
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    delegation_chain: list[str] = Field(default_factory=list)
    taint_node_ids: list[UUID] = Field(
        default_factory=list,
        description="IDs of taint nodes associated with tool arguments",
    )
    dry_run: bool = False


class PolicyDecisionResponse(BaseModel):
    request_id: UUID
    decision: Decision
    matched_rule_id: UUID | None = None
    risk_score: float = 0.0
    taint_flags: list[str] = Field(default_factory=list)
    reason: str = ""
    escalation_id: UUID | None = None
    latency_ms: int = 0
