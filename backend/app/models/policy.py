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
    CROSS_AGENT = "CROSS_AGENT"  # APEP-051: data crossing agent boundary
    SANITISED = "SANITISED"  # APEP-048: output of a sanitisation gate


class TaintEventType(str, Enum):
    """Types of taint audit events (APEP-052)."""

    TAINT_ASSIGNED = "TAINT_ASSIGNED"
    TAINT_PROPAGATED = "TAINT_PROPAGATED"
    TAINT_DOWNGRADED = "TAINT_DOWNGRADED"
    TAINT_QUARANTINED = "TAINT_QUARANTINED"
    CROSS_AGENT_PROPAGATED = "CROSS_AGENT_PROPAGATED"


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


class RateLimitType(str, Enum):
    """Rate limiting algorithm type (APEP-090/091)."""

    SLIDING_WINDOW = "SLIDING_WINDOW"
    FIXED_WINDOW = "FIXED_WINDOW"


class RateLimit(BaseModel):
    count: int = Field(..., gt=0, description="Max invocations per window")
    window_s: int = Field(..., gt=0, description="Window duration in seconds")
    limiter_type: RateLimitType = Field(
        default=RateLimitType.SLIDING_WINDOW,
        description="Rate limiting algorithm: SLIDING_WINDOW or FIXED_WINDOW",
    )


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
    agent_id: str | None = Field(
        default=None, description="Agent that created this node (APEP-051)"
    )
    tool_call_id: str | None = Field(
        default=None, description="Tool call that produced this node (APEP-047)"
    )
    hop_depth: int = Field(
        default=0, description="Number of tool call hops from original source (APEP-047)"
    )
    sanitised_by: str | None = Field(
        default=None, description="Sanitisation function that downgraded taint (APEP-048)"
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)


class SanitisationGate(BaseModel):
    """Declaration of a sanitisation function that can downgrade taint (APEP-048)."""

    gate_id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., description="Human-readable name for the sanitiser")
    function_pattern: str = Field(
        ..., description="Glob/regex pattern matching the sanitisation function name"
    )
    downgrades_from: TaintLevel = Field(
        ..., description="Taint level this gate can downgrade FROM"
    )
    downgrades_to: TaintLevel = Field(
        ..., description="Taint level this gate downgrades TO"
    )
    requires_approval: bool = Field(
        default=False, description="If True, downgrade requires human approval"
    )
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


class TaintAuditEvent(BaseModel):
    """Audit event for taint assignment and propagation (APEP-052)."""

    event_id: UUID = Field(default_factory=uuid4)
    event_type: TaintEventType
    session_id: str
    node_id: UUID
    agent_id: str | None = None
    taint_level: TaintLevel
    previous_taint_level: TaintLevel | None = None
    source: TaintSource
    propagated_from: list[UUID] = Field(default_factory=list)
    tool_call_id: str | None = None
    hop_depth: int = 0
    sanitised_by: str | None = None
    matched_signature: str | None = Field(
        default=None, description="Injection pattern that triggered QUARANTINE"
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# --- Delegation Chain (Sprint 7 — Confused-Deputy Detector) ---


class DelegationHop(BaseModel):
    """A single hop in an agent-to-agent delegation chain (APEP-054).

    Each hop records which agent delegated to which, the tools it granted,
    and the authority source that justified the delegation.
    """

    agent_id: str = Field(..., description="Agent at this hop in the chain")
    granted_tools: list[str] = Field(
        default_factory=list,
        description="Glob patterns of tools this agent was granted by its delegator",
    )
    authority_source: str = Field(
        default="user",
        description="Origin of authority: 'user', 'role:<role_id>', or 'agent:<agent_id>'",
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class DelegationChain(BaseModel):
    """Full delegation chain from originating user to current agent (APEP-054)."""

    session_id: str
    hops: list[DelegationHop] = Field(default_factory=list)
    max_depth: int = Field(default=5, ge=1, description="Maximum allowed chain depth")

    @property
    def depth(self) -> int:
        return len(self.hops)

    @property
    def current_agent(self) -> str | None:
        return self.hops[-1].agent_id if self.hops else None

    @property
    def origin_agent(self) -> str | None:
        return self.hops[0].agent_id if self.hops else None


class SecurityAlertType(str, Enum):
    """Types of security alert events (APEP-059)."""

    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CHAIN_DEPTH_EXCEEDED = "CHAIN_DEPTH_EXCEEDED"
    UNAUTHORIZED_DELEGATION = "UNAUTHORIZED_DELEGATION"
    IMPLICIT_DELEGATION = "IMPLICIT_DELEGATION"
    AUTHORITY_VIOLATION = "AUTHORITY_VIOLATION"


class SecurityAlertEvent(BaseModel):
    """Security alert generated when delegation violations are detected (APEP-059)."""

    alert_id: UUID = Field(default_factory=uuid4)
    alert_type: SecurityAlertType
    session_id: str
    agent_id: str
    delegation_chain: list[str] = Field(default_factory=list)
    tool_name: str = ""
    detail: str = ""
    severity: str = Field(default="HIGH", description="LOW, MEDIUM, HIGH, CRITICAL")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class InjectionSignature(BaseModel):
    """A categorised injection signature pattern (APEP-049)."""

    signature_id: str = Field(..., description="Unique identifier e.g. INJ-001")
    category: str = Field(..., description="Category: prompt_override, role_hijack, system_escape, jailbreak, encoding_bypass")
    pattern: str = Field(..., description="Regex pattern string")
    severity: str = Field(default="HIGH", description="LOW, MEDIUM, HIGH, CRITICAL")
    description: str = Field(default="", description="Human-readable description")


# --- Validator Pipeline Result (APEP-096) ---


class ValidationFailure(BaseModel):
    """A single validation failure from the validator pipeline."""

    validator_type: str = Field(..., description="Type: json_schema, regex, allowlist, blocklist")
    arg_name: str
    reason: str


class ValidationResult(BaseModel):
    """Result of running the full validator pipeline (APEP-096)."""

    passed: bool = True
    failures: list[ValidationFailure] = Field(default_factory=list)

    @property
    def reason(self) -> str:
        if self.passed:
            return ""
        return "; ".join(f"[{f.validator_type}] {f.arg_name}: {f.reason}" for f in self.failures)


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
    tenant_id: str = Field(default="default", description="Tenant identifier for global rate limits (APEP-092)")
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    delegation_chain: list[str] = Field(default_factory=list)
    delegation_hops: list[DelegationHop] = Field(
        default_factory=list,
        description="Structured delegation chain with per-hop authority (APEP-054)",
    )
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
