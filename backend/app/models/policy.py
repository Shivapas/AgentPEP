"""Pydantic models for policy rules, taint nodes, audit decisions, and agent profiles."""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


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


# --- Escalation Ticket (Sprint 9 — Human Escalation Manager) ---


class EscalationState(str, Enum):
    """State machine for escalation tickets (APEP-072)."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    TIMEOUT = "TIMEOUT"


class ApproverRoutingStrategy(str, Enum):
    """Routing strategy for selecting approvers (APEP-076)."""

    ROUND_ROBIN = "ROUND_ROBIN"
    SPECIFIC_USER = "SPECIFIC_USER"
    ON_CALL = "ON_CALL"


class EscalationTicket(BaseModel):
    """Human escalation ticket with full lifecycle (APEP-072).

    State machine: PENDING -> APPROVED | DENIED | TIMEOUT
    """

    ticket_id: UUID = Field(default_factory=uuid4)
    request_id: UUID = Field(..., description="Original ToolCallRequest.request_id")
    session_id: str
    agent_id: str
    tool_name: str
    tool_args_hash: str = Field(default="", description="SHA-256 of tool arguments")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = Field(default="", description="Why escalation was triggered")
    state: EscalationState = EscalationState.PENDING
    assigned_to: str | None = Field(
        default=None, description="Approver user/group assigned to this ticket"
    )
    routing_strategy: ApproverRoutingStrategy = ApproverRoutingStrategy.ROUND_ROBIN
    decided_by: str | None = Field(
        default=None, description="User who approved/denied the ticket"
    )
    decision_reason: str = Field(default="", description="Approver's reason for decision")
    timeout_seconds: int = Field(default=300, ge=1, description="Timeout before auto-resolution")
    timeout_action: EscalationState = Field(
        default=EscalationState.DENIED,
        description="Action on timeout: APPROVED or DENIED",
    )
    taint_flags: list[str] = Field(default_factory=list)
    delegation_chain: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: datetime | None = None


class ApproverGroup(BaseModel):
    """Group of approvers for escalation routing (APEP-076)."""

    group_id: str = Field(..., description="Unique group identifier")
    name: str
    members: list[str] = Field(default_factory=list, description="User IDs in this group")
    strategy: ApproverRoutingStrategy = ApproverRoutingStrategy.ROUND_ROBIN
    on_call_user: str | None = Field(
        default=None, description="Current on-call user (for ON_CALL strategy)"
    )
    last_assigned_index: int = Field(
        default=0, description="Last assigned index for round-robin"
    )
    enabled: bool = True


class ApprovalMemoryEntry(BaseModel):
    """Cached approval pattern to skip re-escalation (APEP-077)."""

    entry_id: UUID = Field(default_factory=uuid4)
    agent_id: str
    tool_name: str
    tool_args_hash: str = Field(..., description="SHA-256 of tool arguments pattern")
    approved_by: str
    original_ticket_id: UUID
    created_at: datetime = Field(default_factory=datetime.utcnow)


class EscalationResolveRequest(BaseModel):
    """Request to resolve (approve/deny) an escalation ticket."""

    ticket_id: UUID
    state: EscalationState = Field(
        ..., description="Must be APPROVED or DENIED"
    )
    decided_by: str
    decision_reason: str = ""


class NotificationConfig(BaseModel):
    """Configuration for escalation notifications (APEP-078/079)."""

    email_webhook_url: str | None = None
    email_recipients: list[str] = Field(default_factory=list)
    slack_webhook_url: str | None = None
    slack_channel: str | None = None
    enabled: bool = True

    @field_validator("email_webhook_url", "slack_webhook_url", mode="before")
    @classmethod
    def _validate_webhook_url(cls, v: str | None) -> str | None:
        """Only allow HTTPS URLs and block private/internal IP ranges to prevent SSRF."""
        if v is None or v == "":
            return v
        from urllib.parse import urlparse
        import ipaddress

        parsed = urlparse(v)
        if parsed.scheme != "https":
            raise ValueError(f"Webhook URL must use HTTPS scheme, got '{parsed.scheme}'")

        hostname = parsed.hostname or ""
        # Block private/internal IP ranges
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
                raise ValueError(
                    f"Webhook URL must not point to private/internal IP: {hostname}"
                )
        except ValueError as exc:
            if "private" in str(exc) or "HTTPS" in str(exc):
                raise
            # hostname is not an IP literal — that's fine (it's a domain name)

        return v


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


# --- Risk Scoring Engine (Sprint 8 — APEP-063) ---


class RiskFactor(BaseModel):
    """A single risk factor produced by a scorer."""

    factor_name: str = Field(..., description="Unique scorer name, e.g. 'operation_type'")
    score: float = Field(0.0, ge=0.0, le=1.0, description="Risk score in [0, 1]")
    detail: str = Field(default="", description="Human-readable explanation")


class RiskWeightConfig(BaseModel):
    """Weight configuration for the risk aggregator (APEP-069).

    Each key is a factor_name mapping to a weight ≥ 0.
    The aggregator normalises weights so they sum to 1.
    """

    operation_type: float = Field(default=0.25, ge=0.0, description="Weight for OperationTypeScorer")
    data_sensitivity: float = Field(default=0.25, ge=0.0, description="Weight for DataSensitivityScorer")
    taint: float = Field(default=0.20, ge=0.0, description="Weight for TaintScorer")
    session_accumulated: float = Field(default=0.10, ge=0.0, description="Weight for SessionAccumulatedRiskScorer")
    delegation_depth: float = Field(default=0.20, ge=0.0, description="Weight for DelegationDepthScorer")


class RiskModelConfig(BaseModel):
    """Top-level risk model configuration stored in MongoDB (APEP-063).

    Supports per-role overrides: if a role key exists in ``role_overrides``,
    those weights replace the defaults for agents with that role.
    """

    model_id: str = Field(default="default", description="Unique config identifier")
    default_weights: RiskWeightConfig = Field(default_factory=RiskWeightConfig)
    role_overrides: dict[str, RiskWeightConfig] = Field(
        default_factory=dict,
        description="Per-role weight overrides keyed by role_id",
    )
    escalation_threshold: float = Field(
        default=0.7, ge=0.0, le=1.0, description="Score above which ESCALATE is triggered"
    )
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


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
    # Sprint 10 — APEP-082: SHA-256 hash chain
    previous_hash: str = Field(default="", description="SHA-256 hash of the previous audit record")
    record_hash: str = Field(default="", description="SHA-256 hash of this record (chained)")
    sequence_number: int = Field(default=0, description="Monotonic sequence number for ordering")


class AuditIntegrityResult(BaseModel):
    """Result of audit hash chain verification (APEP-088)."""

    valid: bool
    total_records: int = 0
    verified_records: int = 0
    first_tampered_sequence: int | None = None
    first_tampered_decision_id: str | None = None
    detail: str = ""


class ComplianceExportRequest(BaseModel):
    """Request parameters for compliance export (APEP-086)."""

    template: str = Field(
        ..., description="Compliance template: DPDPA, GDPR, or CERT_IN"
    )
    format: str = Field(default="json", description="Export format: json or csv")
    agent_id: str | None = None
    tool_name: str | None = None
    decision: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    risk_score_min: float | None = Field(default=None, ge=0.0, le=1.0)
    risk_score_max: float | None = Field(default=None, ge=0.0, le=1.0)


class AuditQueryRequest(BaseModel):
    """Query parameters for audit log search (APEP-085)."""

    agent_id: str | None = None
    tool_name: str | None = None
    decision: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    risk_score_min: float | None = Field(default=None, ge=0.0, le=1.0)
    risk_score_max: float | None = Field(default=None, ge=0.0, le=1.0)
    limit: int = Field(default=100, ge=1, le=10000)
    offset: int = Field(default=0, ge=0)


# --- MCP Proxy Configuration (APEP-102) ---


class MCPProxyConfig(BaseModel):
    """MCP proxy configuration for an agent (APEP-102).

    Defines how the MCP intercept proxy connects to the upstream MCP server
    for this agent and what policy controls apply.
    """

    enabled: bool = Field(default=False, description="Whether MCP proxy is enabled for this agent")
    upstream_url: str = Field(
        default="", description="URL of the target MCP server (e.g. http://localhost:3000/mcp)"
    )
    allowed_tools: list[str] = Field(
        default_factory=list,
        description="Glob patterns of MCP tools this agent can invoke (empty = use profile-level)",
    )
    timeout_s: float = Field(
        default=30.0, gt=0, description="Timeout for upstream MCP server requests in seconds"
    )
    max_concurrent_sessions: int = Field(
        default=10, ge=1, description="Max concurrent MCP proxy sessions for this agent"
    )
    taint_tracking_enabled: bool = Field(
        default=True, description="Whether taint tracking is active for MCP sessions"
    )


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
    mcp_proxy: MCPProxyConfig = Field(
        default_factory=MCPProxyConfig,
        description="MCP proxy configuration (APEP-102)",
    )
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


# --- Escalation Ticket (Sprint 18 — APEP-143..APEP-147) ---


class EscalationStatus(str, Enum):
    """Lifecycle states for an escalation ticket."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    ESCALATED_UP = "ESCALATED_UP"
    AUTO_DECIDED = "AUTO_DECIDED"


class EscalationTicket(BaseModel):
    """A pending escalation awaiting human review (APEP-143)."""

    ticket_id: UUID = Field(default_factory=uuid4)
    session_id: str
    agent_id: str
    agent_role: str = ""
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    tool_args_hash: str = Field(default="", description="SHA-256 of tool args for pattern matching")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    taint_flags: list[str] = Field(default_factory=list)
    delegation_chain: list[str] = Field(default_factory=list)
    matched_rule_id: UUID | None = None
    reason: str = ""
    status: EscalationStatus = EscalationStatus.PENDING
    resolution_comment: str = ""
    resolved_by: str | None = None
    sla_deadline: datetime = Field(
        default_factory=datetime.utcnow,
        description="Deadline before auto-decision applies",
    )
    sla_seconds: int = Field(default=300, description="SLA window in seconds")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: datetime | None = None


class EscalationAction(BaseModel):
    """Request body for approving, denying, or escalating-up a ticket (APEP-145)."""

    action: EscalationStatus = Field(
        ..., description="APPROVED, DENIED, or ESCALATED_UP"
    )
    comment: str = Field(default="", description="Reviewer comment")
    resolved_by: str = Field(default="console_user", description="Who resolved this")


class BulkApproveRequest(BaseModel):
    """Bulk approve tickets matching a tool pattern (APEP-146)."""

    tool_pattern: str = Field(..., description="Glob pattern to match tool_name")
    comment: str = Field(default="", description="Reviewer comment for all approvals")
    resolved_by: str = Field(default="console_user")
