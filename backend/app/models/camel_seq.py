"""Pydantic models for Sprint 55 — CaMeL SEQ Rules, Layer 3 Bridge & Self-Protection.

APEP-436: CaMeL-lite SEQ rule chain pattern models.
APEP-437: Session-wide typed marker system for SEQ-001/002.
APEP-438: ToolTrust -> AgentPEP Intercept bridge models.
APEP-439: CIS scan verdict as taint input models.
APEP-440: Agent-initiated policy modification self-protection models.
APEP-441: Protected path patterns for PreToolUse models.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SEQRuleID(StrEnum):
    """CaMeL-lite SEQ rule identifiers."""

    SEQ_001 = "SEQ-001"  # File read -> external HTTP (enforcing)
    SEQ_002 = "SEQ-002"  # File read -> DNS/external exfil (enforcing)
    SEQ_003 = "SEQ-003"  # Config read -> config write (advisory)
    SEQ_004 = "SEQ-004"  # Secret access -> shell exec (advisory)
    SEQ_005 = "SEQ-005"  # Env read -> config write (config-write enforcement)


class SEQRuleMode(StrEnum):
    """Enforcement mode for SEQ rules."""

    ENFORCING = "ENFORCING"  # Block on match
    ADVISORY = "ADVISORY"  # Log/alert only
    DRY_RUN = "DRY_RUN"  # Log but do not enforce


class MarkerType(StrEnum):
    """Session-wide marker types used by CaMeL-lite SEQ rules."""

    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    CONFIG_READ = "CONFIG_READ"
    CONFIG_WRITE = "CONFIG_WRITE"
    SECRET_ACCESS = "SECRET_ACCESS"
    ENV_READ = "ENV_READ"
    EXTERNAL_HTTP = "EXTERNAL_HTTP"
    DNS_EXFIL = "DNS_EXFIL"
    SHELL_EXEC = "SHELL_EXEC"
    NETWORK_SEND = "NETWORK_SEND"


class BridgeVerdictLevel(StrEnum):
    """ToolTrust Layer 3 scan verdict levels."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class SelfProtectionAction(StrEnum):
    """Self-protection guard action types."""

    BLOCK = "BLOCK"
    WARN = "WARN"
    AUDIT = "AUDIT"


class ProtectedPathAction(StrEnum):
    """Action when a protected path is accessed via PreToolUse."""

    DENY = "DENY"
    ESCALATE = "ESCALATE"
    AUDIT_ONLY = "AUDIT_ONLY"


# ---------------------------------------------------------------------------
# APEP-437: Session-wide typed marker system
# ---------------------------------------------------------------------------


class SessionMarker(BaseModel):
    """A typed marker placed in a session during tool call processing.

    Markers track behavioural signals (e.g. 'FILE_READ occurred') that
    CaMeL-lite SEQ rules use for gap-tolerant sequence detection.
    """

    marker_id: str = Field(
        default_factory=lambda: f"MK-{uuid4().hex[:8].upper()}",
        description="Unique marker identifier",
    )
    session_id: str = Field(..., description="Session this marker belongs to")
    marker_type: MarkerType = Field(..., description="Typed marker category")
    tool_name: str = Field(default="", description="Tool that produced this marker")
    tool_call_id: str = Field(default="", description="Specific tool call ID")
    agent_id: str = Field(default="", description="Agent that triggered this marker")
    metadata: dict = Field(
        default_factory=dict,
        description="Additional context (e.g. file path, URL, domain)",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SessionMarkerQuery(BaseModel):
    """Query parameters for listing session markers."""

    session_id: str = Field(..., description="Session ID to query")
    marker_types: list[MarkerType] | None = Field(
        default=None, description="Filter by marker type(s)"
    )
    since: datetime | None = Field(
        default=None, description="Only markers after this timestamp"
    )
    limit: int = Field(default=100, ge=1, le=1000)


class SessionMarkerListResponse(BaseModel):
    """Response for listing session markers."""

    markers: list[SessionMarker] = Field(default_factory=list)
    total: int = Field(default=0)
    session_id: str = Field(default="")


# ---------------------------------------------------------------------------
# APEP-438: ToolTrust -> AgentPEP Intercept bridge
# ---------------------------------------------------------------------------


class ToolTrustBridgeRequest(BaseModel):
    """Request from ToolTrust Layer 3 PreToolUse hook to AgentPEP Intercept.

    ToolTrust Layer 3 makes a decision about a tool call and forwards
    the verdict to AgentPEP as a taint signal / enrichment.
    """

    session_id: str = Field(..., description="Session ID for the tool call")
    agent_id: str = Field(default="", description="Agent performing the tool call")
    tool_name: str = Field(..., description="Tool being invoked")
    tool_args: dict = Field(default_factory=dict, description="Tool arguments")
    verdict: BridgeVerdictLevel = Field(
        ..., description="ToolTrust Layer 3 scan verdict"
    )
    verdict_details: str = Field(
        default="", description="Human-readable verdict explanation"
    )
    findings: list[dict] = Field(
        default_factory=list,
        description="Detailed scan findings from ToolTrust",
    )
    scan_latency_ms: int = Field(
        default=0, description="ToolTrust scan latency in milliseconds"
    )
    layer: int = Field(default=3, description="ToolTrust layer number")
    trust_cache_hit: bool = Field(
        default=False, description="Whether ToolTrust trust cache was used"
    )


class ToolTrustBridgeResponse(BaseModel):
    """Response from AgentPEP after processing a ToolTrust bridge request."""

    accepted: bool = Field(default=True, description="Whether the bridge request was accepted")
    taint_applied: str | None = Field(
        default=None, description="Taint level applied (if any)"
    )
    intercept_decision: str | None = Field(
        default=None, description="AgentPEP Intercept decision (if evaluated)"
    )
    bridge_latency_ms: int = Field(
        default=0, description="Bridge processing latency"
    )
    detail: str = Field(default="", description="Processing details")


# ---------------------------------------------------------------------------
# APEP-439: CIS scan verdict as taint input
# ---------------------------------------------------------------------------


class CISVerdictTaintRequest(BaseModel):
    """Request to apply a CIS scan verdict as a taint signal to a session."""

    session_id: str = Field(..., description="Session to apply taint to")
    scan_result_id: str = Field(
        default="", description="ID of the CIS scan result"
    )
    verdict: BridgeVerdictLevel = Field(
        ..., description="CIS scan verdict level"
    )
    source_path: str = Field(
        default="", description="Path/content that was scanned"
    )
    findings_count: int = Field(
        default=0, ge=0, description="Number of findings in the scan"
    )
    tier_results: list[dict] = Field(
        default_factory=list,
        description="Per-tier scan outcomes",
    )
    auto_taint: bool = Field(
        default=True,
        description="Whether to auto-apply taint based on verdict",
    )


class CISVerdictTaintResponse(BaseModel):
    """Response after applying a CIS verdict as taint."""

    applied: bool = Field(default=False, description="Whether taint was applied")
    taint_level: str | None = Field(
        default=None, description="Taint level that was applied"
    )
    session_id: str = Field(default="")
    detail: str = Field(default="")


# ---------------------------------------------------------------------------
# APEP-440: Agent-initiated policy modification self-protection
# ---------------------------------------------------------------------------


class SelfProtectionCheckRequest(BaseModel):
    """Request to check whether an operation is allowed by self-protection guards."""

    caller_type: str = Field(
        ..., description="Type of caller: 'human', 'agent', 'api_key'"
    )
    api_key_id: str = Field(default="", description="API key identifier if applicable")
    operation: str = Field(
        ..., description="Operation being attempted (e.g. 'policy.modify', 'rule.delete')"
    )
    target_resource: str = Field(
        default="", description="Resource being modified"
    )
    is_tty: bool = Field(
        default=False, description="Whether the request originates from a TTY terminal"
    )


class SelfProtectionCheckResponse(BaseModel):
    """Response from self-protection check."""

    allowed: bool = Field(default=False)
    action: SelfProtectionAction = Field(default=SelfProtectionAction.BLOCK)
    reason: str = Field(default="")
    guard_name: str = Field(default="", description="Which guard triggered")


class SelfProtectionEvent(BaseModel):
    """Audit event for a self-protection guard activation."""

    event_id: str = Field(default_factory=lambda: f"SP-{uuid4().hex[:8].upper()}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    caller_type: str = Field(default="")
    operation: str = Field(default="")
    target_resource: str = Field(default="")
    action_taken: SelfProtectionAction = Field(default=SelfProtectionAction.BLOCK)
    guard_name: str = Field(default="")
    detail: str = Field(default="")


# ---------------------------------------------------------------------------
# APEP-441: Protected path patterns for PreToolUse
# ---------------------------------------------------------------------------


class ProtectedPathPattern(BaseModel):
    """A pattern defining a protected file/resource path for PreToolUse.

    When a tool call targets a path matching this pattern, the specified
    action is taken (DENY, ESCALATE, or AUDIT_ONLY).
    """

    pattern_id: str = Field(
        default_factory=lambda: f"PP-{uuid4().hex[:8].upper()}",
        description="Unique pattern identifier",
    )
    path_glob: str = Field(
        ..., description="Glob pattern for protected paths (e.g. '**/.env', '**/CLAUDE.md')"
    )
    description: str = Field(default="", description="Why this path is protected")
    action: ProtectedPathAction = Field(
        default=ProtectedPathAction.DENY,
        description="Action when path is matched",
    )
    applies_to_tools: list[str] = Field(
        default_factory=lambda: ["file.write", "file.delete", "shell.exec"],
        description="Tool names this protection applies to",
    )
    enabled: bool = Field(default=True)
    builtin: bool = Field(default=False, description="True for built-in patterns")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ProtectedPathCheckResult(BaseModel):
    """Result of checking a tool call against protected path patterns."""

    blocked: bool = Field(default=False)
    matched_pattern_id: str = Field(default="")
    matched_glob: str = Field(default="")
    action: ProtectedPathAction = Field(default=ProtectedPathAction.DENY)
    detail: str = Field(default="")


class ProtectedPathListResponse(BaseModel):
    """Response for listing protected path patterns."""

    patterns: list[ProtectedPathPattern] = Field(default_factory=list)
    total: int = Field(default=0)


# ---------------------------------------------------------------------------
# SEQ rule detection result
# ---------------------------------------------------------------------------


class SEQRuleMatch(BaseModel):
    """Result when a CaMeL-lite SEQ rule is triggered."""

    rule_id: SEQRuleID = Field(description="Which SEQ rule matched")
    mode: SEQRuleMode = Field(description="Rule enforcement mode")
    markers_matched: list[str] = Field(
        default_factory=list,
        description="Marker IDs that contributed to the match",
    )
    detail: str = Field(default="")
    gap_count: int = Field(
        default=0, description="Number of gap events between matched markers"
    )
    session_id: str = Field(default="")


class SEQDetectionResult(BaseModel):
    """Aggregate SEQ rule detection result for a session."""

    session_id: str = Field(default="")
    matches: list[SEQRuleMatch] = Field(default_factory=list)
    total_matches: int = Field(default=0)
    has_enforcing_match: bool = Field(
        default=False,
        description="True if any ENFORCING rule matched",
    )
    detail: str = Field(default="No SEQ rules triggered")
