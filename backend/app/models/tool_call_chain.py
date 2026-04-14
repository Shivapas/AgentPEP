"""Pydantic models for Sprint 49 — Tool Call Chain Detection Engine.

APEP-388: ToolCallChain pattern model.
APEP-389: Subsequence matching engine models.
APEP-390: Built-in chain pattern library models.
APEP-391: Chain detector PolicyEvaluator integration models.
APEP-392: Chain detection escalation models.
APEP-393: Chain pattern management API models.
APEP-394: Chain detection metrics models.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ChainSeverity(StrEnum):
    """Severity level of a detected chain pattern."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ChainCategory(StrEnum):
    """Attack category for chain patterns."""

    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    RECONNAISSANCE = "RECONNAISSANCE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PERSISTENCE = "PERSISTENCE"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    DESTRUCTION = "DESTRUCTION"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    RESOURCE_ABUSE = "RESOURCE_ABUSE"


class ChainMatchStrategy(StrEnum):
    """Strategy for matching tool call sequences against patterns."""

    EXACT = "EXACT"
    SUBSEQUENCE = "SUBSEQUENCE"
    SLIDING_WINDOW = "SLIDING_WINDOW"


class ChainDetectionAction(StrEnum):
    """Action to take when a chain pattern is detected."""

    ALERT = "ALERT"
    ESCALATE = "ESCALATE"
    DENY = "DENY"
    LOG_ONLY = "LOG_ONLY"


class EscalationPriority(StrEnum):
    """Priority level for chain detection escalations."""

    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class EscalationStatus(StrEnum):
    """Status of a chain detection escalation."""

    PENDING = "PENDING"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DISMISSED = "DISMISSED"


class ChainEventType(StrEnum):
    """Kafka event types for agentpep.chain_detection topic."""

    CHAIN_DETECTED = "CHAIN_DETECTED"
    CHAIN_ESCALATED = "CHAIN_ESCALATED"
    CHAIN_PATTERN_CREATED = "CHAIN_PATTERN_CREATED"
    CHAIN_PATTERN_UPDATED = "CHAIN_PATTERN_UPDATED"
    CHAIN_PATTERN_DELETED = "CHAIN_PATTERN_DELETED"


# ---------------------------------------------------------------------------
# APEP-388: ToolCallChain pattern model
# ---------------------------------------------------------------------------


class ToolCallChainStep(BaseModel):
    """A single step in a chain pattern — a glob pattern for a tool name."""

    tool_pattern: str = Field(
        ..., description="Glob pattern matching tool names (e.g. 'secret.*', '*.read')"
    )
    optional: bool = Field(
        default=False,
        description="If True, this step can be skipped during matching",
    )
    max_gap: int = Field(
        default=10,
        ge=0,
        le=100,
        description="Maximum number of intervening tool calls allowed before this step",
    )


class ToolCallChainPattern(BaseModel):
    """A configurable attack sequence pattern (APEP-388).

    Defines an ordered sequence of tool call patterns that, when matched
    against session history, indicates a potential attack chain.
    """

    pattern_id: str = Field(
        default_factory=lambda: f"CP-{uuid4().hex[:8].upper()}",
        description="Unique pattern identifier",
    )
    name: str = Field(..., description="Human-readable pattern name")
    description: str = Field(default="", description="Detailed pattern description")
    steps: list[ToolCallChainStep] = Field(
        ..., min_length=2, description="Ordered sequence of tool call patterns"
    )
    category: ChainCategory = Field(
        default=ChainCategory.DATA_EXFILTRATION,
        description="MITRE ATT&CK-aligned attack category",
    )
    severity: ChainSeverity = Field(
        default=ChainSeverity.HIGH, description="Severity when pattern is matched"
    )
    action: ChainDetectionAction = Field(
        default=ChainDetectionAction.ESCALATE,
        description="Action to take on detection",
    )
    match_strategy: ChainMatchStrategy = Field(
        default=ChainMatchStrategy.SUBSEQUENCE,
        description="Strategy for matching tool history against this pattern",
    )
    window_seconds: int = Field(
        default=600,
        ge=30,
        le=86400,
        description="Time window in seconds for the chain to be considered active",
    )
    risk_boost: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Risk score boost when pattern is matched",
    )
    mitre_technique_id: str = Field(
        default="", description="MITRE ATT&CK technique ID (e.g. T1041)"
    )
    enabled: bool = Field(default=True, description="Whether this pattern is active")
    builtin: bool = Field(
        default=False,
        description="True for built-in patterns (cannot be deleted via API)",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# APEP-389: Subsequence matching engine result models
# ---------------------------------------------------------------------------


class ChainMatchedStep(BaseModel):
    """A matched step within a chain detection."""

    step_index: int = Field(description="Index of the step in the pattern")
    tool_name: str = Field(description="Actual tool name that matched")
    tool_pattern: str = Field(description="The glob pattern that was matched")
    timestamp: float = Field(description="Timestamp of the tool call")
    gap: int = Field(
        default=0, description="Number of intervening calls since previous step"
    )


class ChainMatchResult(BaseModel):
    """Result when a chain pattern is matched against session history (APEP-389)."""

    pattern_id: str = Field(description="ID of the matched pattern")
    pattern_name: str = Field(description="Name of the matched pattern")
    category: ChainCategory
    severity: ChainSeverity
    action: ChainDetectionAction
    risk_boost: float = Field(default=0.0)
    matched_steps: list[ChainMatchedStep] = Field(default_factory=list)
    match_strategy: ChainMatchStrategy = Field(default=ChainMatchStrategy.SUBSEQUENCE)
    chain_duration_s: float = Field(
        default=0.0, description="Time span from first to last matched step"
    )
    mitre_technique_id: str = Field(default="")
    description: str = Field(default="")
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Match confidence score"
    )


class ChainDetectionResult(BaseModel):
    """Aggregate result from the chain detection engine (APEP-391)."""

    session_id: str = Field(default="")
    agent_id: str = Field(default="")
    matches: list[ChainMatchResult] = Field(default_factory=list)
    total_matches: int = Field(default=0)
    max_risk_boost: float = Field(default=0.0)
    highest_severity: ChainSeverity = Field(default=ChainSeverity.INFO)
    recommended_action: ChainDetectionAction = Field(
        default=ChainDetectionAction.LOG_ONLY
    )
    detail: str = Field(default="No chain patterns detected")
    scan_latency_us: int = Field(default=0, description="Scan latency in microseconds")


# ---------------------------------------------------------------------------
# APEP-392: Chain detection escalation models
# ---------------------------------------------------------------------------


class ChainEscalation(BaseModel):
    """An escalation record created when a chain pattern is detected (APEP-392)."""

    escalation_id: UUID = Field(default_factory=uuid4)
    session_id: str = Field(default="")
    agent_id: str = Field(default="")
    pattern_id: str = Field(description="ID of the chain pattern that triggered escalation")
    pattern_name: str = Field(default="")
    category: ChainCategory = Field(default=ChainCategory.DATA_EXFILTRATION)
    severity: ChainSeverity = Field(default=ChainSeverity.HIGH)
    priority: EscalationPriority = Field(default=EscalationPriority.P2_HIGH)
    status: EscalationStatus = Field(default=EscalationStatus.PENDING)
    risk_boost: float = Field(default=0.0)
    matched_tools: list[str] = Field(default_factory=list)
    chain_duration_s: float = Field(default=0.0)
    mitre_technique_id: str = Field(default="")
    description: str = Field(default="")
    resolution_note: str = Field(default="")
    resolved_by: str = Field(default="")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resolved_at: datetime | None = Field(default=None)


# ---------------------------------------------------------------------------
# APEP-393: Chain pattern management API models
# ---------------------------------------------------------------------------


class ChainPatternCreateRequest(BaseModel):
    """Request body for creating a new chain pattern."""

    name: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=2048)
    steps: list[ToolCallChainStep] = Field(..., min_length=2, max_length=20)
    category: ChainCategory = Field(default=ChainCategory.DATA_EXFILTRATION)
    severity: ChainSeverity = Field(default=ChainSeverity.HIGH)
    action: ChainDetectionAction = Field(default=ChainDetectionAction.ESCALATE)
    match_strategy: ChainMatchStrategy = Field(default=ChainMatchStrategy.SUBSEQUENCE)
    window_seconds: int = Field(default=600, ge=30, le=86400)
    risk_boost: float = Field(default=0.8, ge=0.0, le=1.0)
    mitre_technique_id: str = Field(default="", max_length=32)
    enabled: bool = Field(default=True)


class ChainPatternUpdateRequest(BaseModel):
    """Request body for updating an existing chain pattern."""

    name: str | None = Field(default=None, min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=2048)
    steps: list[ToolCallChainStep] | None = Field(default=None, min_length=2, max_length=20)
    category: ChainCategory | None = None
    severity: ChainSeverity | None = None
    action: ChainDetectionAction | None = None
    match_strategy: ChainMatchStrategy | None = None
    window_seconds: int | None = Field(default=None, ge=30, le=86400)
    risk_boost: float | None = Field(default=None, ge=0.0, le=1.0)
    mitre_technique_id: str | None = Field(default=None, max_length=32)
    enabled: bool | None = None


class ChainPatternListResponse(BaseModel):
    """Response for listing chain patterns."""

    patterns: list[ToolCallChainPattern] = Field(default_factory=list)
    total: int = Field(default=0)


class ChainEscalationResolveRequest(BaseModel):
    """Request body for resolving a chain escalation."""

    status: EscalationStatus = Field(
        ..., description="New status (RESOLVED, FALSE_POSITIVE, DISMISSED)"
    )
    resolution_note: str = Field(default="", max_length=2048)
    resolved_by: str = Field(default="", max_length=256)


class ChainEscalationListResponse(BaseModel):
    """Response for listing chain escalations."""

    escalations: list[ChainEscalation] = Field(default_factory=list)
    total: int = Field(default=0)


# ---------------------------------------------------------------------------
# Kafka chain detection event (APEP-394)
# ---------------------------------------------------------------------------


class ChainDetectionEvent(BaseModel):
    """Kafka event published to agentpep.chain_detection topic."""

    event_id: UUID = Field(default_factory=uuid4)
    event_type: ChainEventType
    session_id: str = Field(default="")
    agent_id: str = Field(default="")
    pattern_id: str = Field(default="")
    pattern_name: str = Field(default="")
    category: ChainCategory | None = None
    severity: ChainSeverity | None = None
    action: ChainDetectionAction | None = None
    risk_boost: float = Field(default=0.0)
    matched_tools: list[str] = Field(default_factory=list)
    chain_duration_s: float = Field(default=0.0)
    mitre_technique_id: str = Field(default="")
    escalation_id: str = Field(default="")
    description: str = Field(default="")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
