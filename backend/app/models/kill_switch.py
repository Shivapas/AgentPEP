"""Pydantic models for Sprint 50 — Kill Switch, Filesystem Sentinel & Adaptive Threat Score.

APEP-396: KillSwitch service data model.
APEP-397: Kill switch activation sources model.
APEP-398: Kill switch isolated API port model.
APEP-399: FilesystemSentinel service data model.
APEP-400: Process lineage attribution model.
APEP-401: AdaptiveThreatScore data model.
APEP-402: De-escalation timer data model.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class KillSwitchState(StrEnum):
    """Overall kill switch state."""

    ARMED = "ARMED"
    DISARMED = "DISARMED"


class KillSwitchSource(StrEnum):
    """The 4 independent activation sources for the kill switch."""

    API_ENDPOINT = "API_ENDPOINT"
    SIGNAL_SIGUSR1 = "SIGNAL_SIGUSR1"
    SENTINEL_FILE = "SENTINEL_FILE"
    CONFIG_FLAG = "CONFIG_FLAG"


class KillSwitchEventType(StrEnum):
    """Kafka event types for kill switch events."""

    KILL_SWITCH_ACTIVATED = "KILL_SWITCH_ACTIVATED"
    KILL_SWITCH_DEACTIVATED = "KILL_SWITCH_DEACTIVATED"
    KILL_SWITCH_HEARTBEAT = "KILL_SWITCH_HEARTBEAT"


class SentinelEventType(StrEnum):
    """Types of filesystem sentinel events."""

    SECRET_DETECTED = "SECRET_DETECTED"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_CREATED = "FILE_CREATED"
    FILE_DELETED = "FILE_DELETED"
    SUSPICIOUS_ACCESS = "SUSPICIOUS_ACCESS"


class SentinelSeverity(StrEnum):
    """Severity levels for sentinel findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ThreatScoreEventType(StrEnum):
    """Event types that contribute to the adaptive threat score."""

    NETWORK_DLP_HIT = "NETWORK_DLP_HIT"
    INJECTION_DETECTED = "INJECTION_DETECTED"
    SSRF_BLOCKED = "SSRF_BLOCKED"
    CHAIN_DETECTED = "CHAIN_DETECTED"
    KILL_SWITCH_ACTIVATED = "KILL_SWITCH_ACTIVATED"
    SENTINEL_HIT = "SENTINEL_HIT"
    ESCALATION_TRIGGERED = "ESCALATION_TRIGGERED"
    DENY_DECISION = "DENY_DECISION"
    PROCESS_LINEAGE_ALERT = "PROCESS_LINEAGE_ALERT"


class DeescalationState(StrEnum):
    """State of a de-escalation timer."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


# ---------------------------------------------------------------------------
# APEP-396: KillSwitch service models
# ---------------------------------------------------------------------------


class KillSwitchActivation(BaseModel):
    """Record of a single kill switch activation."""

    activation_id: UUID = Field(default_factory=uuid4)
    source: KillSwitchSource
    activated_by: str = Field(default="", description="Identity or process that triggered activation")
    reason: str = Field(default="", description="Reason for activation")
    activated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class KillSwitchStatus(BaseModel):
    """Current kill switch state."""

    state: KillSwitchState = Field(default=KillSwitchState.DISARMED)
    activated: bool = Field(default=False)
    activations: list[KillSwitchActivation] = Field(default_factory=list)
    last_activated_at: datetime | None = Field(default=None)
    last_deactivated_at: datetime | None = Field(default=None)
    active_sources: list[KillSwitchSource] = Field(default_factory=list)
    total_activations: int = Field(default=0)


class KillSwitchActivateRequest(BaseModel):
    """Request to activate the kill switch via API endpoint."""

    reason: str = Field(default="Manual activation", max_length=1024)
    activated_by: str = Field(default="api", max_length=256)


class KillSwitchDeactivateRequest(BaseModel):
    """Request to deactivate the kill switch via API endpoint."""

    reason: str = Field(default="Manual deactivation", max_length=1024)
    deactivated_by: str = Field(default="api", max_length=256)


# ---------------------------------------------------------------------------
# APEP-399: FilesystemSentinel models
# ---------------------------------------------------------------------------


class SentinelFinding(BaseModel):
    """A finding from the filesystem sentinel."""

    finding_id: UUID = Field(default_factory=uuid4)
    event_type: SentinelEventType
    severity: SentinelSeverity = Field(default=SentinelSeverity.MEDIUM)
    file_path: str = Field(default="")
    rule_id: str = Field(default="", description="DLP pattern or rule that matched")
    description: str = Field(default="")
    matched_text: str = Field(default="", description="Redacted snippet of matched content")
    process_pid: int | None = Field(default=None, description="PID of the process that caused the event")
    process_name: str = Field(default="", description="Name of the process")
    process_lineage: list[str] = Field(default_factory=list, description="Process ancestry chain")
    mitre_technique_id: str = Field(default="", description="MITRE ATT&CK technique ID")
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SentinelConfig(BaseModel):
    """Configuration for the filesystem sentinel."""

    watch_paths: list[str] = Field(
        default_factory=lambda: ["/tmp", "/var/tmp"],
        description="Directories to watch for file changes",
    )
    file_patterns: list[str] = Field(
        default_factory=lambda: ["*.env", "*.key", "*.pem", "*.secret", "*.credentials"],
        description="File glob patterns to monitor",
    )
    scan_on_create: bool = Field(default=True, description="Scan file content on creation")
    scan_on_modify: bool = Field(default=True, description="Scan file content on modification")
    max_file_scan_bytes: int = Field(default=1_048_576, description="Max bytes to scan per file (1MB)")
    enabled: bool = Field(default=True)


class SentinelStatus(BaseModel):
    """Current filesystem sentinel status."""

    running: bool = Field(default=False)
    watch_paths: list[str] = Field(default_factory=list)
    findings_count: int = Field(default=0)
    last_finding_at: datetime | None = Field(default=None)
    uptime_seconds: float = Field(default=0.0)


# ---------------------------------------------------------------------------
# APEP-400: Process lineage attribution models
# ---------------------------------------------------------------------------


class ProcessInfo(BaseModel):
    """Information about a single process in the lineage chain."""

    pid: int
    ppid: int = Field(default=0, description="Parent PID")
    name: str = Field(default="")
    cmdline: str = Field(default="", description="Full command line")
    exe: str = Field(default="", description="Executable path")
    uid: int = Field(default=-1)
    username: str = Field(default="")
    start_time: float = Field(default=0.0, description="Process start time (epoch)")


class ProcessLineage(BaseModel):
    """Full process lineage from a target PID to init."""

    target_pid: int
    lineage: list[ProcessInfo] = Field(
        default_factory=list,
        description="Process chain from target to init (target first)",
    )
    trusted: bool = Field(default=False, description="Whether the process chain is trusted")
    trust_reason: str = Field(default="", description="Why the lineage is/isn't trusted")
    suspicious_indicators: list[str] = Field(
        default_factory=list,
        description="List of suspicious patterns found in the lineage",
    )


# ---------------------------------------------------------------------------
# APEP-401: AdaptiveThreatScore models
# ---------------------------------------------------------------------------


class ThreatSignal(BaseModel):
    """A single threat signal contributing to the adaptive score."""

    signal_id: UUID = Field(default_factory=uuid4)
    event_type: ThreatScoreEventType
    severity_weight: float = Field(default=0.1, ge=0.0, le=1.0)
    source: str = Field(default="", description="Source service that generated the signal")
    description: str = Field(default="")
    session_id: str = Field(default="")
    agent_id: str = Field(default="")
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AdaptiveThreatScoreResult(BaseModel):
    """Current adaptive threat score for a session."""

    session_id: str = Field(default="")
    agent_id: str = Field(default="")
    score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Adaptive threat score (0.0=safe, 1.0=maximum threat)",
    )
    signal_count: int = Field(default=0, description="Number of contributing signals")
    signals: list[ThreatSignal] = Field(default_factory=list)
    highest_event_type: ThreatScoreEventType | None = Field(default=None)
    escalation_recommended: bool = Field(default=False)
    de_escalation_eligible: bool = Field(default=False)
    window_seconds: int = Field(default=600, description="Scoring window in seconds")
    computed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ThreatScoreRequest(BaseModel):
    """Request to compute/retrieve a session's adaptive threat score."""

    session_id: str = Field(..., min_length=1)
    agent_id: str = Field(default="")
    include_signals: bool = Field(default=False, description="Include individual signals in response")


# ---------------------------------------------------------------------------
# APEP-402: De-escalation timer models
# ---------------------------------------------------------------------------


class DeescalationTimer(BaseModel):
    """A de-escalation timer that counts down after threat subsides."""

    timer_id: UUID = Field(default_factory=uuid4)
    session_id: str = Field(default="")
    agent_id: str = Field(default="")
    state: DeescalationState = Field(default=DeescalationState.PENDING)
    initial_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Threat score when timer was created",
    )
    current_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Current decayed threat score",
    )
    target_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Score to decay to before completing",
    )
    decay_rate: float = Field(
        default=0.1, ge=0.01, le=1.0,
        description="Score reduction per interval",
    )
    interval_seconds: int = Field(
        default=60, ge=10, le=3600,
        description="Seconds between decay steps",
    )
    total_duration_seconds: int = Field(
        default=600, ge=30, le=86400,
        description="Maximum timer duration before auto-completion",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    cancelled_at: datetime | None = Field(default=None)
    cancel_reason: str = Field(default="")


class DeescalationTimerStatus(BaseModel):
    """Summary of active de-escalation timers for a session."""

    session_id: str = Field(default="")
    active_timers: list[DeescalationTimer] = Field(default_factory=list)
    total_timers: int = Field(default=0)
    earliest_completion: datetime | None = Field(default=None)


# ---------------------------------------------------------------------------
# Kafka event models
# ---------------------------------------------------------------------------


class KillSwitchEvent(BaseModel):
    """Kafka event for kill switch state changes."""

    event_id: UUID = Field(default_factory=uuid4)
    event_type: KillSwitchEventType
    source: KillSwitchSource | None = None
    activated_by: str = Field(default="")
    reason: str = Field(default="")
    state: KillSwitchState = Field(default=KillSwitchState.DISARMED)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SentinelEvent(BaseModel):
    """Kafka event for filesystem sentinel findings."""

    event_id: UUID = Field(default_factory=uuid4)
    session_id: str | None = None
    agent_id: str | None = None
    event_type: SentinelEventType
    severity: SentinelSeverity = Field(default=SentinelSeverity.MEDIUM)
    file_path: str = Field(default="")
    rule_id: str = Field(default="")
    process_name: str = Field(default="")
    process_pid: int | None = None
    mitre_technique_id: str = Field(default="")
    blocked: bool = Field(default=False)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ThreatScoreEvent(BaseModel):
    """Kafka event for adaptive threat score changes."""

    event_id: UUID = Field(default_factory=uuid4)
    session_id: str = Field(default="")
    agent_id: str = Field(default="")
    previous_score: float = Field(default=0.0)
    new_score: float = Field(default=0.0)
    trigger_event_type: ThreatScoreEventType | None = None
    escalation_recommended: bool = Field(default=False)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
