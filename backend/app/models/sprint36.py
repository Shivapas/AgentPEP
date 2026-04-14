"""Sprint 36 models — ToolTrust: Conflict Detection, Metrics, Tamper Detection & Multi-Tenancy.

APEP-285: HashChainedContext — tamper-evident context chain with SHA-256 hashes.
APEP-286: TrustDegradationEngine — Pydantic model for real-time trust ceiling tracking.
APEP-287: DEFER decision type schema with conditions and timeout.
APEP-288: STEP_UP decision type schema with auth factor requirements.
APEP-289: Policy conflict detection with resolution strategies.
APEP-290: Multi-tenancy data isolation model.
APEP-291: Prometheus metrics schema.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# APEP-285: HashChainedContext
# ---------------------------------------------------------------------------


class HashChainedContextEntry(BaseModel):
    """A single entry in a hash-chained context sequence.

    Each entry contains a SHA-256 hash linking it to the previous entry,
    creating a tamper-evident chain. Any modification to a prior entry
    invalidates all subsequent hashes.
    """

    entry_id: UUID = Field(default_factory=uuid4)
    session_id: str
    sequence_number: int = Field(ge=0, description="Monotonic position in the chain")
    content_hash: str = Field(
        ..., description="SHA-256 hash of the entry content"
    )
    previous_hash: str = Field(
        default="", description="SHA-256 hash of the previous entry (empty for genesis)"
    )
    chain_hash: str = Field(
        default="",
        description="SHA-256 of (previous_hash || content_hash) — the chain link",
    )
    source: str = Field(default="", description="Origin source of this context entry")
    agent_id: str | None = None
    tenant_id: str = Field(default="default")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class HashChainVerificationResult(BaseModel):
    """Result of verifying a hash-chained context sequence."""

    valid: bool
    total_entries: int = 0
    verified_entries: int = 0
    first_tampered_sequence: int | None = None
    first_tampered_entry_id: str | None = None
    detail: str = ""


# ---------------------------------------------------------------------------
# APEP-286: TrustDegradationEngine (Pydantic model)
# ---------------------------------------------------------------------------


class TrustDegradationRecord(BaseModel):
    """Persistent record of trust ceiling state for a session.

    Tracks the current trust ceiling and degradation history so the
    TrustDegradationEngine can resume from the last known state.
    """

    record_id: UUID = Field(default_factory=uuid4)
    session_id: str
    tenant_id: str = Field(default="default")
    current_ceiling: float = Field(default=1.0, ge=0.0, le=1.0)
    initial_ceiling: float = Field(default=1.0, ge=0.0, le=1.0)
    total_degradation: float = Field(default=0.0, ge=0.0, le=1.0)
    degradation_count: int = Field(default=0, ge=0)
    last_degradation_reason: str = ""
    locked: bool = Field(
        default=False,
        description="Whether the session is locked due to trust floor breach",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# APEP-287: DEFER decision schema
# ---------------------------------------------------------------------------


class DeferCondition(StrEnum):
    """Conditions under which a DEFER decision is issued."""

    PENDING_REVIEW = "PENDING_REVIEW"
    AWAITING_CONTEXT = "AWAITING_CONTEXT"
    RATE_LIMITED = "RATE_LIMITED"
    TRUST_DEGRADED = "TRUST_DEGRADED"
    POLICY_AMBIGUOUS = "POLICY_AMBIGUOUS"


class DeferDecisionRecord(BaseModel):
    """Record of a DEFER decision awaiting resolution."""

    defer_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    session_id: str
    agent_id: str
    tool_name: str
    condition: DeferCondition = DeferCondition.PENDING_REVIEW
    reason: str = ""
    timeout_s: int = Field(default=60, ge=1, le=3600)
    auto_deny_on_timeout: bool = True
    resolved: bool = False
    resolution: str | None = None
    tenant_id: str = Field(default="default")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resolved_at: datetime | None = None


# ---------------------------------------------------------------------------
# APEP-288: STEP_UP decision schema
# ---------------------------------------------------------------------------


class StepUpFactor(StrEnum):
    """Authentication factors that can be required for STEP_UP."""

    MFA = "mfa"
    BIOMETRIC = "biometric"
    MANAGER_APPROVAL = "manager_approval"
    SMS_OTP = "sms_otp"
    EMAIL_OTP = "email_otp"
    HARDWARE_TOKEN = "hardware_token"


class StepUpChallengeStatus(StrEnum):
    """Status of a STEP_UP authentication challenge."""

    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class StepUpChallenge(BaseModel):
    """A STEP_UP authentication challenge issued to the caller."""

    challenge_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    session_id: str
    agent_id: str
    required_factors: list[str] = Field(
        default_factory=list,
        description="Auth factors required (e.g., ['mfa', 'manager_approval'])",
    )
    verified_factors: list[str] = Field(
        default_factory=list,
        description="Factors already verified",
    )
    status: StepUpChallengeStatus = StepUpChallengeStatus.PENDING
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Challenge expiry time",
    )
    tenant_id: str = Field(default="default")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# APEP-289: Policy conflict detection models
# ---------------------------------------------------------------------------


class ConflictSeverity(StrEnum):
    """Severity of a policy conflict."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConflictResolutionStrategy(StrEnum):
    """Strategies for resolving policy conflicts."""

    PRIORITY_WINS = "PRIORITY_WINS"
    MOST_RESTRICTIVE = "MOST_RESTRICTIVE"
    MOST_PERMISSIVE = "MOST_PERMISSIVE"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class PolicyConflict(BaseModel):
    """A detected conflict between two or more policy rules."""

    conflict_id: UUID = Field(default_factory=uuid4)
    rule_ids: list[str] = Field(
        ..., description="IDs of conflicting rules"
    )
    rule_names: list[str] = Field(default_factory=list)
    overlap_type: str = Field(
        default="action_conflict",
        description="Type: action_conflict, scope_overlap, priority_tie",
    )
    severity: ConflictSeverity = ConflictSeverity.MEDIUM
    detail: str = ""
    resolution_strategy: ConflictResolutionStrategy = ConflictResolutionStrategy.PRIORITY_WINS
    resolved: bool = False
    resolution_detail: str = ""
    tenant_id: str = Field(default="default")
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ConflictReport(BaseModel):
    """Summary report of all detected policy conflicts."""

    total_rules_scanned: int = 0
    total_conflicts: int = 0
    conflicts: list[PolicyConflict] = Field(default_factory=list)
    resolution_strategy: ConflictResolutionStrategy = ConflictResolutionStrategy.PRIORITY_WINS
    scan_duration_ms: int = 0
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# APEP-290: Multi-tenancy data isolation
# ---------------------------------------------------------------------------


class TenantIsolationConfig(BaseModel):
    """Per-tenant data isolation configuration."""

    tenant_id: str = Field(..., description="Unique tenant identifier")
    display_name: str = ""
    data_boundary: str = Field(
        default="STRICT",
        description="STRICT: no cross-tenant data; SHARED: allow read-only cross-tenant",
    )
    allowed_peer_tenants: list[str] = Field(
        default_factory=list,
        description="Tenant IDs allowed for cross-tenant data access (SHARED mode only)",
    )
    max_sessions: int = Field(default=10000, ge=1)
    max_agents: int = Field(default=1000, ge=1)
    max_rules: int = Field(default=5000, ge=1)
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TenantIsolationViolation(BaseModel):
    """Record of a detected tenant isolation violation."""

    violation_id: UUID = Field(default_factory=uuid4)
    source_tenant_id: str
    target_tenant_id: str
    resource_type: str = Field(
        description="Type of resource accessed: session, rule, agent, audit"
    )
    resource_id: str = ""
    detail: str = ""
    blocked: bool = True
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
