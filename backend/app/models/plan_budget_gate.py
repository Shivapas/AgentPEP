"""Sprint 40 models -- Declarative Delegates-To & Plan Budget Gate.

APEP-316: PlanDelegatesToFilter data model.
APEP-317: delegates_to enforcement data model.
APEP-318: PlanBudgetGate data model with Redis-backed budget state.
APEP-319: Budget exhaustion enforcement data model.
APEP-320: Budget status API response model.
APEP-321: Budget alert event model.
APEP-322: Plan budget reset model.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# APEP-316: PlanDelegatesToFilter result model
# ---------------------------------------------------------------------------


class DelegationCheckResult(BaseModel):
    """Result of checking whether an agent is authorized under a plan's
    delegates_to whitelist."""

    authorized: bool = Field(
        ..., description="True if the agent is authorized"
    )
    agent_id: str = Field(..., description="Agent ID that was checked")
    plan_id: UUID = Field(..., description="Plan ID that was checked against")
    reason: str = Field(
        default="", description="Human-readable explanation of the result"
    )


# ---------------------------------------------------------------------------
# APEP-318 / APEP-319: PlanBudgetGate state model
# ---------------------------------------------------------------------------


class BudgetDimension(StrEnum):
    """Dimensions of a plan budget that can be exhausted."""

    DELEGATION_COUNT = "DELEGATION_COUNT"
    RISK_TOTAL = "RISK_TOTAL"
    TTL = "TTL"


class BudgetCheckResult(BaseModel):
    """Result of a PlanBudgetGate check against a plan's budget."""

    allowed: bool = Field(
        ..., description="True if the plan budget permits this operation"
    )
    plan_id: UUID = Field(..., description="Plan ID checked")
    exhausted_dimensions: list[BudgetDimension] = Field(
        default_factory=list,
        description="Budget dimensions that are exhausted",
    )
    reason: str = Field(
        default="", description="Human-readable explanation"
    )
    delegation_count: int = Field(
        default=0, description="Current delegation count"
    )
    accumulated_risk: float = Field(
        default=0.0, description="Current accumulated risk score"
    )
    remaining_delegations: int | None = Field(
        default=None, description="Remaining delegations before exhaustion"
    )
    remaining_risk_budget: float | None = Field(
        default=None, description="Remaining risk budget before exhaustion"
    )
    ttl_remaining_seconds: int | None = Field(
        default=None, description="Seconds remaining before TTL expiry"
    )


# ---------------------------------------------------------------------------
# APEP-319: Budget state tracking (Redis-backed)
# ---------------------------------------------------------------------------


class PlanBudgetState(BaseModel):
    """Redis-backed budget state for a MissionPlan.

    Tracks real-time delegation count and accumulated risk score for
    a plan, stored in Redis for low-latency budget gate checks.
    """

    plan_id: UUID = Field(..., description="Plan this state belongs to")
    delegation_count: int = Field(
        default=0, ge=0, description="Number of ALLOW decisions issued"
    )
    accumulated_risk: float = Field(
        default=0.0, ge=0.0, description="Accumulated risk score"
    )
    last_updated: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Last time this state was updated",
    )


# ---------------------------------------------------------------------------
# APEP-320: Budget Status API response
# ---------------------------------------------------------------------------


class BudgetStatusResponse(BaseModel):
    """Response model for GET /v1/plans/{plan_id}/budget."""

    plan_id: UUID
    status: str = Field(
        ..., description="ACTIVE, EXPIRED, REVOKED, or BUDGET_EXHAUSTED"
    )
    delegation_count: int = Field(default=0)
    max_delegations: int | None = Field(default=None)
    accumulated_risk: float = Field(default=0.0)
    max_risk_total: float | None = Field(default=None)
    ttl_seconds: int | None = Field(default=None)
    ttl_remaining_seconds: int | None = Field(default=None)
    issued_at: datetime
    expires_at: datetime | None = None
    exhausted_dimensions: list[BudgetDimension] = Field(default_factory=list)
    budget_utilization: BudgetUtilization | None = None


class BudgetUtilization(BaseModel):
    """Percentage utilization of each budget dimension."""

    delegation_pct: float | None = Field(
        default=None, description="Delegation usage percentage (0-100)"
    )
    risk_pct: float | None = Field(
        default=None, description="Risk usage percentage (0-100)"
    )
    ttl_pct: float | None = Field(
        default=None, description="TTL usage percentage (0-100)"
    )


# ---------------------------------------------------------------------------
# APEP-321: Budget Alert Events
# ---------------------------------------------------------------------------


class BudgetAlertLevel(StrEnum):
    """Severity levels for budget alert events."""

    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    EXHAUSTED = "EXHAUSTED"


class BudgetAlertEvent(BaseModel):
    """Event emitted when a plan's budget reaches a threshold."""

    alert_id: UUID = Field(default_factory=uuid4)
    plan_id: UUID
    alert_level: BudgetAlertLevel
    dimension: BudgetDimension
    current_value: float = Field(
        ..., description="Current value of the exhausted dimension"
    )
    threshold_value: float = Field(
        ..., description="Threshold that triggered the alert"
    )
    max_value: float = Field(
        ..., description="Maximum budget value for this dimension"
    )
    utilization_pct: float = Field(
        ..., description="Current utilization percentage"
    )
    message: str = Field(default="", description="Human-readable alert message")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# APEP-322: Plan Budget Reset
# ---------------------------------------------------------------------------


class BudgetResetRequest(BaseModel):
    """Request body for POST /v1/plans/{plan_id}/budget/reset."""

    reset_delegations: bool = Field(
        default=True, description="Reset delegation count to zero"
    )
    reset_risk: bool = Field(
        default=True, description="Reset accumulated risk to zero"
    )
    new_max_delegations: int | None = Field(
        default=None, description="Optionally set a new max_delegations"
    )
    new_max_risk_total: float | None = Field(
        default=None, description="Optionally set a new max_risk_total"
    )
    new_ttl_seconds: int | None = Field(
        default=None, description="Optionally set a new TTL (from now)"
    )
    reason: str = Field(
        default="", max_length=500, description="Reason for the reset"
    )


class BudgetResetResponse(BaseModel):
    """Response body for POST /v1/plans/{plan_id}/budget/reset."""

    plan_id: UUID
    reset_at: datetime
    previous_delegation_count: int
    previous_accumulated_risk: float
    new_delegation_count: int
    new_accumulated_risk: float
    budget_updated: bool = Field(
        default=False, description="True if budget limits were changed"
    )
    plan_reactivated: bool = Field(
        default=False,
        description="True if the plan was reactivated from EXPIRED status",
    )
