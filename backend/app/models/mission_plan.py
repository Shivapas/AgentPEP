"""Sprint 37 models -- MissionPlan: Model, API & Lifecycle.

APEP-292: MissionPlan Pydantic model with all fields.
APEP-293: Ed25519 plan signing data model.
APEP-294: Plan creation request/response schemas.
APEP-295: Plan retrieval response schema.
APEP-296: Plan revocation schema.
APEP-297: Plan-session binding schema.
APEP-298: Plan TTL expiry model.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# APEP-292: MissionPlan Status Enum
# ---------------------------------------------------------------------------


class PlanStatus(StrEnum):
    """Lifecycle states for a MissionPlan."""

    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


# ---------------------------------------------------------------------------
# APEP-292 / APEP-293: Plan Budget Model
# ---------------------------------------------------------------------------


class PlanBudget(BaseModel):
    """Budget constraints for a MissionPlan.

    When any budget dimension is exceeded the plan transitions to EXPIRED.
    A ``null`` value means unlimited for that dimension.
    """

    max_delegations: int | None = Field(
        default=None,
        description="Plan expires after N total ALLOW decisions; null = unlimited",
    )
    max_risk_total: float | None = Field(
        default=None,
        description="Plan expires when accumulated risk score exceeds this; null = unlimited",
    )
    ttl_seconds: int | None = Field(
        default=None,
        description="Plan expires N seconds after issuance; null = no expiry",
    )


# ---------------------------------------------------------------------------
# APEP-292: MissionPlan Model
# ---------------------------------------------------------------------------


class MissionPlan(BaseModel):
    """First-class authorization plan issued by a human.

    A MissionPlan is the root of a receipt chain. It binds scope, delegates,
    checkpoints, and budget into a single signed document.  Sessions are
    optionally bound to plans; when bound, plan-level constraints layer on
    top of existing RBAC and risk engine decisions.
    """

    plan_id: UUID = Field(default_factory=uuid4, description="Unique plan identifier")
    action: str = Field(
        ...,
        description="Human-readable intent label (e.g. 'Analyze Q3 finance reports')",
    )
    issuer: str = Field(
        ...,
        description="Identity of the human issuing the plan (email / SSO subject)",
    )
    scope: list[str] = Field(
        default_factory=list,
        description="Allowed action patterns in verb:namespace:resource notation",
    )
    requires_checkpoint: list[str] = Field(
        default_factory=list,
        description="Action patterns that trigger ESCALATE regardless of RBAC",
    )
    delegates_to: list[str] = Field(
        default_factory=list,
        description="Agent IDs permitted to receive delegation; [] = no sub-delegation",
    )
    budget: PlanBudget = Field(
        default_factory=PlanBudget,
        description="Budget constraints (TTL, max_delegations, max_risk_total)",
    )
    # Sprint 41 — APEP-327: Human intent propagation
    human_intent: str = Field(
        default="",
        description="Explicit human intent to propagate through the pipeline",
    )
    status: PlanStatus = Field(
        default=PlanStatus.ACTIVE,
        description="Current plan lifecycle state",
    )
    signature: str = Field(
        default="",
        description="Ed25519 signature over canonical plan fields",
    )
    issued_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC issuance timestamp",
    )
    expires_at: datetime | None = Field(
        default=None,
        description="Computed from issued_at + ttl_seconds; null if no TTL",
    )

    # --- Runtime budget tracking (not part of signature) ---
    delegation_count: int = Field(
        default=0,
        ge=0,
        description="Number of ALLOW decisions issued under this plan",
    )
    accumulated_risk: float = Field(
        default=0.0,
        ge=0.0,
        description="Accumulated risk score across all decisions under this plan",
    )

    @property
    def is_active(self) -> bool:
        """Check if the plan is currently active (not expired or revoked)."""
        if self.status != PlanStatus.ACTIVE:
            return False
        if self.expires_at is not None and datetime.now(UTC) >= self.expires_at:
            return False
        return True

    @property
    def budget_exhausted(self) -> bool:
        """Check if any budget dimension has been exceeded."""
        if (
            self.budget.max_delegations is not None
            and self.delegation_count >= self.budget.max_delegations
        ):
            return True
        if (
            self.budget.max_risk_total is not None
            and self.accumulated_risk >= self.budget.max_risk_total
        ):
            return True
        return False


# ---------------------------------------------------------------------------
# APEP-293: Plan Denial Reason Codes
# ---------------------------------------------------------------------------


class PlanDenialReason(StrEnum):
    """Reason codes for plan-level DENY decisions."""

    PLAN_BUDGET_EXHAUSTED = "PLAN_BUDGET_EXHAUSTED"
    PLAN_EXPIRED = "PLAN_EXPIRED"
    PLAN_REVOKED = "PLAN_REVOKED"
    PLAN_AGENT_NOT_AUTHORIZED = "PLAN_AGENT_NOT_AUTHORIZED"
    PLAN_NOT_BOUND = "PLAN_NOT_BOUND"


# ---------------------------------------------------------------------------
# APEP-294: Plan Creation Request / Response
# ---------------------------------------------------------------------------


class CreatePlanRequest(BaseModel):
    """Request body for POST /v1/plans."""

    action: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Human-readable intent label",
    )
    issuer: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Identity of the human issuing the plan",
    )
    scope: list[str] = Field(
        default_factory=list,
        description="Allowed action patterns in verb:namespace:resource notation",
    )
    requires_checkpoint: list[str] = Field(
        default_factory=list,
        description="Action patterns that trigger ESCALATE",
    )
    delegates_to: list[str] = Field(
        default_factory=list,
        description="Agent IDs permitted to receive delegation",
    )
    budget: PlanBudget = Field(
        default_factory=PlanBudget,
        description="Budget constraints",
    )
    # Sprint 41 — APEP-327: Human intent propagation
    human_intent: str = Field(
        default="",
        max_length=1000,
        description="Explicit human intent to propagate through the evaluation pipeline",
    )


class CreatePlanResponse(BaseModel):
    """Response body for POST /v1/plans."""

    plan_id: UUID
    action: str
    issuer: str
    status: PlanStatus
    signature: str
    issued_at: datetime
    expires_at: datetime | None = None


# ---------------------------------------------------------------------------
# APEP-295: Plan Retrieval Response
# ---------------------------------------------------------------------------


class PlanDetailResponse(BaseModel):
    """Response body for GET /v1/plans/{plan_id}."""

    plan_id: UUID
    action: str
    issuer: str
    scope: list[str]
    requires_checkpoint: list[str]
    delegates_to: list[str]
    budget: PlanBudget
    human_intent: str = ""
    status: PlanStatus
    signature: str
    issued_at: datetime
    expires_at: datetime | None = None
    delegation_count: int = 0
    accumulated_risk: float = 0.0
    is_active: bool = True
    budget_exhausted: bool = False


# ---------------------------------------------------------------------------
# APEP-296: Plan Revocation
# ---------------------------------------------------------------------------


class RevokePlanResponse(BaseModel):
    """Response body for DELETE /v1/plans/{plan_id}."""

    plan_id: UUID
    status: PlanStatus
    revoked_at: datetime


# ---------------------------------------------------------------------------
# APEP-297: Plan-Session Binding
# ---------------------------------------------------------------------------


class PlanSessionBinding(BaseModel):
    """Binding record linking a session to a MissionPlan."""

    binding_id: UUID = Field(default_factory=uuid4)
    plan_id: UUID
    session_id: str
    agent_id: str
    bound_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    unbound_at: datetime | None = None
    active: bool = True


class BindPlanRequest(BaseModel):
    """Request body for POST /v1/plans/{plan_id}/bind."""

    session_id: str = Field(..., min_length=1, description="Session to bind to the plan")
    agent_id: str = Field(..., min_length=1, description="Agent initiating the binding")


class BindPlanResponse(BaseModel):
    """Response body for POST /v1/plans/{plan_id}/bind."""

    binding_id: UUID
    plan_id: UUID
    session_id: str
    agent_id: str
    bound_at: datetime
