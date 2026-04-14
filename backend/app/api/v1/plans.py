"""Sprint 37 API -- MissionPlan CRUD and session binding endpoints.

APEP-294: POST /v1/plans -- create and issue a signed plan.
APEP-295: GET /v1/plans/{plan_id} -- retrieve plan with budget status.
APEP-296: DELETE /v1/plans/{plan_id} -- revoke plan.
APEP-297: POST /v1/plans/{plan_id}/bind -- bind plan to session.

Sprint 39 — Receipt chaining with plan root:
APEP-311: GET /v1/plans/{plan_id}/receipts -- return full receipt chain.
APEP-312: GET /v1/plans/{plan_id}/receipts/summary -- return chain summary.

Sprint 40 — Declarative Delegates-To & Plan Budget Gate:
APEP-316.d: GET /v1/plans/{plan_id}/delegates/{agent_id} -- check delegation.
APEP-318.d: GET /v1/plans/{plan_id}/budget -- budget gate status.
APEP-319.d: POST /v1/plans/{plan_id}/budget/check -- budget enforcement check.
APEP-320: GET /v1/plans/{plan_id}/budget -- budget status API.
APEP-322: POST /v1/plans/{plan_id}/budget/reset -- reset plan budget.
"""

from uuid import UUID

from fastapi import APIRouter, HTTPException

from app.models.mission_plan import (
    BindPlanRequest,
    BindPlanResponse,
    CreatePlanRequest,
    CreatePlanResponse,
    PlanDetailResponse,
    RevokePlanResponse,
)
from app.models.plan_budget_gate import (
    BudgetResetRequest,
    BudgetResetResponse,
    BudgetStatusResponse,
    DelegationCheckResult,
)
from app.services.mission_plan_service import mission_plan_service
from app.services.plan_budget_gate import plan_budget_gate
from app.services.plan_delegates_filter import plan_delegates_filter
from app.services.receipt_chain import (
    ReceiptChainResponse,
    ReceiptChainSummary,
    receipt_chain_manager,
)

router = APIRouter(prefix="/v1", tags=["plans"])


# ---------------------------------------------------------------------------
# APEP-294: POST /v1/plans
# ---------------------------------------------------------------------------


@router.post("/plans", response_model=CreatePlanResponse, status_code=201)
async def create_plan(request: CreatePlanRequest) -> CreatePlanResponse:
    """Create and issue a new signed MissionPlan.

    The plan is signed with Ed25519 (or HMAC-SHA256 fallback) and stored
    in MongoDB.  If a TTL is specified in the budget, ``expires_at`` is
    computed automatically.
    """
    plan = await mission_plan_service.create_plan(request)
    return CreatePlanResponse(
        plan_id=plan.plan_id,
        action=plan.action,
        issuer=plan.issuer,
        status=plan.status,
        signature=plan.signature,
        issued_at=plan.issued_at,
        expires_at=plan.expires_at,
    )


# ---------------------------------------------------------------------------
# APEP-295: GET /v1/plans/{plan_id}
# ---------------------------------------------------------------------------


@router.get("/plans/{plan_id}", response_model=PlanDetailResponse)
async def get_plan(plan_id: UUID) -> PlanDetailResponse:
    """Retrieve a MissionPlan by ID with budget usage status.

    If the plan's TTL has elapsed the status is automatically updated
    to EXPIRED before returning.
    """
    detail = await mission_plan_service.get_plan_detail(plan_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Plan not found")
    return detail


# ---------------------------------------------------------------------------
# APEP-296: DELETE /v1/plans/{plan_id}
# ---------------------------------------------------------------------------


@router.delete("/plans/{plan_id}", response_model=RevokePlanResponse)
async def revoke_plan(plan_id: UUID) -> RevokePlanResponse:
    """Revoke a MissionPlan (sets status to REVOKED).

    A revoked plan can no longer authorize tool calls.  Sessions bound
    to a revoked plan will receive PLAN_REVOKED denials.
    """
    result = await mission_plan_service.revoke_plan(plan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Plan not found")
    return result


# ---------------------------------------------------------------------------
# APEP-297: POST /v1/plans/{plan_id}/bind
# ---------------------------------------------------------------------------


@router.post(
    "/plans/{plan_id}/bind",
    response_model=BindPlanResponse,
    status_code=201,
)
async def bind_plan_to_session(
    plan_id: UUID, request: BindPlanRequest
) -> BindPlanResponse:
    """Bind a session to an active MissionPlan.

    The session will inherit the plan's scope, budget, and delegation
    constraints.  Only one active binding per session is allowed; the
    previous binding (if any) is automatically deactivated.
    """
    # Unbind any existing binding for this session
    await mission_plan_service.unbind_session(request.session_id)

    result = await mission_plan_service.bind_session(plan_id, request)
    if result is None:
        raise HTTPException(
            status_code=400,
            detail="Plan not found or not active",
        )
    return result


# ---------------------------------------------------------------------------
# APEP-311: GET /v1/plans/{plan_id}/receipts
# ---------------------------------------------------------------------------


@router.get(
    "/plans/{plan_id}/receipts",
    response_model=ReceiptChainResponse,
)
async def get_plan_receipts(plan_id: UUID) -> ReceiptChainResponse:
    """Retrieve the full receipt chain for a MissionPlan.

    Returns all audit decision receipts linked to the plan in sequence
    order, including hash chain integrity status.
    """
    plan = await mission_plan_service.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")

    return await receipt_chain_manager.get_chain(plan_id)


# ---------------------------------------------------------------------------
# APEP-312: GET /v1/plans/{plan_id}/receipts/summary
# ---------------------------------------------------------------------------


@router.get(
    "/plans/{plan_id}/receipts/summary",
    response_model=ReceiptChainSummary,
)
async def get_plan_receipts_summary(plan_id: UUID) -> ReceiptChainSummary:
    """Retrieve a summary of the receipt chain for a MissionPlan.

    Returns aggregate statistics: receipt count, decision breakdown,
    unique agents/tools, accumulated risk, and chain depth.
    """
    plan = await mission_plan_service.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")

    return await receipt_chain_manager.get_summary(plan_id)


# ---------------------------------------------------------------------------
# Sprint 40 — APEP-316.d: GET /v1/plans/{plan_id}/delegates/{agent_id}
# ---------------------------------------------------------------------------


@router.get(
    "/plans/{plan_id}/delegates/{agent_id}",
    response_model=DelegationCheckResult,
)
async def check_delegation(
    plan_id: UUID, agent_id: str
) -> DelegationCheckResult:
    """Check whether an agent is authorized under a plan's delegates_to list.

    Returns authorization status and reason. Supports both exact match
    and glob pattern matching against the plan's delegates_to whitelist.
    """
    plan = await mission_plan_service.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")

    return plan_delegates_filter.check(plan, agent_id)


# ---------------------------------------------------------------------------
# Sprint 40 — APEP-320: GET /v1/plans/{plan_id}/budget
# ---------------------------------------------------------------------------


@router.get(
    "/plans/{plan_id}/budget",
    response_model=BudgetStatusResponse,
)
async def get_budget_status(plan_id: UUID) -> BudgetStatusResponse:
    """Retrieve the current budget status for a MissionPlan.

    Returns delegation count, risk accumulation, TTL remaining,
    exhausted dimensions, and utilization percentages.
    """
    plan = await mission_plan_service.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")

    return await plan_budget_gate.get_budget_status(plan)


# ---------------------------------------------------------------------------
# Sprint 40 — APEP-322: POST /v1/plans/{plan_id}/budget/reset
# ---------------------------------------------------------------------------


@router.post(
    "/plans/{plan_id}/budget/reset",
    response_model=BudgetResetResponse,
)
async def reset_plan_budget(
    plan_id: UUID, request: BudgetResetRequest
) -> BudgetResetResponse:
    """Reset a plan's budget counters and optionally update budget limits.

    Can reactivate an EXPIRED plan (budget-exhausted) by resetting its
    counters and/or updating its limits. Revoked plans cannot be reset.
    """
    plan = await mission_plan_service.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")

    from app.models.mission_plan import PlanStatus

    if plan.status == PlanStatus.REVOKED:
        raise HTTPException(
            status_code=400,
            detail="Cannot reset budget for a revoked plan",
        )

    return await plan_budget_gate.reset_budget(plan, request)
