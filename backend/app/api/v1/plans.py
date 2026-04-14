"""Sprint 37 API -- MissionPlan CRUD and session binding endpoints.

APEP-294: POST /v1/plans -- create and issue a signed plan.
APEP-295: GET /v1/plans/{plan_id} -- retrieve plan with budget status.
APEP-296: DELETE /v1/plans/{plan_id} -- revoke plan.
APEP-297: POST /v1/plans/{plan_id}/bind -- bind plan to session.
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
from app.services.mission_plan_service import mission_plan_service

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
