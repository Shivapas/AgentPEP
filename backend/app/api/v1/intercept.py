"""Intercept API — stub endpoint for tool call authorization."""

from fastapi import APIRouter

from app.models.policy import PolicyDecisionResponse, ToolCallRequest, Decision

router = APIRouter(prefix="/v1", tags=["intercept"])


@router.post("/intercept", response_model=PolicyDecisionResponse)
async def intercept(request: ToolCallRequest) -> PolicyDecisionResponse:
    """Evaluate a tool call request against the policy stack.

    This is the Sprint 1 stub — returns ALLOW for all requests.
    Full policy evaluation is implemented in Sprint 2+.
    """
    decision = Decision.DRY_RUN if request.dry_run else Decision.ALLOW

    return PolicyDecisionResponse(
        request_id=request.request_id,
        decision=decision,
        reason="Sprint 1 stub — default allow",
        latency_ms=0,
    )
