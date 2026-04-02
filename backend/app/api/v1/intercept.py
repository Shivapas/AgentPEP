"""Intercept API — core decision engine for tool call authorization."""

import time

from fastapi import APIRouter

from app.core.observability import INTERCEPT_LATENCY, INTERCEPT_REQUESTS, POLICY_EVALUATIONS
from app.models.policy import PolicyDecisionResponse, ToolCallRequest
from app.services.policy_evaluator import policy_evaluator

router = APIRouter(prefix="/v1", tags=["intercept"])


@router.post("/intercept", response_model=PolicyDecisionResponse)
async def intercept(request: ToolCallRequest) -> PolicyDecisionResponse:
    """Evaluate a tool call request against the policy stack.

    Fetches matching rules from MongoDB, evaluates with first-match semantics,
    and returns ALLOW / DENY / ESCALATE / DRY_RUN. Deny-by-default when no
    rule matches. Supports configurable FAIL_OPEN / FAIL_CLOSED on timeout.
    """
    start = time.monotonic()
    response = await policy_evaluator.evaluate(request)
    elapsed = time.monotonic() - start

    # Record Prometheus metrics
    INTERCEPT_REQUESTS.labels(decision=response.decision.value).inc()
    INTERCEPT_LATENCY.observe(elapsed)
    POLICY_EVALUATIONS.labels(result=response.decision.value).inc()

    return response
