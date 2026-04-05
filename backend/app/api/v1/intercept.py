"""Intercept API — core decision engine for tool call authorization.

Sprint 23 (APEP-180): Optimised hot path — avoid redundant serialisation,
use pre-validated request objects, record latency with minimal overhead.
"""

import time

from fastapi import APIRouter, Request

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

    Sprint 23 (APEP-180): Eliminated redundant serialisation — the validated
    Pydantic model is passed directly through the evaluation pipeline without
    re-serialising to dict/JSON at intermediate steps.
    """
    start = time.monotonic()
    response = await policy_evaluator.evaluate(request)
    elapsed = time.monotonic() - start

    # Record Prometheus metrics — use string value directly to avoid enum lookup
    decision_val = response.decision.value
    INTERCEPT_REQUESTS.labels(decision=decision_val).inc()
    INTERCEPT_LATENCY.observe(elapsed)
    POLICY_EVALUATIONS.labels(result=decision_val).inc()

    return response
