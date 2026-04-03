"""Intercept API — core decision engine for tool call authorization."""

import time

from fastapi import APIRouter

from app.core.observability import (
    DECISION_LATENCY,
    DECISION_TOTAL,
    INTERCEPT_LATENCY,
    INTERCEPT_REQUESTS,
    POLICY_EVALUATIONS,
    get_tracer,
)
from app.models.policy import ToolCallRequest, PolicyDecisionResponse
from app.services.policy_evaluator import policy_evaluator

router = APIRouter(prefix="/v1", tags=["intercept"])

tracer = get_tracer(__name__)


@router.post("/intercept", response_model=PolicyDecisionResponse)
async def intercept(request: ToolCallRequest) -> PolicyDecisionResponse:
    """Evaluate a tool call request against the policy stack.

    Fetches matching rules from MongoDB, evaluates with first-match semantics,
    and returns ALLOW / DENY / ESCALATE / DRY_RUN. Deny-by-default when no
    rule matches. Supports configurable FAIL_OPEN / FAIL_CLOSED on timeout.
    """
    with tracer.start_as_current_span(
        "intercept",
        attributes={
            "agentpep.agent_id": request.agent_id,
            "agentpep.tool_name": request.tool_name,
            "agentpep.session_id": request.session_id,
            "agentpep.request_id": str(request.request_id),
            "agentpep.dry_run": request.dry_run,
        },
    ) as span:
        start = time.monotonic()
        response = await policy_evaluator.evaluate(request)
        elapsed = time.monotonic() - start

        # Record legacy Prometheus metrics
        INTERCEPT_REQUESTS.labels(decision=response.decision.value).inc()
        INTERCEPT_LATENCY.observe(elapsed)
        POLICY_EVALUATIONS.labels(result=response.decision.value).inc()

        # Record Sprint 26 enhanced metrics (APEP-204)
        DECISION_TOTAL.labels(
            decision=response.decision.value,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
        ).inc()
        DECISION_LATENCY.labels(
            agent_id=request.agent_id,
            tool_name=request.tool_name,
        ).observe(elapsed)

        # Enrich span with decision outcome
        span.set_attribute("agentpep.decision", response.decision.value)
        span.set_attribute("agentpep.latency_ms", response.latency_ms)
        if response.matched_rule_id:
            span.set_attribute("agentpep.matched_rule_id", str(response.matched_rule_id))
        if response.taint_flags:
            span.set_attribute("agentpep.taint_flags", ",".join(response.taint_flags))

        return response
