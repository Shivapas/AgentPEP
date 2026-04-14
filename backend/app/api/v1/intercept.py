"""Intercept API — core decision engine for tool call authorization.

Sprint 23 (APEP-180): Optimised hot path — avoid redundant serialisation,
use pre-validated request objects, record latency with minimal overhead.
Sprint 29 (APEP-232): Execution token generation for ALLOW decisions.
"""

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
from app.models.policy import Decision, PolicyDecisionResponse, ToolCallRequest
from app.services.execution_token import execution_token_manager
from app.services.policy_evaluator import policy_evaluator

router = APIRouter(prefix="/v1", tags=["intercept"])

tracer = get_tracer(__name__)


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

        # Record Prometheus metrics — use string value directly to avoid enum lookup
        decision_val = response.decision.value
        INTERCEPT_REQUESTS.labels(decision=decision_val).inc()
        INTERCEPT_LATENCY.observe(elapsed)
        POLICY_EVALUATIONS.labels(result=decision_val).inc()

        # Record Sprint 26 enhanced metrics (APEP-204)
        # Use bounded label values to prevent unbounded cardinality from
        # high-cardinality fields like agent_id and tool_name.  Replace
        # raw values with "other" if they are not in a known allowlist,
        # or omit them entirely.  For now, use only the decision label
        # which has a small fixed set of values.
        DECISION_TOTAL.labels(
            decision=response.decision.value,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
        ).inc()
        DECISION_LATENCY.labels(
            agent_id=request.agent_id,
            tool_name=request.tool_name,
        ).observe(elapsed)

        # APEP-232: Generate single-use execution token for ALLOW decisions
        if response.decision == Decision.ALLOW:
            response.execution_token = execution_token_manager.generate(
                decision_id=str(response.request_id),
                session_id=request.session_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
            )

        # Sprint 32 (APEP-256): Sign receipt if enabled
        from app.core.config import settings
        if settings.receipt_signing_enabled:
            from app.services.receipt_signer import receipt_signer

            if receipt_signer is not None:
                receipt_record = {
                    "decision_id": str(response.request_id),
                    "decision": response.decision.value,
                    "session_id": request.session_id,
                    "agent_id": request.agent_id,
                    "tool_name": request.tool_name,
                    "risk_score": response.risk_score,
                    "matched_rule_id": str(response.matched_rule_id) if response.matched_rule_id else None,
                    "taint_flags": response.taint_flags,
                    "latency_ms": response.latency_ms,
                }
                response.receipt = receipt_signer.sign(receipt_record)

        # Sprint 36 (APEP-285): Append to hash-chained context
        if settings.hash_chained_context_enabled:
            try:
                from app.services.hash_chained_context import hash_chained_context

                import json
                content = json.dumps({
                    "request_id": str(request.request_id),
                    "tool_name": request.tool_name,
                    "decision": response.decision.value,
                    "risk_score": response.risk_score,
                }, sort_keys=True)
                await hash_chained_context.append(
                    session_id=request.session_id,
                    content=content,
                    source="intercept",
                    agent_id=request.agent_id,
                    tenant_id=request.tenant_id,
                )
            except Exception:
                pass  # Non-blocking — don't fail the intercept

        # Sprint 36 (APEP-286): Record trust degradation event
        if settings.trust_degradation_engine_enabled and response.decision != Decision.ALLOW:
            try:
                from app.services.trust_degradation_engine import trust_degradation_engine

                taint = "TRUSTED"
                if response.taint_flags:
                    if "QUARANTINE" in response.taint_flags:
                        taint = "QUARANTINE"
                    elif "UNTRUSTED" in response.taint_flags:
                        taint = "UNTRUSTED"
                await trust_degradation_engine.record_event(
                    session_id=request.session_id,
                    interaction_type="TOOL_CALL",
                    taint_level=taint,
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    tenant_id=request.tenant_id,
                )
            except Exception:
                pass  # Non-blocking

        # Enrich span with decision outcome
        span.set_attribute("agentpep.decision", response.decision.value)
        span.set_attribute("agentpep.latency_ms", response.latency_ms)
        if response.matched_rule_id:
            span.set_attribute("agentpep.matched_rule_id", str(response.matched_rule_id))
        if response.taint_flags:
            span.set_attribute("agentpep.taint_flags", ",".join(response.taint_flags))

        return response
