"""PDP API — /api/v1/pdp — OPA evaluation endpoint and diagnostic views.

Exposes the Policy Decision Point so that external callers (SDK, CI tests,
diagnostic tooling) can submit authorisation requests and inspect the
enforcement decision log.

Sprint S-E04 (E04-T01 – E04-T05)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.pdp.client import PDPClient, pdp_client
from app.pdp.enforcement_log import enforcement_log
from app.pdp.request_builder import request_builder

router = APIRouter(prefix="/api/v1/pdp", tags=["pdp"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class PDPDecideRequest(BaseModel):
    """Authorisation request body for POST /api/v1/pdp/decide."""

    tool_name: str = Field(..., description="Name of the tool being invoked")
    tool_args: dict[str, Any] = Field(default_factory=dict)
    agent_id: str = ""
    session_id: str = ""
    request_id: str = ""
    taint_level: str = ""
    trust_score: float | None = None
    principal_chain: list[str] | None = None
    deployment_tier: str = ""
    blast_radius_score: float | None = None


class PDPDecideResponse(BaseModel):
    """Response body for POST /api/v1/pdp/decide."""

    request_id: str
    decision: str               # "ALLOW" | "DENY" | "MODIFY"
    reason_code: str
    details: str
    evaluator: str
    latency_ms: float
    bundle_version: str


class PDPStatusResponse(BaseModel):
    """Response body for GET /api/v1/pdp/status."""

    enabled: bool
    bundle_version: str
    evaluator: str
    decision_counts: dict[str, int]
    recent_decisions_count: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/decide", response_model=PDPDecideResponse)
async def decide(body: PDPDecideRequest) -> PDPDecideResponse:
    """Evaluate a tool call authorisation request through the OPA PDP.

    Returns the enforcement decision (ALLOW / DENY / MODIFY), the reason
    code, and evaluation latency.  The decision is unconditionally logged
    to the enforcement decision log.
    """
    result = await pdp_client.decide(
        tool_name=body.tool_name,
        tool_args=body.tool_args,
        agent_id=body.agent_id,
        session_id=body.session_id,
        request_id=body.request_id,
        taint_level=body.taint_level,
        trust_score=body.trust_score,
        principal_chain=body.principal_chain,
        deployment_tier=body.deployment_tier,
        blast_radius_score=body.blast_radius_score,
    )
    return PDPDecideResponse(
        request_id=result.request.request_id,
        decision=result.response.decision.value,
        reason_code=result.response.reason_code.value,
        details=result.response.details,
        evaluator=result.response.evaluator,
        latency_ms=result.latency_ms,
        bundle_version=result.request.bundle_version,
    )


@router.get("/status", response_model=PDPStatusResponse)
async def status() -> PDPStatusResponse:
    """Return PDP operational status and cumulative decision counters."""
    from app.core.config import settings
    from app.pdp.engine import _engine as engine
    from app.policy.bundle_version import bundle_version_tracker

    evaluator_name = getattr(engine, "evaluator_name", "unknown")

    return PDPStatusResponse(
        enabled=settings.pdp_enabled,
        bundle_version=bundle_version_tracker.version_string,
        evaluator=evaluator_name,
        decision_counts=enforcement_log.counts(),
        recent_decisions_count=len(enforcement_log.recent(limit=1000)),
    )


@router.get("/decisions")
async def recent_decisions(limit: int = 50) -> dict[str, Any]:
    """Return the most recent enforcement decision log entries (newest first).

    Limited to 200 entries per call.  Full audit log access is via the
    ``/api/v1/audit`` endpoint.
    """
    limit = min(limit, 200)
    entries = enforcement_log.recent(limit=limit)
    return {
        "count": len(entries),
        "entries": [e.to_ocsf_dict() for e in entries],
    }
