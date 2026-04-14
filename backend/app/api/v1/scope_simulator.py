"""Sprint 43 API -- Scope Simulator & Pattern Library endpoints.

APEP-340/341: POST /v1/scope/simulate — interactive scope simulation.
APEP-342: /v1/scope/patterns — enterprise scope pattern library CRUD.
"""

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.models.scope_pattern_library import (
    CreatePatternTemplateRequest,
    PatternCategory,
    PatternRiskLevel,
    PatternTemplateListResponse,
    PatternTemplateResponse,
    ScopeSimulateRequest,
    ScopeSimulateResult,
    UpdatePatternTemplateRequest,
)
from app.services.kafka_producer import kafka_producer
from app.services.scope_pattern_library import scope_pattern_library
from app.services.scope_simulator import scope_simulator

router = APIRouter(prefix="/v1/scope", tags=["scope"])


# ---------------------------------------------------------------------------
# APEP-340/341: POST /v1/scope/simulate
# ---------------------------------------------------------------------------


@router.post("/simulate", response_model=ScopeSimulateResult)
async def simulate_scope(request: ScopeSimulateRequest) -> ScopeSimulateResult:
    """Simulate a tool call against plan scope patterns.

    Either provide a ``plan_id`` to simulate against an existing plan, or
    provide inline ``scope`` and ``requires_checkpoint`` patterns.

    Returns the effective decision (ALLOW, DENY, or ESCALATE) along with
    detailed scope and checkpoint match information.
    """
    if request.plan_id is None and not request.scope:
        raise HTTPException(
            status_code=400,
            detail="Either plan_id or scope patterns must be provided",
        )
    try:
        result = await scope_simulator.simulate(request)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    # APEP-342.e: Publish scope simulation event to Kafka for pipeline observability
    await kafka_producer.publish_scope_simulation(
        tool_name=request.tool_name,
        effective_decision=result.effective_decision,
        scope_patterns=request.scope or [],
        checkpoint_patterns=request.requires_checkpoint or [],
        plan_id=str(request.plan_id) if request.plan_id else "",
    )

    return result


class BatchSimulateRequest(BaseModel):
    """Request for batch scope simulation."""

    scope: list[str] = Field(..., min_length=1)
    requires_checkpoint: list[str] = Field(default_factory=list)
    tool_names: list[str] = Field(..., min_length=1, max_length=100)
    action: str = Field(default="")


class BatchSimulateResponse(BaseModel):
    """Response for batch scope simulation."""

    results: list[ScopeSimulateResult]
    summary: dict[str, int]


@router.post("/simulate/batch", response_model=BatchSimulateResponse)
async def simulate_scope_batch(request: BatchSimulateRequest) -> BatchSimulateResponse:
    """Simulate multiple tool names against the same scope configuration.

    Useful for testing a scope policy against a set of tools at once.
    """
    results = scope_simulator.simulate_batch_sync(
        scope=request.scope,
        requires_checkpoint=request.requires_checkpoint,
        tool_names=request.tool_names,
        action=request.action,
    )
    summary = {
        "total": len(results),
        "allowed": sum(1 for r in results if r.effective_decision == "ALLOW"),
        "denied": sum(1 for r in results if r.effective_decision == "DENY"),
        "escalated": sum(1 for r in results if r.effective_decision == "ESCALATE"),
    }
    return BatchSimulateResponse(results=results, summary=summary)


# ---------------------------------------------------------------------------
# APEP-342: Pattern Library CRUD
# ---------------------------------------------------------------------------


@router.get("/patterns", response_model=PatternTemplateListResponse)
async def list_pattern_templates(
    category: PatternCategory | None = Query(default=None),
    risk_level: PatternRiskLevel | None = Query(default=None),
    tag: str | None = Query(default=None),
    search: str | None = Query(default=None),
    enabled_only: bool = Query(default=True),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> PatternTemplateListResponse:
    """List enterprise scope pattern templates with optional filtering.

    Supports filtering by category, risk_level, tag, and free-text search.
    """
    return await scope_pattern_library.list_templates(
        category=category,
        risk_level=risk_level,
        tag=tag,
        search=search,
        enabled_only=enabled_only,
        offset=offset,
        limit=limit,
    )


@router.get("/patterns/categories")
async def list_pattern_categories() -> list[dict[str, int]]:
    """Get category counts for faceted browsing."""
    return await scope_pattern_library.get_categories()


@router.get("/patterns/{template_id}", response_model=PatternTemplateResponse)
async def get_pattern_template(template_id: UUID) -> PatternTemplateResponse:
    """Get a single pattern template by ID."""
    tmpl = await scope_pattern_library.get_template(template_id)
    if tmpl is None:
        raise HTTPException(status_code=404, detail="Pattern template not found")
    return tmpl


@router.post("/patterns", response_model=PatternTemplateResponse, status_code=201)
async def create_pattern_template(
    request: CreatePatternTemplateRequest,
) -> PatternTemplateResponse:
    """Create a new pattern template.

    All scope patterns are validated before creation.
    """
    try:
        return await scope_pattern_library.create_template(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch("/patterns/{template_id}", response_model=PatternTemplateResponse)
async def update_pattern_template(
    template_id: UUID,
    request: UpdatePatternTemplateRequest,
) -> PatternTemplateResponse:
    """Update an existing pattern template."""
    try:
        result = await scope_pattern_library.update_template(template_id, request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Pattern template not found")
    return result


@router.delete("/patterns/{template_id}", status_code=204)
async def delete_pattern_template(template_id: UUID) -> None:
    """Delete a pattern template."""
    deleted = await scope_pattern_library.delete_template(template_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Pattern template not found")
