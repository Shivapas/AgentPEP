"""Sprint 38 API -- Scope Pattern Language & DSL Compiler endpoints.

APEP-301: POST /v1/scope/parse -- parse a scope pattern.
APEP-302: POST /v1/scope/compile -- compile scope pattern to RBAC globs.
APEP-303: POST /v1/scope/check-checkpoint -- check tool against checkpoint patterns.
APEP-304: POST /v1/scope/check-scope -- check tool against plan scope patterns.
"""

from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.models.scope_pattern import (
    CheckpointScopeMatch,
    ScopeAllowResult,
    ScopeBatchCompileResponse,
    ScopeCompileResult,
    ScopeParseResult,
)
from app.services.scope_filter import plan_checkpoint_filter, plan_scope_filter
from app.services.scope_pattern_compiler import scope_pattern_compiler
from app.services.scope_pattern_parser import scope_pattern_parser

router = APIRouter(prefix="/v1/scope", tags=["scope"])


# ---------------------------------------------------------------------------
# Request/Response Schemas
# ---------------------------------------------------------------------------


class ParseScopeRequest(BaseModel):
    """Request body for POST /v1/scope/parse."""

    pattern: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Scope pattern string to parse",
    )


class CompileScopeRequest(BaseModel):
    """Request body for POST /v1/scope/compile."""

    pattern: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Scope pattern string to compile",
    )


class CompileBatchRequest(BaseModel):
    """Request body for POST /v1/scope/compile-batch."""

    patterns: list[str] = Field(
        ...,
        min_length=1,
        description="List of scope pattern strings to compile",
    )


class CheckCheckpointRequest(BaseModel):
    """Request body for POST /v1/scope/check-checkpoint."""

    plan_id: UUID = Field(..., description="Plan ID to check against")
    tool_name: str = Field(
        ...,
        min_length=1,
        description="Tool name to check",
    )


class CheckScopeRequest(BaseModel):
    """Request body for POST /v1/scope/check-scope."""

    plan_id: UUID = Field(..., description="Plan ID to check against")
    tool_name: str = Field(
        ...,
        min_length=1,
        description="Tool name to check",
    )


# ---------------------------------------------------------------------------
# APEP-301: POST /v1/scope/parse
# ---------------------------------------------------------------------------


@router.post("/parse", response_model=ScopeParseResult)
async def parse_scope_pattern(request: ParseScopeRequest) -> ScopeParseResult:
    """Parse a scope pattern string into its components.

    Validates the ``verb:namespace:resource`` notation and returns the
    parsed components or an error message.
    """
    return scope_pattern_parser.parse(request.pattern)


# ---------------------------------------------------------------------------
# APEP-302: POST /v1/scope/compile
# ---------------------------------------------------------------------------


@router.post("/compile", response_model=ScopeCompileResult)
async def compile_scope_pattern(request: CompileScopeRequest) -> ScopeCompileResult:
    """Compile a scope pattern into RBAC tool-name globs.

    Maps the ``verb:namespace:resource`` pattern to fnmatch-compatible
    tool-name glob patterns that can be matched against incoming tool calls.
    """
    return scope_pattern_compiler.compile(request.pattern)


@router.post("/compile-batch", response_model=ScopeBatchCompileResponse)
async def compile_scope_patterns_batch(
    request: CompileBatchRequest,
) -> ScopeBatchCompileResponse:
    """Compile multiple scope patterns and return aggregated results.

    Returns per-pattern compilation results plus a deduplicated union of
    all RBAC patterns.
    """
    return scope_pattern_compiler.compile_many(request.patterns)


# ---------------------------------------------------------------------------
# APEP-303: POST /v1/scope/check-checkpoint
# ---------------------------------------------------------------------------


@router.post("/check-checkpoint", response_model=CheckpointScopeMatch)
async def check_checkpoint_scope(
    request: CheckCheckpointRequest,
) -> CheckpointScopeMatch:
    """Check if a tool call matches any requires_checkpoint scope pattern.

    Retrieves the plan by ID and checks whether the tool name triggers a
    checkpoint (ESCALATE) based on the plan's requires_checkpoint patterns.
    """
    from app.services.mission_plan_service import mission_plan_service

    plan = await mission_plan_service.get_plan(request.plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")

    return plan_checkpoint_filter.check(plan, request.tool_name)


# ---------------------------------------------------------------------------
# APEP-304: POST /v1/scope/check-scope
# ---------------------------------------------------------------------------


@router.post("/check-scope", response_model=ScopeAllowResult)
async def check_scope_allow(request: CheckScopeRequest) -> ScopeAllowResult:
    """Check if a tool call is within a plan's allowed scope.

    Retrieves the plan by ID and checks whether the tool name falls within
    the plan's scope patterns. If the plan has no scope patterns, all tools
    are allowed.
    """
    from app.services.mission_plan_service import mission_plan_service

    plan = await mission_plan_service.get_plan(request.plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")

    return plan_scope_filter.check(plan, request.tool_name)
