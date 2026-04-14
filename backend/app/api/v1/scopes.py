"""Sprint 38 API -- Scope Pattern Language endpoints.

APEP-301: POST /v1/scopes/parse — parse scope patterns into structured tokens.
APEP-302: POST /v1/scopes/compile — compile scope patterns to tool-name globs.
APEP-303: POST /v1/scopes/checkpoint — check tool against checkpoint patterns.
APEP-304: POST /v1/scopes/check — check tool against scope allow-list.
"""

from fastapi import APIRouter

from app.models.scope_pattern import (
    CheckpointCheckRequest,
    CheckpointCheckResponse,
    CheckScopeRequest,
    CheckScopeResponse,
    CompileScopeRequest,
    CompileScopeResponse,
    ParseScopeRequest,
    ParseScopeResponse,
)
from app.services.scope_pattern import (
    plan_checkpoint_filter,
    plan_scope_filter,
    scope_pattern_compiler,
    scope_pattern_parser,
)

router = APIRouter(prefix="/v1", tags=["scopes"])


# ---------------------------------------------------------------------------
# APEP-301: POST /v1/scopes/parse
# ---------------------------------------------------------------------------


@router.post("/scopes/parse", response_model=ParseScopeResponse)
async def parse_scopes(request: ParseScopeRequest) -> ParseScopeResponse:
    """Parse scope pattern strings into structured tokens.

    Validates each pattern against the ``verb:namespace:resource`` syntax
    and returns parsed ScopeTokens for valid patterns, plus errors for
    any invalid patterns.
    """
    result = scope_pattern_parser.parse_many(request.patterns)
    return ParseScopeResponse(
        tokens=result.tokens,
        errors=result.errors,
        valid=result.valid,
    )


# ---------------------------------------------------------------------------
# APEP-302: POST /v1/scopes/compile
# ---------------------------------------------------------------------------


@router.post("/scopes/compile", response_model=CompileScopeResponse)
async def compile_scopes(request: CompileScopeRequest) -> CompileScopeResponse:
    """Compile scope pattern strings to fnmatch-compatible tool-name globs.

    Each valid scope pattern is compiled to a glob that can be matched
    against tool names using ``fnmatch.fnmatch(tool_name, glob)``.
    """
    result = scope_pattern_compiler.compile_many(request.patterns)
    return CompileScopeResponse(
        compiled=result.compiled,
        errors=result.errors,
        valid=result.valid,
    )


# ---------------------------------------------------------------------------
# APEP-303: POST /v1/scopes/checkpoint
# ---------------------------------------------------------------------------


@router.post("/scopes/checkpoint", response_model=CheckpointCheckResponse)
async def check_checkpoint(request: CheckpointCheckRequest) -> CheckpointCheckResponse:
    """Check whether a tool name matches any checkpoint scope pattern.

    If a match is found, the tool call should trigger ESCALATE for
    human review regardless of RBAC decisions.
    """
    result = plan_checkpoint_filter.matches(
        request.tool_name, request.requires_checkpoint
    )
    return CheckpointCheckResponse(
        matches=result.matches,
        matched_pattern=result.matched_pattern,
        tool_name=result.tool_name,
        detail=result.detail,
    )


# ---------------------------------------------------------------------------
# APEP-304: POST /v1/scopes/check
# ---------------------------------------------------------------------------


@router.post("/scopes/check", response_model=CheckScopeResponse)
async def check_scope(request: CheckScopeRequest) -> CheckScopeResponse:
    """Check whether a tool name is allowed by a set of scope patterns.

    Returns whether the tool call is permitted by at least one scope
    pattern in the provided list.
    """
    result = plan_scope_filter.check(request.tool_name, request.scope)
    return CheckScopeResponse(
        allowed=result.allowed,
        matched_pattern=result.matched_pattern,
        tool_name=result.tool_name,
        detail=result.detail,
    )
