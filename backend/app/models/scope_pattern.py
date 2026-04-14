"""Sprint 38 models -- Scope Pattern Language & DSL Compiler.

APEP-300: Scope pattern syntax (verb:namespace:resource notation).
APEP-301: ScopePatternParser data model.
APEP-302: ScopePatternCompiler data model.
APEP-303: PlanCheckpointFilter scope matching model.
APEP-304: PlanScopeFilter scope allow-check model.
"""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# APEP-300: Scope Pattern Verb and Namespace Enums
# ---------------------------------------------------------------------------


class ScopeVerb(StrEnum):
    """Valid verbs in scope pattern notation."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    SEND = "send"
    WILDCARD = "*"


class ScopeNamespace(StrEnum):
    """Valid namespaces in scope pattern notation."""

    PUBLIC = "public"
    SECRET = "secret"
    INTERNAL = "internal"
    EXTERNAL = "external"
    WILDCARD = "*"


# ---------------------------------------------------------------------------
# APEP-300/301: ScopePattern Model
# ---------------------------------------------------------------------------


class ScopePattern(BaseModel):
    """A parsed scope pattern in verb:namespace:resource notation.

    Scope patterns follow the format ``verb:namespace:resource`` where:
    - **verb**: read, write, delete, execute, send, or * (wildcard)
    - **namespace**: public, secret, internal, external, or * (wildcard)
    - **resource**: a glob pattern (e.g. ``*.txt``, ``report.*``, ``*``)

    Examples::

        read:public:*              -- read any public resource
        write:secret:credentials.* -- write secret credential resources
        *:*:*                      -- unrestricted access
        execute:internal:deploy.*  -- execute internal deploy resources
    """

    pattern: str = Field(
        ...,
        description="Full scope pattern string (verb:namespace:resource)",
    )
    verb: str | None = Field(
        default=None,
        description="Parsed verb component (read/write/delete/execute/send/*)",
    )
    namespace: str | None = Field(
        default=None,
        description="Parsed namespace (public/secret/internal/external/*)",
    )
    resource_glob: str | None = Field(
        default=None,
        description="Parsed resource glob (*.txt, report.*, *)",
    )
    mapped_rbac_patterns: list[str] = Field(
        default_factory=list,
        description="Computed RBAC tool_name globs this scope pattern covers",
    )


# ---------------------------------------------------------------------------
# APEP-301: ScopePatternParser Result
# ---------------------------------------------------------------------------


class ScopeParseResult(BaseModel):
    """Result of parsing a scope pattern string."""

    valid: bool = Field(
        ...,
        description="Whether the pattern was successfully parsed",
    )
    scope_pattern: ScopePattern | None = Field(
        default=None,
        description="Parsed scope pattern (None if invalid)",
    )
    error: str | None = Field(
        default=None,
        description="Error message if parsing failed",
    )


# ---------------------------------------------------------------------------
# APEP-302: ScopePatternCompiler Models
# ---------------------------------------------------------------------------


class ScopeCompileResult(BaseModel):
    """Result of compiling a scope pattern to RBAC tool-name globs."""

    scope_pattern: ScopePattern = Field(
        ...,
        description="The source scope pattern",
    )
    rbac_patterns: list[str] = Field(
        default_factory=list,
        description="Computed RBAC tool_name glob patterns",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal compilation warnings",
    )


class ScopeBatchCompileRequest(BaseModel):
    """Request to compile multiple scope patterns."""

    patterns: list[str] = Field(
        ...,
        min_length=1,
        description="List of scope pattern strings to compile",
    )


class ScopeBatchCompileResponse(BaseModel):
    """Response from compiling multiple scope patterns."""

    results: list[ScopeCompileResult] = Field(
        default_factory=list,
        description="Compilation results for each pattern",
    )
    all_rbac_patterns: list[str] = Field(
        default_factory=list,
        description="Deduplicated union of all RBAC patterns",
    )


# ---------------------------------------------------------------------------
# APEP-303: PlanCheckpointFilter Scope Matching
# ---------------------------------------------------------------------------


class CheckpointScopeMatch(BaseModel):
    """Result of checking whether a tool call matches checkpoint scope patterns."""

    matches: bool = Field(
        ...,
        description="Whether the tool call matches any checkpoint scope pattern",
    )
    matched_pattern: str | None = Field(
        default=None,
        description="The checkpoint scope pattern that matched (if any)",
    )
    tool_name: str = Field(
        ...,
        description="The tool name that was checked",
    )
    reason: str = Field(
        default="",
        description="Human-readable explanation of the match result",
    )


# ---------------------------------------------------------------------------
# APEP-304: PlanScopeFilter Allow-Check
# ---------------------------------------------------------------------------


class ScopeAllowResult(BaseModel):
    """Result of checking whether a tool call is allowed by plan scope patterns."""

    allowed: bool = Field(
        ...,
        description="Whether the tool call is within the plan's allowed scope",
    )
    matched_scope: str | None = Field(
        default=None,
        description="The scope pattern that grants access (if any)",
    )
    tool_name: str = Field(
        ...,
        description="The tool name that was checked",
    )
    reason: str = Field(
        default="",
        description="Human-readable explanation of the allow/deny result",
    )


# ---------------------------------------------------------------------------
# APEP-305/306: CLI Models
# ---------------------------------------------------------------------------


class ScopeValidationResult(BaseModel):
    """Result of validating scope patterns in a plan YAML file."""

    valid: bool = Field(
        ...,
        description="Whether all scope patterns are valid",
    )
    total_patterns: int = Field(
        default=0,
        description="Total number of scope patterns checked",
    )
    valid_patterns: int = Field(
        default=0,
        description="Number of valid scope patterns",
    )
    invalid_patterns: int = Field(
        default=0,
        description="Number of invalid scope patterns",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Error messages for invalid patterns",
    )
    compiled_rbac_patterns: list[str] = Field(
        default_factory=list,
        description="All compiled RBAC patterns from valid scope patterns",
    )
