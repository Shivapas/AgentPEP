"""Sprint 38 models -- Scope Pattern Language & DSL Compiler.

APEP-300: Scope pattern syntax — ``verb:namespace:resource`` notation.
APEP-301: ScopePatternParser — parse raw scope strings into structured tokens.
APEP-302: ScopePatternCompiler — compile scope patterns to RBAC tool-name globs.
APEP-303: PlanCheckpointFilter — scope matching for requires_checkpoint.
APEP-304: PlanScopeFilter — scope allow-check against plan scope list.

Scope Pattern Syntax
====================

A scope pattern follows the ``verb:namespace:resource`` format::

    <verb>:<namespace>:<resource>

- **verb**: Action verb (e.g. ``read``, ``write``, ``execute``, ``delete``, ``admin``).
  Use ``*`` for any verb.
- **namespace**: Logical namespace / classification (e.g. ``public``, ``internal``,
  ``secret``, ``pii``). Use ``*`` for any namespace.
- **resource**: Resource identifier with optional dot-delimited hierarchy and
  glob wildcards (e.g. ``reports.*``, ``db.users``, ``*``). Use ``*`` for any
  resource, ``foo.*`` for sub-resources of ``foo``.

Examples::

    read:public:*                  # Read any public resource
    write:internal:reports.*       # Write any report in internal namespace
    execute:*:tools.code_exec      # Execute code_exec in any namespace
    *:secret:*                     # Any action on any secret resource
    read:public:docs.readme        # Read a specific resource
    delete:pii:users.*             # Delete any PII user resource
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# APEP-300: Scope Pattern Syntax — Core Enums & Constants
# ---------------------------------------------------------------------------


SCOPE_SEPARATOR = ":"
RESOURCE_SEPARATOR = "."
WILDCARD = "*"
MIN_SCOPE_PARTS = 3
MAX_SCOPE_LENGTH = 256


class ScopeVerb(StrEnum):
    """Well-known scope verbs (non-exhaustive — custom verbs are allowed)."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"
    LIST = "list"
    CREATE = "create"
    UPDATE = "update"
    WILDCARD = "*"


# ---------------------------------------------------------------------------
# APEP-301: ScopePatternParser — Parsed Scope Token
# ---------------------------------------------------------------------------


class ScopeToken(BaseModel):
    """Parsed representation of a single scope pattern string.

    A scope string ``verb:namespace:resource`` is decomposed into its
    three constituent parts for structured matching and compilation.
    """

    raw: str = Field(..., description="Original scope pattern string")
    verb: str = Field(..., description="Action verb (e.g. read, write, *)")
    namespace: str = Field(..., description="Namespace (e.g. public, internal, *)")
    resource: str = Field(
        ..., description="Resource path with optional dot hierarchy (e.g. reports.*, db.users)"
    )

    @property
    def verb_is_wildcard(self) -> bool:
        return self.verb == WILDCARD

    @property
    def namespace_is_wildcard(self) -> bool:
        return self.namespace == WILDCARD

    @property
    def resource_is_wildcard(self) -> bool:
        return self.resource == WILDCARD

    @property
    def resource_segments(self) -> list[str]:
        """Split resource path into dot-delimited segments."""
        return self.resource.split(RESOURCE_SEPARATOR)


class ScopeParseError(BaseModel):
    """Structured error from scope pattern parsing."""

    pattern: str
    error: str
    position: int | None = None


class ScopeParseResult(BaseModel):
    """Result of parsing one or more scope pattern strings."""

    tokens: list[ScopeToken] = Field(default_factory=list)
    errors: list[ScopeParseError] = Field(default_factory=list)
    valid: bool = True


# ---------------------------------------------------------------------------
# APEP-302: ScopePatternCompiler — Compiled Scope / Tool Glob
# ---------------------------------------------------------------------------


class CompiledScope(BaseModel):
    """A scope pattern compiled down to an fnmatch-compatible tool-name glob.

    The compiler maps structured ``verb:namespace:resource`` patterns to
    glob patterns that can be matched against flat tool names used in RBAC
    rules (e.g. ``file.read``, ``db.users.delete``).
    """

    source_pattern: str = Field(..., description="Original scope pattern string")
    tool_glob: str = Field(
        ..., description="fnmatch-compatible tool-name glob"
    )
    verb: str = ""
    namespace: str = ""
    resource: str = ""


class CompileResult(BaseModel):
    """Result of compiling one or more scope patterns."""

    compiled: list[CompiledScope] = Field(default_factory=list)
    errors: list[ScopeParseError] = Field(default_factory=list)
    valid: bool = True


# ---------------------------------------------------------------------------
# APEP-303: PlanCheckpointFilter — Scope-aware checkpoint matching
# ---------------------------------------------------------------------------


class CheckpointMatchResult(BaseModel):
    """Result of matching a tool call against requires_checkpoint scope patterns."""

    matches: bool = Field(
        default=False,
        description="True if the tool call matches any checkpoint pattern",
    )
    matched_pattern: str | None = Field(
        default=None,
        description="The checkpoint scope pattern that matched (if any)",
    )
    tool_name: str = ""
    detail: str = ""


# ---------------------------------------------------------------------------
# APEP-304: PlanScopeFilter — Scope allow-check
# ---------------------------------------------------------------------------


class ScopeCheckResult(BaseModel):
    """Result of checking whether a tool call is allowed by plan scope."""

    allowed: bool = Field(
        default=False,
        description="True if the tool call is permitted by at least one scope pattern",
    )
    matched_pattern: str | None = Field(
        default=None,
        description="The scope pattern that granted access (if any)",
    )
    tool_name: str = ""
    detail: str = ""


# ---------------------------------------------------------------------------
# API Request / Response schemas
# ---------------------------------------------------------------------------


class ParseScopeRequest(BaseModel):
    """Request body for POST /v1/scopes/parse."""

    patterns: list[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Scope pattern strings to parse",
    )


class ParseScopeResponse(BaseModel):
    """Response body for POST /v1/scopes/parse."""

    tokens: list[ScopeToken] = Field(default_factory=list)
    errors: list[ScopeParseError] = Field(default_factory=list)
    valid: bool = True


class CompileScopeRequest(BaseModel):
    """Request body for POST /v1/scopes/compile."""

    patterns: list[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Scope pattern strings to compile",
    )


class CompileScopeResponse(BaseModel):
    """Response body for POST /v1/scopes/compile."""

    compiled: list[CompiledScope] = Field(default_factory=list)
    errors: list[ScopeParseError] = Field(default_factory=list)
    valid: bool = True


class CheckScopeRequest(BaseModel):
    """Request body for POST /v1/scopes/check."""

    tool_name: str = Field(..., min_length=1, description="Tool name to check")
    scope: list[str] = Field(
        ...,
        min_length=1,
        description="Scope patterns to check against",
    )


class CheckScopeResponse(BaseModel):
    """Response body for POST /v1/scopes/check."""

    allowed: bool = False
    matched_pattern: str | None = None
    tool_name: str = ""
    detail: str = ""


class CheckpointCheckRequest(BaseModel):
    """Request body for POST /v1/scopes/checkpoint."""

    tool_name: str = Field(..., min_length=1, description="Tool name to check")
    requires_checkpoint: list[str] = Field(
        ...,
        min_length=1,
        description="Checkpoint scope patterns to check against",
    )


class CheckpointCheckResponse(BaseModel):
    """Response body for POST /v1/scopes/checkpoint."""

    matches: bool = False
    matched_pattern: str | None = None
    tool_name: str = ""
    detail: str = ""
