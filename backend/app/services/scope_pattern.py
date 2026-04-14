"""Sprint 38 — Scope Pattern Language & DSL Compiler.

APEP-300: Scope pattern syntax (verb:namespace:resource).
APEP-301: ScopePatternParser — parse raw scope strings into ScopeTokens.
APEP-302: ScopePatternCompiler — compile scope patterns to fnmatch tool-name globs.
APEP-303: PlanCheckpointFilter — scope-aware requires_checkpoint matching.
APEP-304: PlanScopeFilter — scope allow-check against plan scope list.
"""

from __future__ import annotations

import fnmatch
import logging
import re

from app.models.scope_pattern import (
    WILDCARD,
    MAX_SCOPE_LENGTH,
    MIN_SCOPE_PARTS,
    RESOURCE_SEPARATOR,
    SCOPE_SEPARATOR,
    CheckpointMatchResult,
    CompiledScope,
    CompileResult,
    ScopeCheckResult,
    ScopeParseError,
    ScopeParseResult,
    ScopeToken,
)

logger = logging.getLogger(__name__)

# Allowed characters in each scope segment: alphanumeric, underscore, hyphen, dot, and wildcard
_SEGMENT_RE = re.compile(r"^[a-zA-Z0-9_\-.*]+$")


# ---------------------------------------------------------------------------
# APEP-301: ScopePatternParser
# ---------------------------------------------------------------------------


class ScopePatternParser:
    """Parses raw ``verb:namespace:resource`` strings into structured ScopeTokens.

    Validation rules:
    - Pattern must contain exactly 3 colon-separated segments.
    - Each segment must be non-empty.
    - Each segment must match ``[a-zA-Z0-9_\\-.*]+``.
    - Total pattern length must not exceed MAX_SCOPE_LENGTH.
    """

    def parse(self, pattern: str) -> ScopeToken | ScopeParseError:
        """Parse a single scope pattern string.

        Returns a ScopeToken on success, or a ScopeParseError on failure.
        """
        if not pattern or not pattern.strip():
            return ScopeParseError(pattern=pattern, error="Empty scope pattern")

        pattern = pattern.strip()

        if len(pattern) > MAX_SCOPE_LENGTH:
            return ScopeParseError(
                pattern=pattern,
                error=f"Scope pattern exceeds maximum length of {MAX_SCOPE_LENGTH}",
            )

        parts = pattern.split(SCOPE_SEPARATOR)
        if len(parts) != MIN_SCOPE_PARTS:
            return ScopeParseError(
                pattern=pattern,
                error=f"Scope pattern must have exactly {MIN_SCOPE_PARTS} colon-separated segments "
                f"(verb:namespace:resource), got {len(parts)}",
            )

        verb, namespace, resource = parts

        # Validate each segment
        for i, (segment, name) in enumerate(
            [(verb, "verb"), (namespace, "namespace"), (resource, "resource")]
        ):
            if not segment:
                return ScopeParseError(
                    pattern=pattern,
                    error=f"Empty {name} segment",
                    position=i,
                )
            if not _SEGMENT_RE.match(segment):
                return ScopeParseError(
                    pattern=pattern,
                    error=f"Invalid characters in {name} segment: '{segment}'",
                    position=i,
                )

        return ScopeToken(raw=pattern, verb=verb, namespace=namespace, resource=resource)

    def parse_many(self, patterns: list[str]) -> ScopeParseResult:
        """Parse multiple scope pattern strings.

        Returns a ScopeParseResult containing all successfully parsed tokens
        and any errors encountered.
        """
        tokens: list[ScopeToken] = []
        errors: list[ScopeParseError] = []

        for pattern in patterns:
            result = self.parse(pattern)
            if isinstance(result, ScopeToken):
                tokens.append(result)
            else:
                errors.append(result)

        return ScopeParseResult(
            tokens=tokens,
            errors=errors,
            valid=len(errors) == 0,
        )


# Module-level singleton
scope_pattern_parser = ScopePatternParser()


# ---------------------------------------------------------------------------
# APEP-302: ScopePatternCompiler
# ---------------------------------------------------------------------------


class ScopePatternCompiler:
    """Compiles ``verb:namespace:resource`` scope patterns into fnmatch-compatible
    tool-name glob patterns.

    Compilation strategy:
    - The resource segment is the primary match target for tool names.
    - Verb and namespace are used as qualifying prefixes when not wildcards.
    - ``resource.*`` → ``resource.*`` (fnmatch glob)
    - ``*`` → ``*`` (match everything)
    - Dots in resource are preserved as-is for hierarchical matching.

    The resulting tool_glob can be used with ``fnmatch.fnmatch(tool_name, glob)``
    to check whether a tool call is permitted by the scope.
    """

    def __init__(self, parser: ScopePatternParser | None = None) -> None:
        self._parser = parser or scope_pattern_parser

    def compile(self, pattern: str) -> CompiledScope | ScopeParseError:
        """Compile a single scope pattern to a tool-name glob.

        Returns a CompiledScope on success, or a ScopeParseError on failure.
        """
        result = self._parser.parse(pattern)
        if isinstance(result, ScopeParseError):
            return result

        token = result
        tool_glob = self._token_to_glob(token)

        return CompiledScope(
            source_pattern=token.raw,
            tool_glob=tool_glob,
            verb=token.verb,
            namespace=token.namespace,
            resource=token.resource,
        )

    def compile_many(self, patterns: list[str]) -> CompileResult:
        """Compile multiple scope patterns to tool-name globs."""
        compiled: list[CompiledScope] = []
        errors: list[ScopeParseError] = []

        for pattern in patterns:
            result = self.compile(pattern)
            if isinstance(result, CompiledScope):
                compiled.append(result)
            else:
                errors.append(result)

        return CompileResult(
            compiled=compiled,
            errors=errors,
            valid=len(errors) == 0,
        )

    def _token_to_glob(self, token: ScopeToken) -> str:
        """Convert a parsed ScopeToken to an fnmatch glob pattern.

        Mapping rules:
        - If all three parts are ``*``, the glob is ``*`` (match any tool).
        - The resource forms the base of the glob.
        - If verb is not ``*``, it is prepended as ``verb.`` prefix qualifier.
        - If namespace is not ``*``, it is prepended as ``namespace.`` prefix qualifier.
        - The final glob is: ``[namespace.][verb.]resource``

        This allows tool names like ``internal.read.reports.q3`` or ``file.read``
        to be matched against compiled scope globs.

        For simple tool-name matching (the common case), the resource segment
        alone serves as the glob, since most tool registries use flat or
        dot-hierarchical names (e.g., ``file.read``, ``db.users.list``).
        """
        # All-wildcard → match everything
        if token.verb_is_wildcard and token.namespace_is_wildcard and token.resource_is_wildcard:
            return "*"

        # Build glob from resource segment (primary match)
        glob = token.resource

        # When verb or namespace are specific, include them as prefix qualifiers
        # to narrow matching. This supports tool naming conventions like
        # "namespace.verb.resource" while still matching simple "resource" names.
        parts: list[str] = []
        if not token.namespace_is_wildcard:
            parts.append(token.namespace)
        if not token.verb_is_wildcard:
            parts.append(token.verb)
        parts.append(glob)

        # If we have prefixes, build composite glob; otherwise just use resource
        if len(parts) > 1:
            return RESOURCE_SEPARATOR.join(parts)
        return glob


# Module-level singleton
scope_pattern_compiler = ScopePatternCompiler()


# ---------------------------------------------------------------------------
# APEP-303: PlanCheckpointFilter — scope-aware checkpoint matching
# ---------------------------------------------------------------------------


class PlanCheckpointFilter:
    """Checks whether a tool call matches any ``requires_checkpoint`` scope pattern.

    When a match is found, the tool call should trigger an ESCALATE decision
    regardless of RBAC, forcing human review.

    Matching uses two strategies:
    1. Compile the checkpoint pattern to a tool-name glob and fnmatch against
       the tool name (structured scope matching).
    2. Fall back to direct fnmatch of the raw pattern against the tool name
       (backwards-compatible with simple glob patterns).
    """

    def __init__(self, compiler: ScopePatternCompiler | None = None) -> None:
        self._compiler = compiler or scope_pattern_compiler

    def matches(self, tool_name: str, checkpoint_patterns: list[str]) -> CheckpointMatchResult:
        """Check if a tool name matches any checkpoint scope pattern.

        Args:
            tool_name: The tool name from the tool call request.
            checkpoint_patterns: The ``requires_checkpoint`` patterns from the plan.

        Returns:
            CheckpointMatchResult indicating match status and which pattern matched.
        """
        for pattern in checkpoint_patterns:
            # Strategy 1: compile scope pattern and match against tool glob
            compiled = self._compiler.compile(pattern)
            if isinstance(compiled, CompiledScope):
                if fnmatch.fnmatch(tool_name, compiled.tool_glob):
                    return CheckpointMatchResult(
                        matches=True,
                        matched_pattern=pattern,
                        tool_name=tool_name,
                        detail=f"Tool '{tool_name}' matched checkpoint pattern "
                        f"'{pattern}' via compiled glob '{compiled.tool_glob}'",
                    )

            # Strategy 2: direct fnmatch (backwards-compatible with simple globs)
            if fnmatch.fnmatch(tool_name, pattern):
                return CheckpointMatchResult(
                    matches=True,
                    matched_pattern=pattern,
                    tool_name=tool_name,
                    detail=f"Tool '{tool_name}' matched checkpoint pattern "
                    f"'{pattern}' via direct glob match",
                )

        return CheckpointMatchResult(
            matches=False,
            tool_name=tool_name,
            detail=f"Tool '{tool_name}' did not match any of "
            f"{len(checkpoint_patterns)} checkpoint patterns",
        )


# Module-level singleton
plan_checkpoint_filter = PlanCheckpointFilter()


# ---------------------------------------------------------------------------
# APEP-304: PlanScopeFilter — scope allow-check
# ---------------------------------------------------------------------------


class PlanScopeFilter:
    """Checks whether a tool call is allowed by a plan's scope patterns.

    A tool call is allowed if it matches at least one scope pattern in the
    plan's ``scope`` list. An empty scope list means no restrictions (all
    tool calls are allowed by scope).

    Matching uses two strategies (same as PlanCheckpointFilter):
    1. Compile scope → tool-name glob → fnmatch.
    2. Direct fnmatch fallback.
    """

    def __init__(self, compiler: ScopePatternCompiler | None = None) -> None:
        self._compiler = compiler or scope_pattern_compiler

    def check(self, tool_name: str, scope_patterns: list[str]) -> ScopeCheckResult:
        """Check if a tool name is allowed by any scope pattern.

        Args:
            tool_name: The tool name from the tool call request.
            scope_patterns: The ``scope`` patterns from the plan.

        Returns:
            ScopeCheckResult indicating whether the tool call is allowed.
        """
        # Empty scope list → no restrictions
        if not scope_patterns:
            return ScopeCheckResult(
                allowed=True,
                tool_name=tool_name,
                detail="No scope restrictions — all tools allowed",
            )

        for pattern in scope_patterns:
            # Strategy 1: compile scope pattern and match tool glob
            compiled = self._compiler.compile(pattern)
            if isinstance(compiled, CompiledScope):
                if fnmatch.fnmatch(tool_name, compiled.tool_glob):
                    return ScopeCheckResult(
                        allowed=True,
                        matched_pattern=pattern,
                        tool_name=tool_name,
                        detail=f"Tool '{tool_name}' allowed by scope pattern "
                        f"'{pattern}' via compiled glob '{compiled.tool_glob}'",
                    )

            # Strategy 2: direct fnmatch fallback
            if fnmatch.fnmatch(tool_name, pattern):
                return ScopeCheckResult(
                    allowed=True,
                    matched_pattern=pattern,
                    tool_name=tool_name,
                    detail=f"Tool '{tool_name}' allowed by scope pattern "
                    f"'{pattern}' via direct glob match",
                )

        return ScopeCheckResult(
            allowed=False,
            tool_name=tool_name,
            detail=f"Tool '{tool_name}' not allowed by any of "
            f"{len(scope_patterns)} scope patterns",
        )


# Module-level singleton
plan_scope_filter = PlanScopeFilter()
