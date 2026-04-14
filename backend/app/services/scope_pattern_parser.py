"""Sprint 38 -- ScopePatternParser: parses verb:namespace:resource scope notation.

APEP-300: Scope pattern syntax definition.
APEP-301: ScopePatternParser implementation.

Scope pattern format: ``verb:namespace:resource``

Valid verbs: read, write, delete, execute, send, * (wildcard)
Valid namespaces: public, secret, internal, external, * (wildcard)
Resource: any glob pattern (fnmatch-style), e.g. ``*``, ``*.txt``, ``report.*``
"""

from __future__ import annotations

import re

from app.models.scope_pattern import (
    ScopeParseResult,
    ScopePattern,
)

# ---------------------------------------------------------------------------
# APEP-300: Canonical verb and namespace sets
# ---------------------------------------------------------------------------

VALID_VERBS = frozenset({"read", "write", "delete", "execute", "send", "*"})
VALID_NAMESPACES = frozenset({"public", "secret", "internal", "external", "*"})

# Resource glob: allow alphanumeric, *, ?, ., -, _, /
_RESOURCE_GLOB_RE = re.compile(r"^[\w\*\?\.\-/]+$")

# Maximum pattern length to prevent abuse
_MAX_PATTERN_LENGTH = 256


class ScopePatternParser:
    """Parses scope pattern strings into structured ScopePattern objects.

    Usage::

        parser = ScopePatternParser()
        result = parser.parse("read:public:*.txt")
        if result.valid:
            print(result.scope_pattern.verb)       # "read"
            print(result.scope_pattern.namespace)   # "public"
            print(result.scope_pattern.resource_glob)  # "*.txt"
    """

    def parse(self, pattern: str) -> ScopeParseResult:
        """Parse a scope pattern string into its components.

        Returns a ScopeParseResult with valid=True and a populated
        ScopePattern on success, or valid=False with an error message.
        """
        if not pattern or not isinstance(pattern, str):
            return ScopeParseResult(
                valid=False,
                error="Scope pattern must be a non-empty string",
            )

        if len(pattern) > _MAX_PATTERN_LENGTH:
            return ScopeParseResult(
                valid=False,
                error=f"Scope pattern exceeds maximum length of {_MAX_PATTERN_LENGTH}",
            )

        # Split on colon -- exactly 3 parts expected
        parts = pattern.split(":")
        if len(parts) != 3:
            return ScopeParseResult(
                valid=False,
                error=(
                    f"Invalid scope pattern '{pattern}': expected format "
                    f"'verb:namespace:resource', got {len(parts)} part(s)"
                ),
            )

        verb, namespace, resource_glob = parts

        # Validate verb
        verb_lower = verb.lower()
        if verb_lower not in VALID_VERBS:
            return ScopeParseResult(
                valid=False,
                error=(
                    f"Invalid verb '{verb}' in scope pattern '{pattern}'. "
                    f"Valid verbs: {', '.join(sorted(VALID_VERBS))}"
                ),
            )

        # Validate namespace
        namespace_lower = namespace.lower()
        if namespace_lower not in VALID_NAMESPACES:
            return ScopeParseResult(
                valid=False,
                error=(
                    f"Invalid namespace '{namespace}' in scope pattern '{pattern}'. "
                    f"Valid namespaces: {', '.join(sorted(VALID_NAMESPACES))}"
                ),
            )

        # Validate resource glob
        if not resource_glob:
            return ScopeParseResult(
                valid=False,
                error=f"Empty resource glob in scope pattern '{pattern}'",
            )

        if not _RESOURCE_GLOB_RE.match(resource_glob):
            return ScopeParseResult(
                valid=False,
                error=(
                    f"Invalid resource glob '{resource_glob}' in scope pattern "
                    f"'{pattern}'. Resource globs may contain alphanumeric "
                    f"characters, *, ?, ., -, _, and /"
                ),
            )

        scope = ScopePattern(
            pattern=f"{verb_lower}:{namespace_lower}:{resource_glob}",
            verb=verb_lower,
            namespace=namespace_lower,
            resource_glob=resource_glob,
        )

        return ScopeParseResult(valid=True, scope_pattern=scope)

    def parse_many(self, patterns: list[str]) -> list[ScopeParseResult]:
        """Parse multiple scope patterns.

        Returns a list of ScopeParseResult objects, one per input pattern.
        """
        return [self.parse(p) for p in patterns]

    def is_valid(self, pattern: str) -> bool:
        """Quick check whether a scope pattern string is syntactically valid."""
        return self.parse(pattern).valid


# Module-level singleton
scope_pattern_parser = ScopePatternParser()
