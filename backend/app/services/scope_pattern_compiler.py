"""Sprint 38 -- ScopePatternCompiler: maps scope patterns to RBAC tool-name globs.

APEP-302: ScopePatternCompiler implementation.

The compiler translates ``verb:namespace:resource`` scope patterns into
fnmatch-style tool-name glob patterns that the existing RBAC RuleMatcher
understands. This bridges human-readable scope notation with the
underlying RBAC engine.

Mapping strategy:

    verb       -> tool-name prefix
    namespace  -> tool-name middle segment
    resource   -> tool-name suffix (glob)

    read:public:*         -> file.read.*, db.read.*, api.get.*
    write:secret:creds.*  -> secret.write.creds.*, credential.write.creds.*
    execute:internal:*    -> exec.*, shell.*, deploy.*
    *:*:*                 -> *  (unrestricted)
"""

from __future__ import annotations

import fnmatch
import logging

from app.models.scope_pattern import (
    ScopeBatchCompileResponse,
    ScopeCompileResult,
    ScopePattern,
)
from app.services.scope_pattern_parser import scope_pattern_parser

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# APEP-302: Verb -> tool-name prefix mapping
# ---------------------------------------------------------------------------

_VERB_TOOL_PREFIXES: dict[str, list[str]] = {
    "read": ["file.read", "db.read", "api.get", "read"],
    "write": ["file.write", "db.write", "api.post", "api.put", "write"],
    "delete": ["file.delete", "db.drop", "db.delete", "api.delete", "delete"],
    "execute": ["exec", "shell", "deploy", "execute"],
    "send": ["email.send", "slack.send", "notify", "send"],
    "*": ["*"],
}

# ---------------------------------------------------------------------------
# APEP-302: Namespace -> tool-name segment mapping
# ---------------------------------------------------------------------------

_NAMESPACE_SEGMENTS: dict[str, list[str]] = {
    "public": ["public"],
    "secret": ["secret", "credential"],
    "internal": ["internal", "admin"],
    "external": ["external", "api"],
    "*": ["*"],
}


class ScopePatternCompiler:
    """Compiles scope patterns into RBAC-compatible tool-name globs.

    The compiler produces a set of fnmatch glob patterns that can be
    evaluated by the existing RuleMatcher against incoming tool names.

    Usage::

        compiler = ScopePatternCompiler()
        result = compiler.compile("read:public:*")
        print(result.rbac_patterns)
        # ['file.read.public.*', 'db.read.public.*', ...]
    """

    def __init__(
        self,
        verb_prefixes: dict[str, list[str]] | None = None,
        namespace_segments: dict[str, list[str]] | None = None,
    ) -> None:
        self._verb_prefixes = _VERB_TOOL_PREFIXES if verb_prefixes is None else verb_prefixes
        self._namespace_segments = _NAMESPACE_SEGMENTS if namespace_segments is None else namespace_segments

    def compile(self, pattern: str) -> ScopeCompileResult:
        """Compile a single scope pattern to RBAC tool-name globs.

        Parses the pattern, maps verb/namespace to tool prefixes, and
        produces a list of fnmatch-compatible glob patterns.
        """
        result = scope_pattern_parser.parse(pattern)
        if not result.valid or result.scope_pattern is None:
            return ScopeCompileResult(
                scope_pattern=ScopePattern(pattern=pattern),
                rbac_patterns=[],
                warnings=[result.error or "Invalid scope pattern"],
            )

        sp = result.scope_pattern
        assert sp.verb is not None
        assert sp.namespace is not None
        assert sp.resource_glob is not None

        # Full wildcard shortcut
        if sp.verb == "*" and sp.namespace == "*" and sp.resource_glob == "*":
            sp.mapped_rbac_patterns = ["*"]
            return ScopeCompileResult(
                scope_pattern=sp,
                rbac_patterns=["*"],
            )

        warnings: list[str] = []
        rbac_patterns: list[str] = []

        prefixes = self._verb_prefixes.get(sp.verb, [])
        if not prefixes:
            warnings.append(f"No tool prefix mapping for verb '{sp.verb}'")
            prefixes = [sp.verb]

        segments = self._namespace_segments.get(sp.namespace, [])
        if not segments:
            warnings.append(f"No tool segment mapping for namespace '{sp.namespace}'")
            segments = [sp.namespace]

        for prefix in prefixes:
            for segment in segments:
                if prefix == "*":
                    # Wildcard verb: just use segment and resource
                    if segment == "*":
                        rbac_patterns.append(f"*.{sp.resource_glob}")
                    else:
                        rbac_patterns.append(f"*.{segment}.{sp.resource_glob}")
                elif segment == "*":
                    # Wildcard namespace: prefix + any segment + resource
                    rbac_patterns.append(f"{prefix}.*.{sp.resource_glob}")
                else:
                    rbac_patterns.append(
                        f"{prefix}.{segment}.{sp.resource_glob}"
                    )

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for p in rbac_patterns:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        rbac_patterns = unique

        sp.mapped_rbac_patterns = rbac_patterns

        return ScopeCompileResult(
            scope_pattern=sp,
            rbac_patterns=rbac_patterns,
            warnings=warnings,
        )

    def compile_many(self, patterns: list[str]) -> ScopeBatchCompileResponse:
        """Compile multiple scope patterns and return aggregated results."""
        results: list[ScopeCompileResult] = []
        all_patterns: set[str] = set()

        for pattern in patterns:
            result = self.compile(pattern)
            results.append(result)
            all_patterns.update(result.rbac_patterns)

        return ScopeBatchCompileResponse(
            results=results,
            all_rbac_patterns=sorted(all_patterns),
        )

    def matches_tool(self, scope_patterns: list[str], tool_name: str) -> str | None:
        """Check if a tool name matches any of the given scope patterns.

        Compiles each scope pattern to RBAC globs and checks if any glob
        matches the tool name. Returns the matching scope pattern string,
        or None if no match.
        """
        for pattern in scope_patterns:
            result = self.compile(pattern)
            for rbac_glob in result.rbac_patterns:
                if fnmatch.fnmatch(tool_name, rbac_glob):
                    return pattern
        return None


# Module-level singleton
scope_pattern_compiler = ScopePatternCompiler()
