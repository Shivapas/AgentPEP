"""Injection signature library — categorised prompt injection pattern detection.

APEP-049: A curated library of injection signatures used to detect prompt
injection attempts across five categories: prompt_override, role_hijack,
system_escape, jailbreak, and encoding_bypass.

Patterns are compiled at initialisation for runtime performance.  The module
exposes a singleton ``injection_library`` for use by taint analysis and
policy evaluation layers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from app.models.policy import InjectionSignature

# ---------------------------------------------------------------------------
# Matched result returned by check()
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MatchedSignature:
    """Lightweight result object returned when a signature matches input text."""

    signature_id: str
    category: str
    severity: str
    description: str


# ---------------------------------------------------------------------------
# Signature definitions
# ---------------------------------------------------------------------------

_SIGNATURES: list[InjectionSignature] = [
    # ── prompt_override ────────────────────────────────────────────────
    InjectionSignature(
        signature_id="INJ-001",
        category="prompt_override",
        pattern=r"(?i)ignore\s+all\s+previous\s+instructions",
        severity="CRITICAL",
        description="Attempts to override all prior instructions",
    ),
    InjectionSignature(
        signature_id="INJ-002",
        category="prompt_override",
        pattern=r"(?i)disregard\s+all\s+previous\s+prompts?",
        severity="CRITICAL",
        description="Instructs the model to disregard previous prompts",
    ),
    InjectionSignature(
        signature_id="INJ-003",
        category="prompt_override",
        pattern=r"(?i)forget\s+your\s+previous\s+instructions",
        severity="HIGH",
        description="Asks the model to forget prior instructions",
    ),
    InjectionSignature(
        signature_id="INJ-004",
        category="prompt_override",
        pattern=r"(?i)new\s+instructions\s*:",
        severity="HIGH",
        description="Introduces replacement instructions via a labelled block",
    ),
    InjectionSignature(
        signature_id="INJ-005",
        category="prompt_override",
        pattern=r"(?i)do\s+not\s+follow\s+the\s+previous\s+instructions",
        severity="HIGH",
        description="Explicitly tells the model not to follow prior instructions",
    ),
    InjectionSignature(
        signature_id="INJ-006",
        category="prompt_override",
        pattern=r"(?i)override\s+previous\s+directives?",
        severity="HIGH",
        description="Attempts to override previous directives",
    ),
    InjectionSignature(
        signature_id="INJ-007",
        category="prompt_override",
        pattern=r"(?i)from\s+now\s+on\s+ignore\s+all\s+rules",
        severity="CRITICAL",
        description="Instructs the model to ignore all rules going forward",
    ),
    InjectionSignature(
        signature_id="INJ-008",
        category="prompt_override",
        pattern=r"(?i)reset\s+and\s+start\s+fresh\s+with\s+these\s+instructions",
        severity="HIGH",
        description="Attempts a full context reset with new instructions",
    ),
    InjectionSignature(
        signature_id="INJ-009",
        category="prompt_override",
        pattern=r"(?i)ignore\s+(the\s+)?(above|prior|earlier)\s+(instructions?|directions?|prompts?)",
        severity="HIGH",
        description="Variant phrasing to ignore prior context",
    ),

    # ── role_hijack ────────────────────────────────────────────────────
    InjectionSignature(
        signature_id="INJ-010",
        category="role_hijack",
        pattern=r"(?i)you\s+are\s+now\s+a\s+",
        severity="HIGH",
        description="Attempts to reassign the model's identity",
    ),
    InjectionSignature(
        signature_id="INJ-011",
        category="role_hijack",
        pattern=r"(?i)pretend\s+you\s+are\s+",
        severity="HIGH",
        description="Asks the model to pretend to be something else",
    ),
    InjectionSignature(
        signature_id="INJ-012",
        category="role_hijack",
        pattern=r"(?i)act\s+as\s+if\s+you\s+have\s+no\s+restrictions",
        severity="CRITICAL",
        description="Instructs the model to behave without restrictions",
    ),
    InjectionSignature(
        signature_id="INJ-013",
        category="role_hijack",
        pattern=r"(?i)pretend\s+that\s+you\s+have\s+no\s+rules",
        severity="CRITICAL",
        description="Asks the model to pretend it has no rules",
    ),
    InjectionSignature(
        signature_id="INJ-014",
        category="role_hijack",
        pattern=r"(?i)your\s+new\s+role\s+is\s+",
        severity="HIGH",
        description="Attempts to assign a new role to the model",
    ),
    InjectionSignature(
        signature_id="INJ-015",
        category="role_hijack",
        pattern=r"(?i)\byou\s+are\s+DAN\b",
        severity="CRITICAL",
        description="DAN (Do Anything Now) role hijack attempt",
    ),
    InjectionSignature(
        signature_id="INJ-016",
        category="role_hijack",
        pattern=r"(?i)imagine\s+you\s+are\s+an?\s+unrestricted",
        severity="HIGH",
        description="Asks the model to imagine being unrestricted",
    ),

    # ── system_escape ──────────────────────────────────────────────────
    InjectionSignature(
        signature_id="INJ-017",
        category="system_escape",
        pattern=r"\[SYSTEM\]",
        severity="HIGH",
        description="Fake system message tag in square brackets",
    ),
    InjectionSignature(
        signature_id="INJ-018",
        category="system_escape",
        pattern=r"<\s*system\s*>",
        severity="HIGH",
        description="Fake system message using XML-style tag",
    ),
    InjectionSignature(
        signature_id="INJ-019",
        category="system_escape",
        pattern=r"(?i)^system\s*:\s*you\s+are",
        severity="HIGH",
        description="Fake system prompt prefixed with 'system:'",
    ),
    InjectionSignature(
        signature_id="INJ-020",
        category="system_escape",
        pattern=r"(?i)ADMIN\s+OVERRIDE",
        severity="CRITICAL",
        description="Fake admin override command",
    ),
    InjectionSignature(
        signature_id="INJ-021",
        category="system_escape",
        pattern=r"(?i)\bsudo\s+mode\b",
        severity="HIGH",
        description="Fake sudo/superuser mode activation",
    ),
    InjectionSignature(
        signature_id="INJ-022",
        category="system_escape",
        pattern=r"(?i)\broot\s+access\s+granted\b",
        severity="HIGH",
        description="Fake root access declaration",
    ),
    InjectionSignature(
        signature_id="INJ-023",
        category="system_escape",
        pattern=r"\{\{\s*system_prompt\s*\}\}",
        severity="MEDIUM",
        description="Template injection attempting to extract system prompt",
    ),
    InjectionSignature(
        signature_id="INJ-024",
        category="system_escape",
        pattern=r"```\s*system\b",
        severity="MEDIUM",
        description="Fake system block inside markdown code fence",
    ),

    # ── jailbreak ──────────────────────────────────────────────────────
    InjectionSignature(
        signature_id="INJ-025",
        category="jailbreak",
        pattern=r"(?i)\bjailbreak\b",
        severity="HIGH",
        description="Explicit mention of jailbreak intent",
    ),
    InjectionSignature(
        signature_id="INJ-026",
        category="jailbreak",
        pattern=r"(?i)\bDAN\s+mode\b",
        severity="CRITICAL",
        description="DAN (Do Anything Now) jailbreak mode",
    ),
    InjectionSignature(
        signature_id="INJ-027",
        category="jailbreak",
        pattern=r"(?i)developer\s+mode\s+enabled",
        severity="HIGH",
        description="Fake developer mode activation",
    ),
    InjectionSignature(
        signature_id="INJ-028",
        category="jailbreak",
        pattern=r"(?i)enable\s+unrestricted\s+mode",
        severity="CRITICAL",
        description="Attempts to enable an unrestricted mode",
    ),
    InjectionSignature(
        signature_id="INJ-029",
        category="jailbreak",
        pattern=r"(?i)bypass\s+safety\s+filters?",
        severity="CRITICAL",
        description="Explicit attempt to bypass safety filters",
    ),
    InjectionSignature(
        signature_id="INJ-030",
        category="jailbreak",
        pattern=r"(?i)remove\s+all\s+content\s+filters?",
        severity="CRITICAL",
        description="Requests removal of all content filters",
    ),
    InjectionSignature(
        signature_id="INJ-031",
        category="jailbreak",
        pattern=r"(?i)\bdo\s+anything\s+now\b",
        severity="HIGH",
        description="'Do Anything Now' jailbreak phrase",
    ),

    # ── encoding_bypass ────────────────────────────────────────────────
    InjectionSignature(
        signature_id="INJ-032",
        category="encoding_bypass",
        pattern=r"(?i)aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM=",
        severity="CRITICAL",
        description="Base64-encoded 'ignore all previous instructions'",
    ),
    InjectionSignature(
        signature_id="INJ-033",
        category="encoding_bypass",
        pattern=r"(?i)\b[A-Za-z0-9+/]{20,}={0,2}\b",
        severity="LOW",
        description="Suspicious base64-encoded blob (potential encoded injection)",
    ),
    InjectionSignature(
        signature_id="INJ-034",
        category="encoding_bypass",
        pattern=r"(?i)\bvtaber\s+nyy\s+cerivbhf\s+vafgehpgvbaf\b",
        severity="HIGH",
        description="ROT13-encoded 'ignore all previous instructions'",
    ),
    InjectionSignature(
        signature_id="INJ-035",
        category="encoding_bypass",
        pattern=r"[\u0400-\u04ff][\u0000-\u007f][\u0400-\u04ff]|[\u0000-\u007f][\u0400-\u04ff][\u0000-\u007f][\u0400-\u04ff]",
        severity="MEDIUM",
        description="Mixed Cyrillic/Latin script suggesting homoglyph substitution",
    ),
    InjectionSignature(
        signature_id="INJ-036",
        category="encoding_bypass",
        pattern=r"<\s*script\b[^>]*>",
        severity="HIGH",
        description="HTML script tag injection",
    ),
    InjectionSignature(
        signature_id="INJ-037",
        category="encoding_bypass",
        pattern=r"(?i)javascript\s*:",
        severity="HIGH",
        description="JavaScript URI scheme injection",
    ),
    InjectionSignature(
        signature_id="INJ-038",
        category="encoding_bypass",
        pattern=r"\|{3,}|={3,}|-{3,}",
        severity="LOW",
        description="Delimiter-based prompt section injection (|||, ===, ---)",
    ),
    InjectionSignature(
        signature_id="INJ-039",
        category="encoding_bypass",
        pattern=r"[\u200b\u200c\u200d\u2060\ufeff]",
        severity="MEDIUM",
        description="Zero-width character injection (ZWSP, ZWNJ, ZWJ, WJ, BOM)",
    ),
    InjectionSignature(
        signature_id="INJ-040",
        category="encoding_bypass",
        pattern=r"[\u0370-\u03ff][\u0000-\u007f]{1,3}[\u0370-\u03ff]",
        severity="MEDIUM",
        description="Mixed Greek/Latin script suggesting homoglyph substitution",
    ),
]


# ---------------------------------------------------------------------------
# Compiled signature (internal)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _CompiledSignature:
    """A signature with its regex pre-compiled for fast matching."""

    signature: InjectionSignature
    compiled: re.Pattern[str]


# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------


class InjectionSignatureLibrary:
    """Categorised library of prompt injection detection signatures.

    All regex patterns are compiled once at initialisation.  Public methods are
    safe for concurrent reads (the internal data structures are immutable after
    ``__init__``).
    """

    def __init__(self, signatures: Sequence[InjectionSignature] | None = None) -> None:
        raw = list(signatures) if signatures is not None else list(_SIGNATURES)
        self._signatures: list[InjectionSignature] = raw
        self._compiled: list[_CompiledSignature] = []

        for sig in raw:
            try:
                compiled = re.compile(sig.pattern)
            except re.error as exc:
                raise ValueError(
                    f"Invalid regex in signature {sig.signature_id}: {exc}"
                ) from exc
            self._compiled.append(_CompiledSignature(signature=sig, compiled=compiled))

        # Pre-build category and severity indexes for fast lookups.
        self._by_category: dict[str, list[InjectionSignature]] = {}
        self._by_severity: dict[str, list[InjectionSignature]] = {}
        for sig in raw:
            self._by_category.setdefault(sig.category, []).append(sig)
            self._by_severity.setdefault(sig.severity, []).append(sig)

    # -- Public API ---------------------------------------------------------

    def check(self, text: str) -> list[MatchedSignature]:
        """Return all signatures that match *text*.

        The returned list preserves signature declaration order so that
        higher-priority (lower ID) signatures appear first.
        """
        matches: list[MatchedSignature] = []
        for entry in self._compiled:
            if entry.compiled.search(text):
                sig = entry.signature
                matches.append(
                    MatchedSignature(
                        signature_id=sig.signature_id,
                        category=sig.category,
                        severity=sig.severity,
                        description=sig.description,
                    )
                )
        return matches

    def check_any(self, text: str) -> bool:
        """Return ``True`` if *text* matches at least one signature."""
        for entry in self._compiled:
            if entry.compiled.search(text):
                return True
        return False

    def get_by_category(self, category: str) -> list[InjectionSignature]:
        """Return all signatures belonging to *category*."""
        return list(self._by_category.get(category, []))

    def get_by_severity(self, severity: str) -> list[InjectionSignature]:
        """Return all signatures with the given *severity* level."""
        return list(self._by_severity.get(severity, []))

    @property
    def signatures(self) -> list[InjectionSignature]:
        """Return a copy of the full signature list."""
        return list(self._signatures)

    def __len__(self) -> int:
        return len(self._signatures)

    def __repr__(self) -> str:
        cats = sorted(self._by_category)
        return (
            f"<InjectionSignatureLibrary signatures={len(self._signatures)} "
            f"categories={cats}>"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

injection_library = InjectionSignatureLibrary()
