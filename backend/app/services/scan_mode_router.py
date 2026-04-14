"""ScanModeRouter — per-category scan mode restrictions.

Sprint 52 — APEP-414: Routes injection scans through the appropriate subset
of patterns based on the active scan mode.  Each ToolTrust category is mapped
to one or more allowed scan modes (STRICT, STANDARD, LENIENT).  STRICT enables
all categories, STANDARD enables a hardened subset, and LENIENT only enables
categories with the highest false-positive confidence.

The router wraps :class:`InjectionSignatureLibrary` and filters results
according to the active mode before returning them to callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from app.models.policy import InjectionSignature
from app.services.injection_signatures import (
    InjectionSignatureLibrary,
    MatchedSignature,
    injection_library,
)


# ---------------------------------------------------------------------------
# Scan mode enum (maps to InjectionSignature.scan_modes values)
# ---------------------------------------------------------------------------


class CISScanMode(StrEnum):
    """Content Ingestion Security scan modes.

    STRICT  — all 25 categories active; maximum protection.
    STANDARD — balanced subset; suppresses low-confidence categories.
    LENIENT — minimal scanning; only high-confidence, low-FP categories.
    """

    STRICT = "STRICT"
    STANDARD = "STANDARD"
    LENIENT = "LENIENT"


# ---------------------------------------------------------------------------
# Default per-category mode restrictions
# ---------------------------------------------------------------------------

# Categories active in each mode.  STRICT always includes everything.
# STANDARD drops context_overflow, output_manipulation, resource_abuse (higher FP).
# LENIENT keeps only the most unambiguous attack / DLP categories.

_STANDARD_CATEGORIES: frozenset[str] = frozenset(
    [
        "prompt_override",
        "role_hijack",
        "system_escape",
        "jailbreak",
        "encoding_bypass",
        "indirect_injection",
        "multi_turn_attack",
        "privilege_probe",
        "social_engineering",
        "reconnaissance",
        "data_exfiltration",
        "tool_manipulation",
        "instruction_hierarchy",
        "goal_hijacking",
        "configuration_attack",
        "supply_chain",
        "persistence",
        "dlp_api_key",
        "dlp_token",
        "dlp_credential",
        "dlp_cloud_token",
        "dlp_secret",
    ]
)

_LENIENT_CATEGORIES: frozenset[str] = frozenset(
    [
        "prompt_override",
        "role_hijack",
        "system_escape",
        "jailbreak",
        "data_exfiltration",
        "supply_chain",
        "dlp_api_key",
        "dlp_token",
        "dlp_credential",
        "dlp_cloud_token",
        "dlp_secret",
    ]
)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


@dataclass
class ScanModeRouter:
    """Filters injection signature results by the active scan mode.

    Parameters
    ----------
    library:
        The :class:`InjectionSignatureLibrary` to delegate matching to.
        Defaults to the module-level singleton.
    standard_categories:
        Categories enabled in STANDARD mode.
    lenient_categories:
        Categories enabled in LENIENT mode.
    """

    library: InjectionSignatureLibrary = field(default_factory=lambda: injection_library)
    standard_categories: frozenset[str] = _STANDARD_CATEGORIES
    lenient_categories: frozenset[str] = _LENIENT_CATEGORIES

    # -- Public API ---------------------------------------------------------

    def check(
        self,
        text: str,
        mode: CISScanMode = CISScanMode.STRICT,
    ) -> list[MatchedSignature]:
        """Return matching signatures filtered by *mode*."""
        all_matches = self.library.check(text)
        if mode == CISScanMode.STRICT:
            return all_matches
        allowed = self._allowed_categories(mode)
        return [m for m in all_matches if m.category in allowed]

    def check_any(
        self,
        text: str,
        mode: CISScanMode = CISScanMode.STRICT,
    ) -> bool:
        """Return ``True`` if *text* matches at least one signature in *mode*."""
        return len(self.check(text, mode)) > 0

    def active_categories(self, mode: CISScanMode) -> frozenset[str]:
        """Return the set of categories enabled for *mode*."""
        if mode == CISScanMode.STRICT:
            return frozenset(cat for cat in self.library._by_category)
        return self._allowed_categories(mode)

    def active_signatures(self, mode: CISScanMode) -> list[InjectionSignature]:
        """Return signatures enabled for *mode*."""
        if mode == CISScanMode.STRICT:
            return self.library.signatures
        allowed = self._allowed_categories(mode)
        return [s for s in self.library.signatures if s.category in allowed]

    # -- Internal -----------------------------------------------------------

    def _allowed_categories(self, mode: CISScanMode) -> frozenset[str]:
        if mode == CISScanMode.STANDARD:
            return self.standard_categories
        if mode == CISScanMode.LENIENT:
            return self.lenient_categories
        return frozenset(cat for cat in self.library._by_category)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

scan_mode_router = ScanModeRouter()
