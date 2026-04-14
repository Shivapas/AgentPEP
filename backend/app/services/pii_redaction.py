"""PII Redaction Engine — Sprint 35 (APEP-281).

Detects and redacts Personally Identifiable Information (PII) in tool call
arguments and outputs.  Supports category-specific placeholders
(e.g. ``[SSN_REDACTED]``, ``[EMAIL_REDACTED]``) and recursive dict traversal.

PII categories: SSN, EMAIL, PHONE, CREDIT_CARD, NAME, ADDRESS, IBAN, PASSPORT.
"""

from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII categories
# ---------------------------------------------------------------------------


class PIICategory(StrEnum):
    SSN = "SSN"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CREDIT_CARD = "CREDIT_CARD"
    NAME = "NAME"
    ADDRESS = "ADDRESS"
    IBAN = "IBAN"
    PASSPORT = "PASSPORT"


# ---------------------------------------------------------------------------
# Result data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PIIMatch:
    """A single PII match found in text."""

    category: PIICategory
    original: str
    start: int
    end: int
    confidence: float


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """Result of a PII redaction operation."""

    original_text: str
    redacted_text: str
    matches: list[PIIMatch]
    redaction_count: int
    categories_found: frozenset[PIICategory]


# ---------------------------------------------------------------------------
# PII pattern library
# ---------------------------------------------------------------------------

_PII_PATTERNS: list[tuple[PIICategory, re.Pattern[str], float]] = [
    # SSN: 123-45-6789
    (PIICategory.SSN, re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.95),
    # Email
    (
        PIICategory.EMAIL,
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        0.95,
    ),
    # Phone: US formats (XXX) XXX-XXXX, XXX-XXX-XXXX, +1XXXXXXXXXX
    (
        PIICategory.PHONE,
        re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        ),
        0.85,
    ),
    # Credit card: 16 digits with optional separators
    (
        PIICategory.CREDIT_CARD,
        re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        0.90,
    ),
    # IBAN: 2 letters + 2 digits + up to 30 alphanumeric
    (
        PIICategory.IBAN,
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,23}\b"),
        0.90,
    ),
    # Passport: US-style letter + 7 digits
    (
        PIICategory.PASSPORT,
        re.compile(r"\b[A-Z]\d{7}\b"),
        0.70,
    ),
    # Address: street number + name + suffix
    (
        PIICategory.ADDRESS,
        re.compile(
            r"\b\d+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+"
            r"(?:St|Ave|Blvd|Dr|Rd|Ln|Ct|Way|Place|Pl|Circle|Cir|Street|Avenue|Boulevard|Drive|Road|Lane|Court)\b",
            re.IGNORECASE,
        ),
        0.75,
    ),
    # Name: two or more capitalised words (lower confidence — heuristic)
    (
        PIICategory.NAME,
        re.compile(r"\b[A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20}\b"),
        0.50,
    ),
]


# ---------------------------------------------------------------------------
# PII Redaction Engine
# ---------------------------------------------------------------------------


class PIIRedactionEngine:
    """Detect and redact PII in text and structured data.

    Each PII category uses a category-specific placeholder:
    ``[SSN_REDACTED]``, ``[EMAIL_REDACTED]``, etc.
    """

    def __init__(self, placeholder: str = "[REDACTED]") -> None:
        self._default_placeholder = placeholder
        self._patterns = list(_PII_PATTERNS)

    def detect(self, text: str) -> list[PIIMatch]:
        """Scan text for PII and return all matches."""
        if not text:
            return []

        matches: list[PIIMatch] = []
        for category, pattern, confidence in self._patterns:
            for m in pattern.finditer(text):
                matches.append(
                    PIIMatch(
                        category=category,
                        original=m.group(),
                        start=m.start(),
                        end=m.end(),
                        confidence=confidence,
                    )
                )

        # Sort by start position, deduplicate overlapping ranges
        matches.sort(key=lambda m: (m.start, -m.end))
        return self._deduplicate(matches)

    def redact(self, text: str) -> RedactionResult:
        """Detect PII and replace with category-specific placeholders."""
        matches = self.detect(text)
        if not matches:
            return RedactionResult(
                original_text=text,
                redacted_text=text,
                matches=[],
                redaction_count=0,
                categories_found=frozenset(),
            )

        # Apply replacements from end to start to preserve indices
        redacted = text
        for match in reversed(matches):
            placeholder = f"[{match.category.value}_REDACTED]"
            redacted = redacted[: match.start] + placeholder + redacted[match.end :]

        categories = frozenset(m.category for m in matches)
        return RedactionResult(
            original_text=text,
            redacted_text=redacted,
            matches=matches,
            redaction_count=len(matches),
            categories_found=categories,
        )

    def redact_dict(
        self, data: dict[str, Any]
    ) -> tuple[dict[str, Any], list[PIIMatch]]:
        """Recursively redact PII in all string values of a dict.

        Returns (redacted_dict, all_matches).
        The input dict is not modified — a deep copy is returned.
        """
        if not data:
            return {}, []

        result = copy.deepcopy(data)
        all_matches: list[PIIMatch] = []
        self._redact_recursive(result, all_matches)
        return result, all_matches

    def _redact_recursive(
        self, obj: Any, all_matches: list[PIIMatch]
    ) -> Any:
        """In-place recursive redaction of string values."""
        if isinstance(obj, dict):
            for key in obj:
                if isinstance(obj[key], str):
                    redaction = self.redact(obj[key])
                    if redaction.redaction_count > 0:
                        obj[key] = redaction.redacted_text
                        all_matches.extend(redaction.matches)
                elif isinstance(obj[key], (dict, list)):
                    self._redact_recursive(obj[key], all_matches)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str):
                    redaction = self.redact(item)
                    if redaction.redaction_count > 0:
                        obj[i] = redaction.redacted_text
                        all_matches.extend(redaction.matches)
                elif isinstance(item, (dict, list)):
                    self._redact_recursive(item, all_matches)
        return obj

    @staticmethod
    def _deduplicate(matches: list[PIIMatch]) -> list[PIIMatch]:
        """Remove overlapping matches, keeping the higher-confidence one."""
        if not matches:
            return []

        result: list[PIIMatch] = [matches[0]]
        for current in matches[1:]:
            prev = result[-1]
            if current.start < prev.end:
                # Overlapping: keep higher confidence
                if current.confidence > prev.confidence:
                    result[-1] = current
            else:
                result.append(current)
        return result


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

pii_redaction_engine = PIIRedactionEngine()
