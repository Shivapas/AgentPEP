"""Entropy analyzer — Shannon entropy calculation for secret detection.

Sprint 44 — APEP-352: Detects high-entropy strings that are likely secrets,
API keys, or tokens by calculating Shannon entropy and comparing against
configurable thresholds.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from app.models.network_scan import EntropyResult, ScanFinding, ScanSeverity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Entropy thresholds (bits per character)
# English text: ~3.5–4.0, base64 random: ~5.5–6.0, hex random: ~4.0
_DEFAULT_THRESHOLD = 4.5
_HIGH_ENTROPY_THRESHOLD = 5.0

# Minimum token length to analyse (short strings produce unreliable entropy)
_MIN_TOKEN_LENGTH = 16

# Regex to split text into analysable tokens (words, base64 blobs, hex strings)
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=\-_]{16,}")


# ---------------------------------------------------------------------------
# Core entropy calculation
# ---------------------------------------------------------------------------


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits per character) for *data*.

    Returns 0.0 for empty strings.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# EntropyAnalyzer
# ---------------------------------------------------------------------------


class EntropyAnalyzer:
    """Analyses text for high-entropy tokens that may be secrets or credentials.

    Thread-safe: no mutable state after initialisation.
    """

    def __init__(
        self,
        threshold: float = _DEFAULT_THRESHOLD,
        high_threshold: float = _HIGH_ENTROPY_THRESHOLD,
        min_token_length: int = _MIN_TOKEN_LENGTH,
    ) -> None:
        self._threshold = threshold
        self._high_threshold = high_threshold
        self._min_token_length = min_token_length

    def analyse_token(self, token: str) -> EntropyResult:
        """Calculate entropy for a single token."""
        ent = shannon_entropy(token)
        return EntropyResult(
            text_snippet=token[:80],
            entropy=round(ent, 4),
            is_suspicious=ent >= self._threshold,
            threshold=self._threshold,
        )

    def analyse_text(self, text: str) -> list[EntropyResult]:
        """Extract tokens from *text* and return entropy results for suspicious ones."""
        results: list[EntropyResult] = []
        for match in _TOKEN_RE.finditer(text):
            token = match.group()
            if len(token) < self._min_token_length:
                continue
            result = self.analyse_token(token)
            if result.is_suspicious:
                results.append(result)
        return results

    def scan(self, text: str) -> list[ScanFinding]:
        """Scan *text* and return ScanFindings for high-entropy tokens.

        Used as a layer in the URL scanner pipeline.
        """
        findings: list[ScanFinding] = []
        for result in self.analyse_text(text):
            severity = (
                ScanSeverity.HIGH
                if result.entropy >= self._high_threshold
                else ScanSeverity.MEDIUM
            )
            findings.append(
                ScanFinding(
                    rule_id="ENTROPY-001",
                    scanner="EntropyAnalyzer",
                    severity=severity,
                    description=f"High-entropy token detected (entropy={result.entropy:.2f})",
                    matched_text=result.text_snippet,
                    mitre_technique_id="T1552.001",
                    metadata={"entropy": result.entropy, "threshold": result.threshold},
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

entropy_analyzer = EntropyAnalyzer()
