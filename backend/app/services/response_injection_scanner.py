"""ResponseInjectionScanner — multi-pass injection detection for fetched responses.

Sprint 46 — APEP-366: Scans response bodies through multiple detection passes
after Unicode normalization. Detects prompt injection, role hijacking, system
escape attempts, and encoding-based evasion in fetched content.

Detection passes:
  1. RAW_SIGNATURE — Run injection signature library on raw text
  2. NORMALIZED_SIGNATURE — Run injection signatures on normalized text
  3. STRUCTURAL_PATTERN — Detect structural prompt injection patterns
  4. ENCODING_PROBE — Detect encoding-based evasion (base64, hex, etc.)
  5. SEMANTIC_HEURISTIC — Heuristic detection of instruction injection
  6. STATISTICAL_ANOMALY — Statistical anomaly detection (entropy, repetition)

Thread-safe: relies on compiled regex patterns and the ResponseNormalizer.
"""

from __future__ import annotations

import base64
import logging
import math
import re
import time
from collections import Counter

from app.models.fetch_proxy import (
    InjectionFinding,
    InjectionScanPassType,
    InjectionScanResult,
)
from app.services.injection_signatures import MatchedSignature, injection_library
from app.services.response_normalizer import response_normalizer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pass 3: Structural patterns (prompt injection structure detection)
# ---------------------------------------------------------------------------

_STRUCTURAL_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "STRUCT-001",
        re.compile(
            r"(?i)<\s*system\s*>.*?<\s*/\s*system\s*>",
            re.DOTALL,
        ),
        "CRITICAL",
        "Embedded <system> tags in response body",
    ),
    (
        "STRUCT-002",
        re.compile(
            r"(?i)\[\s*INST\s*\].*?\[\s*/\s*INST\s*\]",
            re.DOTALL,
        ),
        "CRITICAL",
        "Embedded [INST] instruction blocks in response body",
    ),
    (
        "STRUCT-003",
        re.compile(
            r"(?i)```\s*system\s*\n.*?```",
            re.DOTALL,
        ),
        "HIGH",
        "System instruction in fenced code block",
    ),
    (
        "STRUCT-004",
        re.compile(
            r"(?i)###\s*(system\s+prompt|instructions|directive)",
        ),
        "HIGH",
        "Markdown heading mimicking system prompt section",
    ),
    (
        "STRUCT-005",
        re.compile(
            r"(?i)<\|im_start\|>.*?<\|im_end\|>",
            re.DOTALL,
        ),
        "CRITICAL",
        "ChatML-style injection tokens in response",
    ),
    (
        "STRUCT-006",
        re.compile(
            r"(?i)(human|user|assistant)\s*:\s*\n",
        ),
        "MEDIUM",
        "Role-label pattern attempting to inject conversation turns",
    ),
    (
        "STRUCT-007",
        re.compile(
            r"(?i)<\s*tool_call\s*>|<\s*function_call\s*>",
        ),
        "CRITICAL",
        "Embedded tool/function call tags in response",
    ),
]

# ---------------------------------------------------------------------------
# Pass 4: Encoding probe patterns
# ---------------------------------------------------------------------------

_BASE64_INSTRUCTION_RE = re.compile(
    r"[A-Za-z0-9+/]{20,}={0,2}",
)

_HEX_ENCODED_RE = re.compile(
    r"(?:0x[0-9a-fA-F]{2}\s*){8,}|(?:\\x[0-9a-fA-F]{2}){8,}",
)

_URL_ENCODED_INSTRUCTION_RE = re.compile(
    r"(?:%[0-9a-fA-F]{2}){10,}",
)

# Known injection phrases to look for in decoded content
_DECODED_INJECTION_PHRASES = [
    "ignore all previous",
    "ignore previous instructions",
    "disregard all previous",
    "new instructions:",
    "system prompt:",
    "you are now",
    "override previous",
    "forget your instructions",
]

# ---------------------------------------------------------------------------
# Pass 5: Semantic heuristic patterns
# ---------------------------------------------------------------------------

_SEMANTIC_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "SEM-001",
        re.compile(
            r"(?i)(?:you\s+(?:are|must|should|will)\s+now\s+(?:act|behave|respond|pretend|be)\s+as)",
        ),
        "HIGH",
        "Instruction to change model persona/behavior",
    ),
    (
        "SEM-002",
        re.compile(
            r"(?i)(?:from\s+now\s+on|starting\s+now|henceforth),?\s+(?:you|your|the\s+(?:ai|assistant|model))",
        ),
        "HIGH",
        "Temporal instruction override pattern",
    ),
    (
        "SEM-003",
        re.compile(
            r"(?i)(?:do\s+not|don'?t|never)\s+(?:mention|reveal|disclose|share|tell)\s+(?:this|the|your|these)\s+(?:instructions|prompt|rules|system)",
        ),
        "MEDIUM",
        "Instruction to hide system prompt",
    ),
    (
        "SEM-004",
        re.compile(
            r"(?i)(?:execute|run|perform|call)\s+(?:the\s+following\s+)?(?:command|function|tool|code)",
        ),
        "HIGH",
        "Instruction to execute commands or call tools",
    ),
    (
        "SEM-005",
        re.compile(
            r"(?i)(?:output|print|return|respond\s+with)\s+(?:only|exactly|just)\s+(?:the|this|your)",
        ),
        "MEDIUM",
        "Attempt to control output format for exfiltration",
    ),
    (
        "SEM-006",
        re.compile(
            r"(?i)(?:when\s+(?:the\s+)?user|if\s+(?:the\s+)?user|whenever)\s+(?:asks?|says?|types?|sends?)\s+(?:about|for|the)",
        ),
        "MEDIUM",
        "Conditional behavior injection",
    ),
]


# ---------------------------------------------------------------------------
# ResponseInjectionScanner
# ---------------------------------------------------------------------------


class ResponseInjectionScanner:
    """Multi-pass injection detection scanner for fetched response bodies.

    Runs 6 detection passes on both raw and normalized text, aggregating
    findings with severity levels and confidence scores.

    Thread-safe: all operations are pure functions on compiled patterns.
    """

    _SEVERITY_ORDER = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }

    def scan(self, raw_text: str, normalized_text: str | None = None) -> InjectionScanResult:
        """Scan response text through all 6 detection passes.

        Args:
            raw_text: Original response body text.
            normalized_text: Pre-normalized text (if None, normalizer is run).

        Returns:
            InjectionScanResult with all findings aggregated.
        """
        start = time.monotonic()

        if not raw_text:
            return InjectionScanResult(
                injection_detected=False,
                findings=[],
                passes_run=[],
                total_findings=0,
                highest_severity="INFO",
                scan_latency_us=0,
            )

        if normalized_text is None:
            norm_result = response_normalizer.normalize(raw_text)
            normalized_text = norm_result.normalized_text

        findings: list[InjectionFinding] = []
        passes_run: list[InjectionScanPassType] = []

        # Pass 1: RAW_SIGNATURE
        p1 = self._pass_raw_signature(raw_text)
        findings.extend(p1)
        passes_run.append(InjectionScanPassType.RAW_SIGNATURE)

        # Pass 2: NORMALIZED_SIGNATURE
        p2 = self._pass_normalized_signature(normalized_text)
        findings.extend(p2)
        passes_run.append(InjectionScanPassType.NORMALIZED_SIGNATURE)

        # Pass 3: STRUCTURAL_PATTERN
        p3 = self._pass_structural(normalized_text)
        findings.extend(p3)
        passes_run.append(InjectionScanPassType.STRUCTURAL_PATTERN)

        # Pass 4: ENCODING_PROBE
        p4 = self._pass_encoding_probe(raw_text)
        findings.extend(p4)
        passes_run.append(InjectionScanPassType.ENCODING_PROBE)

        # Pass 5: SEMANTIC_HEURISTIC
        p5 = self._pass_semantic(normalized_text)
        findings.extend(p5)
        passes_run.append(InjectionScanPassType.SEMANTIC_HEURISTIC)

        # Pass 6: STATISTICAL_ANOMALY
        p6 = self._pass_statistical(raw_text)
        findings.extend(p6)
        passes_run.append(InjectionScanPassType.STATISTICAL_ANOMALY)

        # Deduplicate by signature_id (keep highest confidence)
        findings = self._deduplicate(findings)

        highest = self._highest_severity(findings)
        elapsed_us = int((time.monotonic() - start) * 1_000_000)

        return InjectionScanResult(
            injection_detected=len(findings) > 0,
            findings=findings,
            passes_run=passes_run,
            total_findings=len(findings),
            highest_severity=highest,
            scan_latency_us=elapsed_us,
        )

    # --- Pass implementations ---

    def _pass_raw_signature(self, text: str) -> list[InjectionFinding]:
        """Pass 1: Run injection signature library on raw text."""
        matches = injection_library.check(text)
        return [self._match_to_finding(m, InjectionScanPassType.RAW_SIGNATURE) for m in matches]

    def _pass_normalized_signature(self, text: str) -> list[InjectionFinding]:
        """Pass 2: Run injection signatures on normalized text."""
        matches = injection_library.check(text)
        return [
            self._match_to_finding(m, InjectionScanPassType.NORMALIZED_SIGNATURE, confidence=0.95)
            for m in matches
        ]

    def _pass_structural(self, text: str) -> list[InjectionFinding]:
        """Pass 3: Detect structural prompt injection patterns."""
        findings: list[InjectionFinding] = []
        for sig_id, pattern, severity, description in _STRUCTURAL_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    InjectionFinding(
                        pass_type=InjectionScanPassType.STRUCTURAL_PATTERN,
                        signature_id=sig_id,
                        severity=severity,
                        description=description,
                        matched_text=match.group()[:200],
                        confidence=0.9,
                        mitre_technique_id="T1059.001",
                    )
                )
        return findings

    def _pass_encoding_probe(self, text: str) -> list[InjectionFinding]:
        """Pass 4: Detect encoding-based evasion (base64, hex, URL-encoded)."""
        findings: list[InjectionFinding] = []

        # Check base64 segments
        for match in _BASE64_INSTRUCTION_RE.finditer(text):
            candidate = match.group()
            try:
                decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
                lower = decoded.lower()
                for phrase in _DECODED_INJECTION_PHRASES:
                    if phrase in lower:
                        findings.append(
                            InjectionFinding(
                                pass_type=InjectionScanPassType.ENCODING_PROBE,
                                signature_id="ENC-B64-001",
                                severity="CRITICAL",
                                description=f"Base64-encoded injection: '{phrase}'",
                                matched_text=candidate[:200],
                                confidence=0.85,
                                mitre_technique_id="T1027",
                            )
                        )
                        break
            except Exception:
                continue

        # Check hex-encoded segments
        for match in _HEX_ENCODED_RE.finditer(text):
            candidate = match.group()
            try:
                hex_str = re.sub(r"0x|\\x|\s", "", candidate)
                decoded = bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
                lower = decoded.lower()
                for phrase in _DECODED_INJECTION_PHRASES:
                    if phrase in lower:
                        findings.append(
                            InjectionFinding(
                                pass_type=InjectionScanPassType.ENCODING_PROBE,
                                signature_id="ENC-HEX-001",
                                severity="HIGH",
                                description=f"Hex-encoded injection: '{phrase}'",
                                matched_text=candidate[:200],
                                confidence=0.80,
                                mitre_technique_id="T1027",
                            )
                        )
                        break
            except Exception:
                continue

        # Check URL-encoded segments
        for match in _URL_ENCODED_INSTRUCTION_RE.finditer(text):
            candidate = match.group()
            try:
                from urllib.parse import unquote
                decoded = unquote(candidate)
                lower = decoded.lower()
                for phrase in _DECODED_INJECTION_PHRASES:
                    if phrase in lower:
                        findings.append(
                            InjectionFinding(
                                pass_type=InjectionScanPassType.ENCODING_PROBE,
                                signature_id="ENC-URL-001",
                                severity="HIGH",
                                description=f"URL-encoded injection: '{phrase}'",
                                matched_text=candidate[:200],
                                confidence=0.80,
                                mitre_technique_id="T1027",
                            )
                        )
                        break
            except Exception:
                continue

        return findings

    def _pass_semantic(self, text: str) -> list[InjectionFinding]:
        """Pass 5: Heuristic detection of instruction injection."""
        findings: list[InjectionFinding] = []
        for sig_id, pattern, severity, description in _SEMANTIC_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    InjectionFinding(
                        pass_type=InjectionScanPassType.SEMANTIC_HEURISTIC,
                        signature_id=sig_id,
                        severity=severity,
                        description=description,
                        matched_text=match.group()[:200],
                        confidence=0.75,
                        mitre_technique_id="T1059.001",
                    )
                )
        return findings

    def _pass_statistical(self, text: str) -> list[InjectionFinding]:
        """Pass 6: Statistical anomaly detection."""
        findings: list[InjectionFinding] = []

        if len(text) < 50:
            return findings

        # High ratio of non-ASCII to ASCII characters (possible evasion)
        ascii_count = sum(1 for c in text if ord(c) < 128)
        total = len(text)
        non_ascii_ratio = 1.0 - (ascii_count / total) if total > 0 else 0.0
        if non_ascii_ratio > 0.5 and total > 100:
            findings.append(
                InjectionFinding(
                    pass_type=InjectionScanPassType.STATISTICAL_ANOMALY,
                    signature_id="STAT-001",
                    severity="MEDIUM",
                    description=f"High non-ASCII ratio ({non_ascii_ratio:.1%}) may indicate Unicode evasion",
                    matched_text=text[:100],
                    confidence=0.60,
                    mitre_technique_id="T1027",
                )
            )

        # Repetitive character patterns (possible padding/evasion)
        char_counts = Counter(text)
        if char_counts:
            most_common_char, most_common_count = char_counts.most_common(1)[0]
            repetition_ratio = most_common_count / total
            if (
                repetition_ratio > 0.3
                and total > 200
                and most_common_char not in (" ", "\n", "\t", ".", ",")
            ):
                findings.append(
                    InjectionFinding(
                        pass_type=InjectionScanPassType.STATISTICAL_ANOMALY,
                        signature_id="STAT-002",
                        severity="LOW",
                        description=(
                            f"Suspicious character repetition: "
                            f"'{repr(most_common_char)}' appears {repetition_ratio:.1%} of text"
                        ),
                        matched_text=text[:100],
                        confidence=0.50,
                        mitre_technique_id="T1027",
                    )
                )

        # Shannon entropy check on text segments
        entropy = self._shannon_entropy(text[:1000])
        if entropy < 2.0 and total > 200:
            findings.append(
                InjectionFinding(
                    pass_type=InjectionScanPassType.STATISTICAL_ANOMALY,
                    signature_id="STAT-003",
                    severity="LOW",
                    description=f"Abnormally low entropy ({entropy:.2f}) may indicate crafted payload",
                    matched_text=text[:100],
                    confidence=0.45,
                    mitre_technique_id="T1027",
                )
            )

        return findings

    # --- Helpers ---

    def _match_to_finding(
        self,
        match: MatchedSignature,
        pass_type: InjectionScanPassType,
        confidence: float = 1.0,
    ) -> InjectionFinding:
        """Convert an injection library MatchedSignature to an InjectionFinding."""
        return InjectionFinding(
            pass_type=pass_type,
            signature_id=match.signature_id,
            severity=match.severity,
            description=match.description,
            matched_text="",
            confidence=confidence,
            mitre_technique_id="T1059.001",
        )

    def _deduplicate(self, findings: list[InjectionFinding]) -> list[InjectionFinding]:
        """Deduplicate findings by signature_id, keeping highest confidence."""
        seen: dict[str, InjectionFinding] = {}
        for f in findings:
            key = f.signature_id
            if key not in seen or f.confidence > seen[key].confidence:
                seen[key] = f
        return list(seen.values())

    def _highest_severity(self, findings: list[InjectionFinding]) -> str:
        """Return the highest severity string from findings."""
        if not findings:
            return "INFO"
        return max(
            findings,
            key=lambda f: self._SEVERITY_ORDER.get(f.severity, 0),
        ).severity

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Compute Shannon entropy of a text string."""
        if not text:
            return 0.0
        freq = Counter(text)
        total = len(text)
        return -sum(
            (count / total) * math.log2(count / total)
            for count in freq.values()
            if count > 0
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

response_injection_scanner = ResponseInjectionScanner()
