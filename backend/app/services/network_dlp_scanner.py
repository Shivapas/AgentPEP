"""Network DLP Scanner — Data Loss Prevention scanning for tool arguments.

Sprint 44 — APEP-348: Scans text and tool arguments for sensitive data leakage
using the 46 DLP patterns from injection_signatures.py, plus entropy analysis.
Integrates with the PolicyEvaluator pipeline as a pre-evaluation stage.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from app.models.network_scan import (
    NetworkEvent,
    NetworkEventType,
    ScanFinding,
    ScanSeverity,
)
from app.services.entropy_analyzer import entropy_analyzer
from app.services.injection_signatures import InjectionSignatureLibrary, MatchedSignature, injection_library

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DLP category prefixes (match the DLP-xxx patterns added in Sprint 44)
# ---------------------------------------------------------------------------

_DLP_CATEGORIES = {
    "dlp_api_key",
    "dlp_token",
    "dlp_credential",
    "dlp_cloud_token",
    "dlp_secret",
}


# ---------------------------------------------------------------------------
# NetworkDLPScanner
# ---------------------------------------------------------------------------


class NetworkDLPScanner:
    """Scans text and tool arguments for data loss prevention violations.

    Uses the shared injection_signatures library (DLP-001 through DLP-046)
    and the entropy analyzer to detect secrets, API keys, tokens, and
    credentials in tool call arguments.

    Thread-safe: relies on immutable compiled signatures.
    """

    def __init__(
        self,
        library: InjectionSignatureLibrary | None = None,
        entropy_threshold: float = 4.5,
    ) -> None:
        self._library = library or injection_library
        self._entropy_threshold = entropy_threshold

    def _get_dlp_signatures(self) -> list[Any]:
        """Return only DLP-category signatures from the library."""
        sigs = []
        for cat in _DLP_CATEGORIES:
            sigs.extend(self._library.get_by_category(cat))
        return sigs

    def scan_text(self, text: str) -> list[ScanFinding]:
        """Scan a text string for DLP pattern matches and high-entropy tokens.

        Returns a list of ScanFinding objects.
        """
        findings: list[ScanFinding] = []

        # 1. Pattern-based DLP detection
        matches = self._library.check(text)
        for match in matches:
            if not match.signature_id.startswith("DLP-"):
                continue
            findings.append(
                ScanFinding(
                    rule_id=match.signature_id,
                    scanner="NetworkDLPScanner",
                    severity=ScanSeverity(match.severity),
                    description=match.description,
                    matched_text=text[:200] if len(text) > 200 else text,
                    mitre_technique_id="T1552.001",
                )
            )

        # 2. Entropy-based detection
        entropy_findings = entropy_analyzer.scan(text)
        findings.extend(entropy_findings)

        return findings

    def scan_tool_args(
        self,
        tool_args: dict[str, Any],
        *,
        tool_name: str = "",
    ) -> list[ScanFinding]:
        """Scan tool call arguments (key-value pairs) for DLP violations.

        Recursively serialises argument values and scans each for secrets.
        """
        findings: list[ScanFinding] = []

        for key, value in tool_args.items():
            text = self._serialize_value(value)
            if not text:
                continue

            arg_findings = self.scan_text(text)
            for f in arg_findings:
                f.metadata["tool_name"] = tool_name
                f.metadata["arg_key"] = key
            findings.extend(arg_findings)

        return findings

    def scan_url(self, url: str) -> list[ScanFinding]:
        """Scan a URL string for embedded credentials or tokens."""
        return self.scan_text(url)

    def _serialize_value(self, value: Any) -> str:
        """Serialise a value to a scannable string."""
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float, bool)):
            return str(value)
        if isinstance(value, dict):
            return json.dumps(value, default=str)
        if isinstance(value, (list, tuple)):
            return json.dumps(value, default=str)
        return str(value) if value is not None else ""

    def has_dlp_findings(self, findings: list[ScanFinding]) -> bool:
        """Return True if any findings are DLP-related."""
        return any(f.rule_id.startswith("DLP-") or f.rule_id == "ENTROPY-001" for f in findings)

    def max_severity(self, findings: list[ScanFinding]) -> ScanSeverity | None:
        """Return the highest severity from a list of findings."""
        if not findings:
            return None
        severity_order = {
            ScanSeverity.CRITICAL: 4,
            ScanSeverity.HIGH: 3,
            ScanSeverity.MEDIUM: 2,
            ScanSeverity.LOW: 1,
            ScanSeverity.INFO: 0,
        }
        return max(findings, key=lambda f: severity_order.get(f.severity, 0)).severity

    def create_network_event(
        self,
        finding: ScanFinding,
        *,
        session_id: str | None = None,
        agent_id: str | None = None,
        url: str | None = None,
        blocked: bool = False,
    ) -> NetworkEvent:
        """Create a Kafka NetworkEvent from a DLP finding."""
        return NetworkEvent(
            session_id=session_id,
            agent_id=agent_id,
            event_type=NetworkEventType.DLP_HIT,
            scanner=finding.scanner,
            finding_rule_id=finding.rule_id,
            severity=finding.severity,
            mitre_technique_id=finding.mitre_technique_id,
            url=url,
            blocked=blocked,
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

network_dlp_scanner = NetworkDLPScanner()
