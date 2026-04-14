"""WebSocket Frame DLP + Injection Scanner.

Sprint 47 — APEP-378: Scans individual WebSocket frames for DLP violations
(data exfiltration) and injection attacks (prompt injection, command injection).

APEP-378.b: Core security logic — frame scanning with DLP and injection patterns.
APEP-378.c: Security guards and validation for frame scanning.
APEP-378.d: Integration into enforcement pipeline via WebSocket proxy.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from app.models.forward_proxy import (
    FrameScanResult,
    FrameScanVerdict,
    WebSocketFrameType,
)
from app.models.network_scan import (
    NetworkEvent,
    NetworkEventType,
    ScanFinding,
    ScanSeverity,
)

logger = logging.getLogger(__name__)

# Minimum frame size to bother scanning (skip tiny control frames)
_MIN_SCAN_SIZE = 8

# Maximum frame data to scan (truncate very large frames)
_MAX_SCAN_SIZE = 1_048_576  # 1 MB


class WebSocketFrameScanner:
    """Scans WebSocket frames for DLP violations and injection attacks.

    Combines two scanning passes:
      1. DLP scan — detects API keys, tokens, credentials, PII being
         exfiltrated through WebSocket frames (uses NetworkDLPScanner).
      2. Injection scan — detects prompt injection, command injection,
         and other attack patterns in inbound frames (uses
         InjectionSignatureLibrary).

    Security guarantees:
      - Outbound frames are scanned for DLP (data exfiltration prevention).
      - Inbound frames are scanned for injection (attack prevention).
      - Both directions can optionally scan for both categories.
      - Findings are emitted as Kafka events for audit trail.

    Thread-safe: relies on immutable compiled patterns.
    """

    def __init__(
        self,
        *,
        block_on_dlp_critical: bool = True,
        block_on_dlp_high: bool = False,
        block_on_injection: bool = True,
        scan_inbound_dlp: bool = True,
        scan_outbound_injection: bool = True,
    ) -> None:
        self._block_on_dlp_critical = block_on_dlp_critical
        self._block_on_dlp_high = block_on_dlp_high
        self._block_on_injection = block_on_injection
        self._scan_inbound_dlp = scan_inbound_dlp
        self._scan_outbound_injection = scan_outbound_injection
        self._scan_count = 0
        self._dlp_hit_count = 0
        self._injection_hit_count = 0
        self._block_count = 0

    def scan_frame(
        self,
        data: str,
        frame_type: WebSocketFrameType = WebSocketFrameType.TEXT,
        direction: str = "outbound",
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> FrameScanResult:
        """Scan a single WebSocket frame for security violations.

        Args:
            data: Frame payload (text or decoded binary).
            frame_type: Type of WebSocket frame.
            direction: "inbound" (from upstream) or "outbound" (from client).
            session_id: AgentPEP session ID for correlation.
            agent_id: Agent ID for correlation.

        Returns:
            FrameScanResult with verdict and findings.
        """
        start = time.monotonic()
        self._scan_count += 1

        # Skip non-text frames and tiny frames
        if frame_type not in (WebSocketFrameType.TEXT, WebSocketFrameType.BINARY):
            return FrameScanResult(frame_type=frame_type)

        if len(data) < _MIN_SCAN_SIZE:
            return FrameScanResult(frame_type=frame_type)

        # Truncate very large frames
        scan_data = data[:_MAX_SCAN_SIZE]

        dlp_findings: list[dict[str, Any]] = []
        injection_findings: list[dict[str, Any]] = []
        verdict = FrameScanVerdict.ALLOW

        # 1. DLP scan (outbound by default; optionally inbound too)
        if direction == "outbound" or self._scan_inbound_dlp:
            dlp_findings = self._scan_dlp(scan_data)
            if dlp_findings:
                self._dlp_hit_count += len(dlp_findings)
                # Determine if we should block based on severity
                for f in dlp_findings:
                    severity = f.get("severity", "")
                    if severity == "CRITICAL" and self._block_on_dlp_critical:
                        verdict = FrameScanVerdict.BLOCK
                        break
                    if severity == "HIGH" and self._block_on_dlp_high:
                        verdict = FrameScanVerdict.BLOCK
                        break

        # 2. Injection scan (inbound by default; optionally outbound too)
        if direction == "inbound" or self._scan_outbound_injection:
            injection_findings = self._scan_injection(scan_data)
            if injection_findings:
                self._injection_hit_count += len(injection_findings)
                if self._block_on_injection:
                    verdict = FrameScanVerdict.BLOCK

        if verdict == FrameScanVerdict.BLOCK:
            self._block_count += 1

        scan_latency_us = int((time.monotonic() - start) * 1_000_000)

        return FrameScanResult(
            verdict=verdict,
            dlp_findings=dlp_findings,
            injection_findings=injection_findings,
            frame_type=frame_type,
            scan_latency_us=scan_latency_us,
        )

    def _scan_dlp(self, text: str) -> list[dict[str, Any]]:
        """Run DLP patterns against text, return serializable findings."""
        try:
            from app.services.network_dlp_scanner import network_dlp_scanner

            findings = network_dlp_scanner.scan_text(text)
            return [
                {
                    "rule_id": f.rule_id,
                    "scanner": f.scanner,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "description": f.description,
                    "matched_text": f.matched_text[:100],
                    "mitre_technique_id": f.mitre_technique_id,
                }
                for f in findings
                if f.rule_id.startswith("DLP-") or f.rule_id.startswith("ENTROPY-")
            ]
        except Exception:
            logger.exception("DLP scan error in frame scanner")
            return []

    def _scan_injection(self, text: str) -> list[dict[str, Any]]:
        """Run injection signature patterns against text."""
        try:
            from app.services.injection_signatures import injection_library

            matches = injection_library.check(text)
            return [
                {
                    "signature_id": m.signature_id,
                    "category": m.category,
                    "severity": m.severity,
                    "description": m.description,
                    "mitre_technique_id": getattr(m, "mitre_technique_id", ""),
                }
                for m in matches
                if not m.signature_id.startswith("DLP-")  # Avoid double-counting DLP
            ]
        except Exception:
            logger.exception("Injection scan error in frame scanner")
            return []

    def create_network_events(
        self,
        result: FrameScanResult,
        *,
        session_id: str | None = None,
        agent_id: str | None = None,
        direction: str = "outbound",
    ) -> list[NetworkEvent]:
        """Create Kafka NetworkEvents from frame scan results."""
        events: list[NetworkEvent] = []

        for finding in result.dlp_findings[:5]:
            events.append(
                NetworkEvent(
                    session_id=session_id,
                    agent_id=agent_id,
                    event_type=NetworkEventType.DLP_HIT,
                    scanner="WebSocketFrameScanner",
                    finding_rule_id=finding.get("rule_id", "WS-DLP"),
                    severity=ScanSeverity.HIGH,
                    mitre_technique_id="T1048",
                    blocked=result.verdict == FrameScanVerdict.BLOCK,
                )
            )

        for finding in result.injection_findings[:5]:
            events.append(
                NetworkEvent(
                    session_id=session_id,
                    agent_id=agent_id,
                    event_type=NetworkEventType.INJECTION_DETECTED,
                    scanner="WebSocketFrameScanner",
                    finding_rule_id=finding.get("signature_id", "WS-INJ"),
                    severity=ScanSeverity.HIGH,
                    mitre_technique_id="T1059",
                    blocked=result.verdict == FrameScanVerdict.BLOCK,
                )
            )

        return events

    @property
    def stats(self) -> dict[str, int]:
        return {
            "scan_count": self._scan_count,
            "dlp_hit_count": self._dlp_hit_count,
            "injection_hit_count": self._injection_hit_count,
            "block_count": self._block_count,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

websocket_frame_scanner = WebSocketFrameScanner()
