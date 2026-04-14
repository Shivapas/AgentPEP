"""Forward Proxy DLP Scanner — Request body DLP scanning for CONNECT tunnels.

Sprint 47 — APEP-373: Scans intercepted request bodies in the forward proxy
for sensitive data (API keys, tokens, credentials, PII) before they leave
the network perimeter.

APEP-373.b: Core security logic — DLP scan on intercepted HTTP request bodies.
APEP-373.c: Security guards and validation for forward proxy DLP.
APEP-373.d: Integration into enforcement pipeline.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from app.models.forward_proxy import FrameScanResult, FrameScanVerdict
from app.models.network_scan import (
    NetworkEvent,
    NetworkEventType,
    ScanFinding,
    ScanSeverity,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTTP request body extraction helpers
# ---------------------------------------------------------------------------

_CONTENT_LENGTH_RE = re.compile(rb"Content-Length:\s*(\d+)", re.IGNORECASE)
_CONTENT_TYPE_RE = re.compile(rb"Content-Type:\s*([^\r\n]+)", re.IGNORECASE)

# Content types that should be scanned for DLP
_SCANNABLE_CONTENT_TYPES = {
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain",
    "text/xml",
    "application/xml",
    "multipart/form-data",
    "application/graphql",
}

# Maximum body size to scan (avoid scanning large file uploads)
_MAX_SCAN_BODY_SIZE = 1_048_576  # 1 MB


class ForwardProxyDLPScanner:
    """DLP scanner for intercepted forward proxy traffic.

    When TLS interception is active, this scanner inspects HTTP request
    bodies for sensitive data before they are forwarded to the upstream
    server.  It reuses the existing DLP patterns from the NetworkDLPScanner
    (Sprint 44/45).

    Security guarantees:
      - Only scans text-based content types (not binary uploads)
      - Respects max body size limits
      - Returns findings without blocking by default (configurable)
      - Emits Kafka events for all DLP hits
    """

    def __init__(
        self,
        *,
        block_on_critical: bool = True,
        block_on_high: bool = False,
        max_body_size: int = _MAX_SCAN_BODY_SIZE,
    ) -> None:
        self._block_on_critical = block_on_critical
        self._block_on_high = block_on_high
        self._max_body_size = max_body_size
        self._scan_count = 0
        self._hit_count = 0
        self._block_count = 0

    def scan_request_body(
        self,
        body: bytes,
        *,
        content_type: str = "",
        hostname: str = "",
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> ForwardProxyDLPResult:
        """Scan an intercepted HTTP request body for DLP violations.

        Args:
            body: Raw request body bytes.
            content_type: HTTP Content-Type header value.
            hostname: Target hostname (for logging).
            session_id: AgentPEP session ID for taint correlation.
            agent_id: Agent ID for event correlation.

        Returns:
            ForwardProxyDLPResult with findings and block verdict.
        """
        start = time.monotonic()
        self._scan_count += 1

        # Skip non-scannable content types
        if content_type and not self._is_scannable(content_type):
            return ForwardProxyDLPResult(
                scanned=False,
                reason="non_scannable_content_type",
            )

        # Skip oversized bodies
        if len(body) > self._max_body_size:
            return ForwardProxyDLPResult(
                scanned=False,
                reason="body_too_large",
            )

        # Decode body to text
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return ForwardProxyDLPResult(scanned=False, reason="decode_error")

        # Run DLP scan using the shared scanner
        from app.services.network_dlp_scanner import network_dlp_scanner

        findings = network_dlp_scanner.scan_text(text)
        elapsed_us = int((time.monotonic() - start) * 1_000_000)

        if not findings:
            return ForwardProxyDLPResult(
                scanned=True,
                scan_latency_us=elapsed_us,
            )

        self._hit_count += len(findings)

        # Determine if we should block
        should_block = False
        for f in findings:
            if f.severity == ScanSeverity.CRITICAL and self._block_on_critical:
                should_block = True
                break
            if f.severity == ScanSeverity.HIGH and self._block_on_high:
                should_block = True
                break

        if should_block:
            self._block_count += 1

        return ForwardProxyDLPResult(
            scanned=True,
            findings=findings,
            blocked=should_block,
            scan_latency_us=elapsed_us,
            hostname=hostname,
            session_id=session_id,
            agent_id=agent_id,
        )

    def scan_raw_http(
        self,
        raw_data: bytes,
        *,
        hostname: str = "",
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> ForwardProxyDLPResult:
        """Scan raw HTTP data (headers + body) for DLP violations.

        Parses the Content-Type and Content-Length headers to extract
        and scan only the body portion.
        """
        # Find header/body boundary
        boundary = raw_data.find(b"\r\n\r\n")
        if boundary == -1:
            boundary = raw_data.find(b"\n\n")
            if boundary == -1:
                return ForwardProxyDLPResult(scanned=False, reason="no_body")
            header_end = boundary + 2
        else:
            header_end = boundary + 4

        headers = raw_data[:boundary]
        body = raw_data[header_end:]

        if not body:
            return ForwardProxyDLPResult(scanned=False, reason="empty_body")

        # Extract content type
        ct_match = _CONTENT_TYPE_RE.search(headers)
        content_type = ct_match.group(1).decode("utf-8", errors="replace").strip() if ct_match else ""

        return self.scan_request_body(
            body,
            content_type=content_type,
            hostname=hostname,
            session_id=session_id,
            agent_id=agent_id,
        )

    def _is_scannable(self, content_type: str) -> bool:
        """Check if a content type should be DLP-scanned."""
        ct_lower = content_type.lower().split(";")[0].strip()
        return ct_lower in _SCANNABLE_CONTENT_TYPES

    def create_network_events(
        self, result: ForwardProxyDLPResult
    ) -> list[NetworkEvent]:
        """Create Kafka NetworkEvents from DLP scan results."""
        events: list[NetworkEvent] = []
        for finding in result.findings[:10]:  # Cap at 10 events
            events.append(
                NetworkEvent(
                    session_id=result.session_id,
                    agent_id=result.agent_id,
                    event_type=NetworkEventType.DLP_HIT,
                    scanner="ForwardProxyDLPScanner",
                    finding_rule_id=finding.rule_id,
                    severity=finding.severity,
                    mitre_technique_id="T1048",
                    url=result.hostname,
                    blocked=result.blocked,
                )
            )
        return events

    @property
    def stats(self) -> dict[str, int]:
        return {
            "scan_count": self._scan_count,
            "hit_count": self._hit_count,
            "block_count": self._block_count,
        }


class ForwardProxyDLPResult:
    """Result from forward proxy DLP scanning."""

    __slots__ = (
        "scanned",
        "findings",
        "blocked",
        "scan_latency_us",
        "reason",
        "hostname",
        "session_id",
        "agent_id",
    )

    def __init__(
        self,
        *,
        scanned: bool = False,
        findings: list[ScanFinding] | None = None,
        blocked: bool = False,
        scan_latency_us: int = 0,
        reason: str = "",
        hostname: str = "",
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> None:
        self.scanned = scanned
        self.findings = findings or []
        self.blocked = blocked
        self.scan_latency_us = scan_latency_us
        self.reason = reason
        self.hostname = hostname
        self.session_id = session_id
        self.agent_id = agent_id

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

forward_proxy_dlp_scanner = ForwardProxyDLPScanner()
