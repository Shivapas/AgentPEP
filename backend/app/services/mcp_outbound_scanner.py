"""MCP outbound DLP scanner — bidirectional DLP scanning for MCP proxy.

Sprint 48 — APEP-380: Scans outbound MCP tool call arguments for DLP
violations (secrets, API keys, credentials, PII) before they are sent to
the upstream MCP server. Also scans inbound MCP server responses.

Integrates with the existing NetworkDLPScanner and injection signature
library from Sprint 44/45.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from app.models.mcp_security import (
    MCPDLPAction,
    MCPDLPFinding,
    MCPOutboundScanResult,
    MCPScanDirection,
)
from app.models.network_scan import ScanSeverity
from app.services.injection_signatures import injection_library
from app.services.network_dlp_scanner import network_dlp_scanner

logger = logging.getLogger(__name__)


class MCPOutboundScanner:
    """Scans outbound MCP tool call arguments for DLP violations.

    Uses the shared NetworkDLPScanner to detect secrets, API keys, tokens,
    and credentials in tool call arguments before they are sent upstream.

    Thread-safe: delegates to immutable compiled signatures.
    """

    def __init__(
        self,
        *,
        block_on_critical: bool = True,
        block_on_high: bool = False,
    ) -> None:
        self._block_on_critical = block_on_critical
        self._block_on_high = block_on_high

    def scan_outbound(
        self,
        *,
        tool_name: str,
        tool_args: dict[str, Any],
        session_id: str,
        agent_id: str,
    ) -> MCPOutboundScanResult:
        """Scan outbound tool call arguments for DLP violations.

        Returns an MCPOutboundScanResult with findings and block decision.
        """
        start_us = time.monotonic_ns() // 1000

        findings: list[MCPDLPFinding] = []

        # Scan each argument value
        for key, value in tool_args.items():
            text = self._serialize_value(value)
            if not text:
                continue

            scan_findings = network_dlp_scanner.scan_text(text)
            for f in scan_findings:
                findings.append(MCPDLPFinding(
                    rule_id=f.rule_id,
                    category=f.metadata.get("category", ""),
                    severity=f.severity.value if isinstance(f.severity, ScanSeverity) else str(f.severity),
                    description=f.description,
                    matched_field=key,
                    matched_text_snippet=f.matched_text[:100] if f.matched_text else "",
                    mitre_technique_id=f.mitre_technique_id,
                ))

        # Determine action
        blocked = False
        action = MCPDLPAction.LOG
        if findings:
            max_sev = self._max_severity(findings)
            if max_sev == "CRITICAL" and self._block_on_critical:
                blocked = True
                action = MCPDLPAction.BLOCK
            elif max_sev == "HIGH" and self._block_on_high:
                blocked = True
                action = MCPDLPAction.BLOCK
            elif max_sev in ("CRITICAL", "HIGH"):
                action = MCPDLPAction.ALERT

        latency_us = (time.monotonic_ns() // 1000) - start_us

        return MCPOutboundScanResult(
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            direction=MCPScanDirection.OUTBOUND,
            findings=findings,
            blocked=blocked,
            action_taken=action,
            latency_us=latency_us,
        )

    def scan_inbound(
        self,
        *,
        tool_name: str,
        response_data: Any,
        session_id: str,
        agent_id: str,
    ) -> MCPOutboundScanResult:
        """Scan inbound MCP server response data for DLP violations.

        Returns an MCPOutboundScanResult with INBOUND direction.
        """
        start_us = time.monotonic_ns() // 1000

        findings: list[MCPDLPFinding] = []
        text = self._serialize_value(response_data)

        if text:
            scan_findings = network_dlp_scanner.scan_text(text)
            for f in scan_findings:
                findings.append(MCPDLPFinding(
                    rule_id=f.rule_id,
                    category=f.metadata.get("category", ""),
                    severity=f.severity.value if isinstance(f.severity, ScanSeverity) else str(f.severity),
                    description=f.description,
                    matched_field="response",
                    matched_text_snippet=f.matched_text[:100] if f.matched_text else "",
                    mitre_technique_id=f.mitre_technique_id,
                ))

        blocked = False
        action = MCPDLPAction.LOG
        if findings:
            max_sev = self._max_severity(findings)
            if max_sev == "CRITICAL" and self._block_on_critical:
                blocked = True
                action = MCPDLPAction.BLOCK
            elif max_sev in ("CRITICAL", "HIGH"):
                action = MCPDLPAction.ALERT

        latency_us = (time.monotonic_ns() // 1000) - start_us

        return MCPOutboundScanResult(
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            direction=MCPScanDirection.INBOUND,
            findings=findings,
            blocked=blocked,
            action_taken=action,
            latency_us=latency_us,
        )

    def _serialize_value(self, value: Any) -> str:
        """Serialise a value to a scannable string."""
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float, bool)):
            return str(value)
        if isinstance(value, (dict, list, tuple)):
            return json.dumps(value, default=str)
        return str(value) if value is not None else ""

    @staticmethod
    def _max_severity(findings: list[MCPDLPFinding]) -> str:
        """Return the highest severity from a list of findings."""
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        if not findings:
            return "INFO"
        return max(findings, key=lambda f: order.get(f.severity, 0)).severity


# Module-level singleton
mcp_outbound_scanner = MCPOutboundScanner()
