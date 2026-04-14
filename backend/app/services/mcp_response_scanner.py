"""MCP response scanner — scan MCP server responses for injection and DLP.

Sprint 48 — APEP-381: Scans MCP server responses for prompt injection,
hidden instructions, and DLP violations. Integrates with the existing
ResponseInjectionScanner and NetworkDLPScanner from Sprint 44/46.

When injection is detected, the response is quarantined via the taint
graph and the session graph manager.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from app.models.mcp_security import (
    MCPDLPFinding,
    MCPInjectionFinding,
    MCPResponseScanResult,
    MCPScanDirection,
)
from app.models.network_scan import ScanSeverity
from app.services.injection_signatures import injection_library
from app.services.network_dlp_scanner import network_dlp_scanner

logger = logging.getLogger(__name__)


# Structural patterns that indicate prompt injection in MCP responses
_MCP_INJECTION_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        "MCP-INJ-001",
        r"(?i)<\s*system\s*>",
        "CRITICAL",
        "Embedded <system> tag in MCP response",
    ),
    (
        "MCP-INJ-002",
        r"(?i)\[\s*INST\s*\]",
        "CRITICAL",
        "Embedded [INST] block in MCP response",
    ),
    (
        "MCP-INJ-003",
        r"(?i)ignore\s+all\s+previous\s+instructions",
        "CRITICAL",
        "Prompt override attempt in MCP response",
    ),
    (
        "MCP-INJ-004",
        r"(?i)you\s+are\s+now\s+a",
        "HIGH",
        "Role hijacking attempt in MCP response",
    ),
    (
        "MCP-INJ-005",
        r"(?i)disregard\s+(all\s+)?previous\s+prompts?",
        "CRITICAL",
        "Prompt disregard attempt in MCP response",
    ),
    (
        "MCP-INJ-006",
        r"(?i)new\s+instructions\s*:",
        "HIGH",
        "New instructions injection in MCP response",
    ),
    (
        "MCP-INJ-007",
        r"(?i)do\s+not\s+follow\s+the\s+previous\s+instructions",
        "HIGH",
        "Instruction override in MCP response",
    ),
    (
        "MCP-INJ-008",
        r"(?i)override\s+previous\s+directives?",
        "HIGH",
        "Directive override in MCP response",
    ),
]


class MCPResponseScanner:
    """Scans MCP server responses for injection and DLP violations.

    Combines injection detection (prompt override, role hijack, structural
    patterns) with DLP scanning (secrets, tokens, credentials) on the
    response data returned by upstream MCP servers.

    Thread-safe: uses compiled regex and immutable signature library.
    """

    def __init__(self) -> None:
        import re

        self._compiled_patterns: list[tuple[str, Any, str, str]] = []
        for rule_id, pattern, severity, desc in _MCP_INJECTION_PATTERNS:
            self._compiled_patterns.append(
                (rule_id, re.compile(pattern), severity, desc)
            )

    def scan_response(
        self,
        *,
        tool_name: str,
        response_data: Any,
        session_id: str,
        agent_id: str,
    ) -> MCPResponseScanResult:
        """Scan an MCP server response for injection and DLP violations.

        Args:
            tool_name: Name of the tool that produced the response.
            response_data: The response payload from the MCP server.
            session_id: MCP proxy session ID.
            agent_id: Agent ID for the session.

        Returns:
            MCPResponseScanResult with all findings.
        """
        start_us = time.monotonic_ns() // 1000

        text = self._extract_text(response_data)

        # 1. Injection detection
        injection_findings = self._scan_for_injection(text)

        # 2. Also check against the shared injection signature library
        lib_matches = injection_library.check(text)
        for match in lib_matches:
            injection_findings.append(MCPInjectionFinding(
                rule_id=match.signature_id,
                category=match.category,
                severity=match.severity,
                description=match.description,
                matched_text_snippet=text[:200] if len(text) > 200 else text,
                mitre_technique_id="T1059.001",
            ))

        # 3. DLP scanning on response
        dlp_findings: list[MCPDLPFinding] = []
        dlp_scan = network_dlp_scanner.scan_text(text)
        for f in dlp_scan:
            dlp_findings.append(MCPDLPFinding(
                rule_id=f.rule_id,
                category=f.metadata.get("category", ""),
                severity=f.severity.value if isinstance(f.severity, ScanSeverity) else str(f.severity),
                description=f.description,
                matched_field="response",
                matched_text_snippet=f.matched_text[:100] if f.matched_text else "",
                mitre_technique_id=f.mitre_technique_id,
            ))

        # Determine quarantine
        quarantined = len(injection_findings) > 0
        taint_level = "QUARANTINE" if quarantined else None

        latency_us = (time.monotonic_ns() // 1000) - start_us

        return MCPResponseScanResult(
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            direction=MCPScanDirection.INBOUND,
            dlp_findings=dlp_findings,
            injection_findings=injection_findings,
            quarantined=quarantined,
            taint_level_assigned=taint_level,
            latency_us=latency_us,
        )

    def _scan_for_injection(self, text: str) -> list[MCPInjectionFinding]:
        """Run MCP-specific injection patterns against text."""
        findings: list[MCPInjectionFinding] = []
        if not text:
            return findings

        for rule_id, compiled, severity, description in self._compiled_patterns:
            if compiled.search(text):
                findings.append(MCPInjectionFinding(
                    rule_id=rule_id,
                    category="mcp_response_injection",
                    severity=severity,
                    description=description,
                    matched_text_snippet=text[:200] if len(text) > 200 else text,
                    mitre_technique_id="T1059.001",
                ))

        return findings

    def _extract_text(self, data: Any) -> str:
        """Extract scannable text from response data."""
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            return json.dumps(data, default=str)
        if isinstance(data, (list, tuple)):
            return json.dumps(data, default=str)
        return str(data) if data is not None else ""


# Module-level singleton
mcp_response_scanner = MCPResponseScanner()
