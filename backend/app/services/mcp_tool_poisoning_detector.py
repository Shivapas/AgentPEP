"""MCP tool poisoning detector — scan tools/list responses for injection.

Sprint 48 — APEP-382: Scans tool descriptions returned by ``tools/list``
for prompt injection, hidden instructions, and exfiltration attempts.

Malicious MCP servers can embed injection payloads in tool descriptions
that get passed to the LLM as context. This detector catches:
  - Prompt override attempts in descriptions
  - Hidden instructions (zero-width chars, Unicode tricks)
  - Exfiltration triggers (URLs, data sinks) in descriptions
  - Privilege escalation hints
  - Encoding evasion attempts (base64, hex)
"""

from __future__ import annotations

import base64
import logging
import re
import time
import unicodedata
from typing import Any

from app.models.mcp_security import (
    ToolDescriptionSnapshot,
    ToolPoisoningCategory,
    ToolPoisoningFinding,
    ToolPoisoningScanResult,
)
from app.services.injection_signatures import injection_library

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Poisoning detection patterns
# ---------------------------------------------------------------------------

_POISONING_PATTERNS: list[tuple[str, re.Pattern[str], ToolPoisoningCategory, str, str]] = [
    # Prompt injection in descriptions
    (
        "POISON-001",
        re.compile(r"(?i)ignore\s+(all\s+)?previous\s+instructions", re.DOTALL),
        ToolPoisoningCategory.PROMPT_INJECTION,
        "CRITICAL",
        "Prompt override in tool description",
    ),
    (
        "POISON-002",
        re.compile(r"(?i)disregard\s+(all\s+)?previous\s+prompts?", re.DOTALL),
        ToolPoisoningCategory.PROMPT_INJECTION,
        "CRITICAL",
        "Prompt disregard in tool description",
    ),
    (
        "POISON-003",
        re.compile(r"(?i)you\s+are\s+now\s+a\b", re.DOTALL),
        ToolPoisoningCategory.PROMPT_INJECTION,
        "HIGH",
        "Role hijacking in tool description",
    ),
    (
        "POISON-004",
        re.compile(r"(?i)<\s*system\s*>", re.DOTALL),
        ToolPoisoningCategory.PROMPT_INJECTION,
        "CRITICAL",
        "Embedded system tag in tool description",
    ),
    (
        "POISON-005",
        re.compile(r"(?i)\[\s*INST\s*\]", re.DOTALL),
        ToolPoisoningCategory.PROMPT_INJECTION,
        "CRITICAL",
        "Embedded instruction block in tool description",
    ),
    # Hidden instructions
    (
        "POISON-006",
        re.compile(r"(?i)IMPORTANT\s*:.*(?:always|must|never)\b", re.DOTALL),
        ToolPoisoningCategory.HIDDEN_INSTRUCTION,
        "HIGH",
        "Hidden behavioral instruction in tool description",
    ),
    (
        "POISON-007",
        re.compile(r"(?i)(?:before|after)\s+(?:each|every|any)\s+(?:call|request|use)", re.DOTALL),
        ToolPoisoningCategory.HIDDEN_INSTRUCTION,
        "MEDIUM",
        "Behavioral trigger instruction in tool description",
    ),
    # Exfiltration attempts
    (
        "POISON-008",
        re.compile(
            r"(?i)(?:send|post|upload|transmit|forward)\s+(?:all|any|the)\s+"
            r"(?:data|content|information|results?|output|response)",
            re.DOTALL,
        ),
        ToolPoisoningCategory.EXFILTRATION_ATTEMPT,
        "CRITICAL",
        "Data exfiltration instruction in tool description",
    ),
    (
        "POISON-009",
        re.compile(r"https?://[^\s\"'<>]{10,}", re.DOTALL),
        ToolPoisoningCategory.EXFILTRATION_ATTEMPT,
        "MEDIUM",
        "URL embedded in tool description (potential data sink)",
    ),
    # Privilege escalation
    (
        "POISON-010",
        re.compile(
            r"(?i)(?:execute|run|invoke)\s+(?:this|the\s+following)\s+"
            r"(?:command|script|code|tool)",
            re.DOTALL,
        ),
        ToolPoisoningCategory.PRIVILEGE_ESCALATION,
        "HIGH",
        "Command execution instruction in tool description",
    ),
    (
        "POISON-011",
        re.compile(r"(?i)(?:sudo|admin|root|superuser|elevated)\s+(?:access|mode|privilege)", re.DOTALL),
        ToolPoisoningCategory.PRIVILEGE_ESCALATION,
        "HIGH",
        "Privilege escalation hint in tool description",
    ),
]

# Zero-width and invisible Unicode characters
_INVISIBLE_CHARS = frozenset([
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\u2060",  # Word joiner
    "\u2061",  # Function application
    "\u2062",  # Invisible times
    "\u2063",  # Invisible separator
    "\u2064",  # Invisible plus
    "\ufeff",  # BOM / zero-width no-break space
    "\u00ad",  # Soft hyphen
    "\u034f",  # Combining grapheme joiner
    "\u061c",  # Arabic letter mark
    "\u180e",  # Mongolian vowel separator
])


class MCPToolPoisoningDetector:
    """Detects poisoned tool descriptions in MCP tools/list responses.

    Scans each tool's description and input schema for injection payloads,
    hidden instructions, exfiltration triggers, and encoding evasion.
    """

    def scan_tools_list(
        self,
        *,
        tools: list[dict[str, Any]],
        session_id: str,
        agent_id: str,
    ) -> ToolPoisoningScanResult:
        """Scan a tools/list response for poisoning.

        Args:
            tools: List of tool definitions from the MCP tools/list response.
            session_id: MCP proxy session ID.
            agent_id: Agent ID for the session.

        Returns:
            ToolPoisoningScanResult with all findings.
        """
        start = time.monotonic_ns()
        findings: list[ToolPoisoningFinding] = []

        for tool_def in tools:
            name = tool_def.get("name", "")
            description = tool_def.get("description", "")
            input_schema = tool_def.get("inputSchema", tool_def.get("input_schema", {}))

            # Scan description
            findings.extend(self._scan_text(name, description))

            # Scan input schema descriptions
            if isinstance(input_schema, dict):
                schema_text = self._extract_schema_descriptions(input_schema)
                if schema_text:
                    findings.extend(self._scan_text(name, schema_text))

            # Check for invisible characters
            invisible_findings = self._check_invisible_chars(name, description)
            findings.extend(invisible_findings)

            # Check for encoding evasion in description
            encoding_findings = self._check_encoding_evasion(name, description)
            findings.extend(encoding_findings)

        blocked = any(f.severity == "CRITICAL" for f in findings)

        return ToolPoisoningScanResult(
            session_id=session_id,
            agent_id=agent_id,
            tools_scanned=len(tools),
            findings=findings,
            blocked=blocked,
        )

    def _scan_text(
        self, tool_name: str, text: str
    ) -> list[ToolPoisoningFinding]:
        """Run poisoning patterns against text."""
        findings: list[ToolPoisoningFinding] = []
        if not text:
            return findings

        for rule_id, pattern, category, severity, desc in _POISONING_PATTERNS:
            if pattern.search(text):
                findings.append(ToolPoisoningFinding(
                    tool_name=tool_name,
                    category=category,
                    severity=severity,
                    description=desc,
                    matched_text_snippet=text[:200] if len(text) > 200 else text,
                    rule_id=rule_id,
                ))

        # Also check against shared injection signature library
        lib_matches = injection_library.check(text)
        for match in lib_matches:
            findings.append(ToolPoisoningFinding(
                tool_name=tool_name,
                category=ToolPoisoningCategory.PROMPT_INJECTION,
                severity=match.severity,
                description=f"Injection signature match: {match.description}",
                matched_text_snippet=text[:200] if len(text) > 200 else text,
                rule_id=match.signature_id,
            ))

        return findings

    def _check_invisible_chars(
        self, tool_name: str, text: str
    ) -> list[ToolPoisoningFinding]:
        """Check for invisible/zero-width characters that might hide instructions."""
        if not text:
            return []

        invisible_count = sum(1 for ch in text if ch in _INVISIBLE_CHARS)
        if invisible_count > 0:
            return [ToolPoisoningFinding(
                tool_name=tool_name,
                category=ToolPoisoningCategory.ENCODING_EVASION,
                severity="HIGH" if invisible_count > 3 else "MEDIUM",
                description=(
                    f"Found {invisible_count} invisible/zero-width character(s) "
                    f"in tool description — possible hidden instruction"
                ),
                matched_text_snippet=repr(text[:100]),
                rule_id="POISON-ZW",
            )]
        return []

    def _check_encoding_evasion(
        self, tool_name: str, text: str
    ) -> list[ToolPoisoningFinding]:
        """Check for base64/hex-encoded payloads in tool descriptions."""
        findings: list[ToolPoisoningFinding] = []
        if not text:
            return findings

        # Look for base64-encoded blocks (min 20 chars to reduce false positives)
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
        for match in b64_pattern.finditer(text):
            candidate = match.group()
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                if len(decoded) > 10 and any(c.isalpha() for c in decoded):
                    # Check if decoded content contains injection patterns
                    lib_matches = injection_library.check(decoded)
                    if lib_matches:
                        findings.append(ToolPoisoningFinding(
                            tool_name=tool_name,
                            category=ToolPoisoningCategory.ENCODING_EVASION,
                            severity="CRITICAL",
                            description=(
                                f"Base64-encoded injection payload in tool description: "
                                f"{lib_matches[0].description}"
                            ),
                            matched_text_snippet=candidate[:100],
                            rule_id="POISON-B64",
                        ))
            except Exception:
                pass

        return findings

    def _extract_schema_descriptions(self, schema: dict[str, Any]) -> str:
        """Extract all description fields from a JSON schema."""
        texts: list[str] = []

        def _walk(obj: Any) -> None:
            if isinstance(obj, dict):
                if "description" in obj and isinstance(obj["description"], str):
                    texts.append(obj["description"])
                for v in obj.values():
                    _walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item)

        _walk(schema)
        return " ".join(texts)

    def capture_snapshot(
        self, tools: list[dict[str, Any]]
    ) -> list[ToolDescriptionSnapshot]:
        """Capture a snapshot of tool descriptions for rug-pull comparison."""
        snapshots = []
        for tool_def in tools:
            snapshots.append(ToolDescriptionSnapshot(
                name=tool_def.get("name", ""),
                description=tool_def.get("description", ""),
                input_schema=tool_def.get("inputSchema", tool_def.get("input_schema", {})),
            ))
        return snapshots


# Module-level singleton
mcp_tool_poisoning_detector = MCPToolPoisoningDetector()
