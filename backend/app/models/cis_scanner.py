"""Pydantic models for Sprint 54 — Pre-Session Repository Scanner & Agent Instruction File Scanner.

APEP-428/429/430/431/432: Data models for CIS repo scanning, agent instruction
file scanning, scan-on-session-start hook, PostToolUse auto-scan, and
individual file/text scanning endpoints.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CISScanTarget(StrEnum):
    """What to scan via the CIS endpoints."""

    FILE = "file"
    DIRECTORY = "directory"
    TEXT = "text"
    TOOL_OUTPUT = "tool_output"
    REPOSITORY = "repository"


class CISScanVerdict(StrEnum):
    """Aggregate verdict from a CIS scan."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class InstructionFileType(StrEnum):
    """Known agent instruction file types scanned in STRICT mode."""

    CLAUDE_MD = "CLAUDE.md"
    CURSORRULES = ".cursorrules"
    AGENTS_MD = "AGENTS.md"
    COPILOT_INSTRUCTIONS = ".github/copilot-instructions.md"
    UNKNOWN = "UNKNOWN"


class PostToolScanTrigger(StrEnum):
    """What triggered a PostToolUse auto-scan."""

    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    COMMAND_OUTPUT = "command_output"
    MCP_RESPONSE = "mcp_response"
    WEB_FETCH = "web_fetch"
    TOOL_OUTPUT = "tool_output"


class CISEventType(StrEnum):
    """Kafka event types for the agentpep.cis topic."""

    REPO_SCAN_STARTED = "REPO_SCAN_STARTED"
    REPO_SCAN_COMPLETED = "REPO_SCAN_COMPLETED"
    INSTRUCTION_FILE_DETECTED = "INSTRUCTION_FILE_DETECTED"
    INJECTION_IN_INSTRUCTION = "INJECTION_IN_INSTRUCTION"
    POST_TOOL_SCAN_HIT = "POST_TOOL_SCAN_HIT"
    SESSION_SCAN_COMPLETED = "SESSION_SCAN_COMPLETED"


# ---------------------------------------------------------------------------
# CIS Scan Request (shared across endpoints)
# ---------------------------------------------------------------------------


class CISScanRequest(BaseModel):
    """Request payload for CIS scan endpoints."""

    scan_target: CISScanTarget = Field(..., description="What to scan")
    path: str | None = Field(default=None, description="File or directory path")
    content: str | None = Field(default=None, description="Text content to scan")
    session_id: str | None = Field(
        default=None, description="Associate result with session for auto-taint"
    )
    agent_id: str | None = Field(
        default=None, description="Agent context for scan mode selection"
    )
    scan_mode: str = Field(
        default="STRICT", description="STRICT, STANDARD, or LENIENT"
    )
    tiers: list[int] = Field(
        default=[0, 1], description="Tiers to run: 0=regex, 1=ONNX"
    )
    use_cache: bool = Field(default=True, description="Use trust cache")
    tenant_id: str = Field(default="", description="Tenant ID for allowlist lookups")


# ---------------------------------------------------------------------------
# CIS Scan Finding
# ---------------------------------------------------------------------------


class CISFinding(BaseModel):
    """A single finding from the CIS scanner."""

    finding_id: UUID = Field(default_factory=uuid4)
    rule_id: str = Field(..., description="Matched rule or pattern identifier")
    scanner: str = Field(..., description="Scanner that produced the finding")
    severity: str = Field(default="MEDIUM", description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    description: str = Field(default="")
    matched_text: str = Field(default="", description="Snippet that matched (truncated)")
    file_path: str | None = Field(default=None, description="File where finding occurred")
    line_number: int | None = Field(default=None, description="Line number in file")
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# CIS Scan Result (shared)
# ---------------------------------------------------------------------------


class CISScanResult(BaseModel):
    """Aggregate result from a CIS scan."""

    scan_id: UUID = Field(default_factory=uuid4)
    allowed: bool = Field(default=True, description="Whether content passed all tiers")
    verdict: CISScanVerdict = Field(default=CISScanVerdict.CLEAN)
    findings: list[CISFinding] = Field(default_factory=list)
    tier_results: list[dict[str, Any]] = Field(default_factory=list)
    scan_mode: str = Field(default="STRICT")
    taint_assigned: str | None = Field(
        default=None, description="Taint level if session_id provided"
    )
    cache_hit: bool = Field(default=False)
    files_scanned: int = Field(default=0, description="Number of files scanned")
    latency_ms: int = Field(default=0)


# ---------------------------------------------------------------------------
# Repo Scan Request / Result (APEP-428)
# ---------------------------------------------------------------------------


class RepoScanRequest(BaseModel):
    """Request for POST /v1/cis/scan-repo."""

    repo_path: str = Field(..., description="Path to repository root to scan")
    session_id: str | None = Field(
        default=None, description="Session ID for taint propagation"
    )
    agent_id: str | None = Field(default=None, description="Agent context")
    scan_mode: str = Field(default="STRICT", description="Default: STRICT for repos")
    tiers: list[int] = Field(default=[0, 1], description="Tiers to run")
    max_files: int = Field(
        default=500, ge=1, le=10000,
        description="Maximum files to scan (safety limit)",
    )
    include_patterns: list[str] = Field(
        default_factory=list,
        description="Glob patterns to include (empty = all files)",
    )
    exclude_patterns: list[str] = Field(
        default_factory=lambda: [
            "*.pyc", "__pycache__/**", "node_modules/**", ".git/**",
            "*.lock", "*.min.js", "*.min.css", "dist/**", "build/**",
        ],
        description="Glob patterns to exclude",
    )
    use_cache: bool = Field(default=True)
    tenant_id: str = Field(default="")


class RepoScanFileResult(BaseModel):
    """Per-file result within a repo scan."""

    file_path: str
    scan_mode_applied: str
    allowed: bool = True
    findings: list[CISFinding] = Field(default_factory=list)
    is_instruction_file: bool = Field(
        default=False, description="Whether this is an agent instruction file"
    )
    instruction_file_type: InstructionFileType | None = None
    cache_hit: bool = False
    latency_ms: int = 0


class RepoScanResult(BaseModel):
    """Result from POST /v1/cis/scan-repo."""

    scan_id: UUID = Field(default_factory=uuid4)
    repo_path: str
    allowed: bool = Field(default=True, description="Overall: no HIGH/CRITICAL findings")
    verdict: CISScanVerdict = Field(default=CISScanVerdict.CLEAN)
    total_files_scanned: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    instruction_files_found: int = 0
    file_results: list[RepoScanFileResult] = Field(default_factory=list)
    taint_assigned: str | None = None
    scan_mode: str = "STRICT"
    latency_ms: int = 0
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None


# ---------------------------------------------------------------------------
# File Scan Request / Result (APEP-432)
# ---------------------------------------------------------------------------


class FileScanRequest(BaseModel):
    """Request for POST /v1/cis/scan-file."""

    file_path: str = Field(..., description="Path to file to scan")
    session_id: str | None = None
    agent_id: str | None = None
    scan_mode: str | None = Field(
        default=None,
        description="Override scan mode; None = auto-detect from file type",
    )
    tiers: list[int] = Field(default=[0, 1])
    use_cache: bool = Field(default=True)
    tenant_id: str = Field(default="")


class FileScanResult(BaseModel):
    """Result from POST /v1/cis/scan-file."""

    scan_id: UUID = Field(default_factory=uuid4)
    file_path: str
    allowed: bool = True
    verdict: CISScanVerdict = Field(default=CISScanVerdict.CLEAN)
    findings: list[CISFinding] = Field(default_factory=list)
    scan_mode_applied: str = "STANDARD"
    is_instruction_file: bool = False
    instruction_file_type: InstructionFileType | None = None
    taint_assigned: str | None = None
    cache_hit: bool = False
    latency_ms: int = 0


# ---------------------------------------------------------------------------
# Session Start Hook (APEP-430)
# ---------------------------------------------------------------------------


class SessionStartScanRequest(BaseModel):
    """Request for scan-on-session-start hook."""

    session_id: str = Field(..., description="Session being started")
    agent_id: str | None = None
    repo_path: str | None = Field(
        default=None, description="Repository root; None = skip repo scan"
    )
    scan_mode: str = Field(default="STRICT")
    tiers: list[int] = Field(default=[0, 1])
    max_files: int = Field(default=500)
    tenant_id: str = Field(default="")


class SessionStartScanResult(BaseModel):
    """Result from scan-on-session-start hook."""

    session_id: str
    scan_id: UUID = Field(default_factory=uuid4)
    repo_scan: RepoScanResult | None = None
    instruction_files_clean: bool = True
    session_allowed: bool = Field(
        default=True,
        description="False if any CRITICAL/HIGH findings in instruction files",
    )
    taint_assigned: str | None = None
    latency_ms: int = 0


# ---------------------------------------------------------------------------
# PostToolUse Auto-Scan (APEP-431)
# ---------------------------------------------------------------------------


class PostToolScanRequest(BaseModel):
    """Request for PostToolUse auto-scan."""

    session_id: str = Field(..., description="Active session ID")
    agent_id: str | None = None
    tool_name: str = Field(..., description="Tool that produced the output")
    tool_output: str = Field(..., description="Output content from the tool")
    trigger: PostToolScanTrigger = Field(default=PostToolScanTrigger.TOOL_OUTPUT)
    scan_mode: str = Field(default="STANDARD")
    tiers: list[int] = Field(default=[0, 1])
    auto_taint: bool = Field(
        default=True, description="Auto-label QUARANTINE if injection detected"
    )
    auto_escalate: bool = Field(
        default=True, description="Auto-escalate MEDIUM→HIGH if injection in tool output"
    )
    tenant_id: str = Field(default="")


class PostToolScanResult(BaseModel):
    """Result from PostToolUse auto-scan."""

    scan_id: UUID = Field(default_factory=uuid4)
    session_id: str
    tool_name: str
    trigger: PostToolScanTrigger
    allowed: bool = True
    verdict: CISScanVerdict = Field(default=CISScanVerdict.CLEAN)
    findings: list[CISFinding] = Field(default_factory=list)
    scan_mode_applied: str = "STANDARD"
    taint_assigned: str | None = None
    escalated: bool = Field(
        default=False, description="Whether severity was auto-escalated"
    )
    latency_ms: int = 0


# ---------------------------------------------------------------------------
# CIS Kafka Event
# ---------------------------------------------------------------------------


class CISEvent(BaseModel):
    """Kafka event published to agentpep.cis topic."""

    event_id: UUID = Field(default_factory=uuid4)
    event_type: CISEventType
    session_id: str | None = None
    agent_id: str | None = None
    scan_id: UUID | None = None
    file_path: str | None = None
    verdict: CISScanVerdict = CISScanVerdict.CLEAN
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    taint_assigned: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
