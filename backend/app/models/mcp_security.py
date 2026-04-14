"""Pydantic models for Sprint 48 — MCP Proxy Enhancement: Bidirectional DLP & Tool Poisoning Detection.

APEP-380: MCPProxy outbound DLP scan models
APEP-381: MCP response scan models
APEP-382: Tool poisoning detection models
APEP-383: Rug-pull detection models
APEP-384: MCP HTTP reverse proxy mode models
APEP-385: MCP session DLP budget models
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


class MCPScanDirection(StrEnum):
    """Direction of DLP scan in the MCP proxy."""

    OUTBOUND = "outbound"  # Agent -> MCP server (request args)
    INBOUND = "inbound"  # MCP server -> Agent (response)


class MCPDLPAction(StrEnum):
    """Action taken when a DLP finding is detected."""

    BLOCK = "block"
    REDACT = "redact"
    LOG = "log"
    ALERT = "alert"


class ToolPoisoningCategory(StrEnum):
    """Categories of tool poisoning detected in tools/list descriptions."""

    PROMPT_INJECTION = "prompt_injection"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    EXFILTRATION_ATTEMPT = "exfiltration_attempt"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ENCODING_EVASION = "encoding_evasion"


class RugPullType(StrEnum):
    """Types of mid-session rug-pull changes detected."""

    DESCRIPTION_CHANGED = "description_changed"
    TOOL_ADDED = "tool_added"
    TOOL_REMOVED = "tool_removed"
    SCHEMA_CHANGED = "schema_changed"
    PARAMETER_CHANGED = "parameter_changed"


class MCPSecurityEventType(StrEnum):
    """Kafka event types for agentpep.mcp_security topic."""

    OUTBOUND_DLP_HIT = "OUTBOUND_DLP_HIT"
    INBOUND_DLP_HIT = "INBOUND_DLP_HIT"
    TOOL_POISONING_DETECTED = "TOOL_POISONING_DETECTED"
    RUG_PULL_DETECTED = "RUG_PULL_DETECTED"
    DLP_BUDGET_EXCEEDED = "DLP_BUDGET_EXCEEDED"
    RESPONSE_INJECTION = "RESPONSE_INJECTION"


# ---------------------------------------------------------------------------
# APEP-380: Outbound DLP scan
# ---------------------------------------------------------------------------


class MCPOutboundScanResult(BaseModel):
    """Result of scanning outbound MCP tool call arguments for DLP violations."""

    scan_id: UUID = Field(default_factory=uuid4)
    session_id: str
    agent_id: str
    tool_name: str
    direction: MCPScanDirection = MCPScanDirection.OUTBOUND
    findings: list[MCPDLPFinding] = Field(default_factory=list)
    blocked: bool = False
    action_taken: MCPDLPAction = MCPDLPAction.LOG
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    latency_us: int = 0


class MCPDLPFinding(BaseModel):
    """A single DLP finding in an MCP message."""

    rule_id: str
    category: str = ""
    severity: str = "MEDIUM"
    description: str = ""
    matched_field: str = Field(default="", description="The field/key where the match was found")
    matched_text_snippet: str = Field(default="", description="Truncated snippet of matched text")
    mitre_technique_id: str = ""


# ---------------------------------------------------------------------------
# APEP-381: MCP response scan
# ---------------------------------------------------------------------------


class MCPResponseScanResult(BaseModel):
    """Result of scanning an MCP server response for injection or DLP violations."""

    scan_id: UUID = Field(default_factory=uuid4)
    session_id: str
    agent_id: str
    tool_name: str
    direction: MCPScanDirection = MCPScanDirection.INBOUND
    dlp_findings: list[MCPDLPFinding] = Field(default_factory=list)
    injection_findings: list[MCPInjectionFinding] = Field(default_factory=list)
    quarantined: bool = False
    taint_level_assigned: str | None = None
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    latency_us: int = 0


class MCPInjectionFinding(BaseModel):
    """An injection finding in an MCP server response."""

    rule_id: str
    category: str = ""
    severity: str = "CRITICAL"
    description: str = ""
    matched_text_snippet: str = ""
    mitre_technique_id: str = ""


# ---------------------------------------------------------------------------
# APEP-382: Tool poisoning detection
# ---------------------------------------------------------------------------


class ToolDescriptionSnapshot(BaseModel):
    """Snapshot of a single tool from a tools/list response."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ToolPoisoningFinding(BaseModel):
    """A finding from scanning a tool description for poisoning."""

    tool_name: str
    category: ToolPoisoningCategory
    severity: str = "CRITICAL"
    description: str = ""
    matched_text_snippet: str = ""
    rule_id: str = ""
    mitre_technique_id: str = "T1059.001"


class ToolPoisoningScanResult(BaseModel):
    """Result of scanning tools/list response for poisoning."""

    scan_id: UUID = Field(default_factory=uuid4)
    session_id: str
    agent_id: str
    tools_scanned: int = 0
    findings: list[ToolPoisoningFinding] = Field(default_factory=list)
    blocked: bool = False
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# APEP-383: Rug-pull detection
# ---------------------------------------------------------------------------


class RugPullChange(BaseModel):
    """A detected change between two snapshots of the same tool."""

    tool_name: str
    change_type: RugPullType
    field: str = ""
    old_value: str = ""
    new_value: str = ""
    severity: str = "HIGH"
    description: str = ""


class RugPullDetectionResult(BaseModel):
    """Result of comparing two tools/list snapshots for rug-pull detection."""

    scan_id: UUID = Field(default_factory=uuid4)
    session_id: str
    agent_id: str
    changes: list[RugPullChange] = Field(default_factory=list)
    is_rug_pull: bool = False
    blocked: bool = False
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# APEP-384: MCP HTTP reverse proxy mode
# ---------------------------------------------------------------------------


class MCPReverseProxyConfig(BaseModel):
    """Configuration for MCP HTTP reverse proxy mode."""

    enabled: bool = False
    listen_port: int = Field(default=8890, ge=1024, le=65535)
    upstream_url: str = ""
    dlp_scan_enabled: bool = True
    poisoning_detection_enabled: bool = True
    rug_pull_detection_enabled: bool = True
    max_request_body_bytes: int = Field(default=10_485_760, description="10MB max request body")
    max_response_body_bytes: int = Field(default=52_428_800, description="50MB max response body")
    timeout_s: float = Field(default=30.0, gt=0)


class MCPReverseProxySession(BaseModel):
    """Tracking record for an MCP reverse proxy session."""

    session_id: str
    agent_id: str
    upstream_url: str
    status: str = "active"
    request_count: int = 0
    dlp_findings_count: int = 0
    poisoning_findings_count: int = 0
    rug_pull_detections: int = 0
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    ended_at: datetime | None = None


# ---------------------------------------------------------------------------
# APEP-385: MCP session DLP budget
# ---------------------------------------------------------------------------


class MCPSessionDLPBudget(BaseModel):
    """DLP budget tracking for an MCP session."""

    session_id: str
    agent_id: str
    max_dlp_findings: int = Field(default=10, ge=0, description="Max DLP findings before session block")
    max_critical_findings: int = Field(default=3, ge=0, description="Max CRITICAL findings before block")
    max_outbound_bytes_scanned: int = Field(
        default=104_857_600, description="100MB max outbound data scanned"
    )
    max_inbound_bytes_scanned: int = Field(
        default=524_288_000, description="500MB max inbound data scanned"
    )
    current_dlp_findings: int = 0
    current_critical_findings: int = 0
    outbound_bytes_scanned: int = 0
    inbound_bytes_scanned: int = 0
    budget_exceeded: bool = False
    exceeded_reason: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Kafka event model
# ---------------------------------------------------------------------------


class MCPSecurityEvent(BaseModel):
    """Kafka event published to agentpep.mcp_security topic."""

    event_id: UUID = Field(default_factory=uuid4)
    event_type: MCPSecurityEventType
    session_id: str
    agent_id: str
    tool_name: str = ""
    severity: str = "MEDIUM"
    description: str = ""
    findings_count: int = 0
    blocked: bool = False
    mitre_technique_id: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
