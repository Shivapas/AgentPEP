"""Pydantic models for Sprint 44 — Network DLP Engine & 11-Layer URL Scanner.

APEP-348/349/350/351/352/353/354/355: Data models for NetworkDLPScanner,
URLScanner pipeline, EntropyAnalyzer, SSRFGuard, domain blocklist, per-domain
rate limiting, and the POST /v1/scan endpoint.
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


class ScanKind(StrEnum):
    """What to scan via /v1/scan."""

    URL = "url"
    DLP = "dlp"
    INJECTION = "injection"
    TOOL_CALL = "tool_call"


class NetworkEventType(StrEnum):
    """Kafka event types for agentpep.network topic."""

    DLP_HIT = "DLP_HIT"
    INJECTION_DETECTED = "INJECTION_DETECTED"
    SSRF_BLOCKED = "SSRF_BLOCKED"
    CHAIN_DETECTED = "CHAIN_DETECTED"
    KILL_SWITCH = "KILL_SWITCH"
    SENTINEL_HIT = "SENTINEL_HIT"


class ScanSeverity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanMode(StrEnum):
    """TFN security modes mapping to AgentPEP enforcement posture."""

    STRICT = "strict"
    BALANCED = "balanced"
    AUDIT = "audit"


# ---------------------------------------------------------------------------
# Finding (shared across all scanners)
# ---------------------------------------------------------------------------


class ScanFinding(BaseModel):
    """A single finding from any scanner."""

    rule_id: str = Field(..., description="Matched rule or pattern identifier")
    scanner: str = Field(..., description="Scanner that produced the finding")
    severity: ScanSeverity = Field(default=ScanSeverity.MEDIUM)
    description: str = Field(default="", description="Human-readable finding description")
    matched_text: str = Field(default="", description="Snippet of text that matched (truncated)")
    mitre_technique_id: str = Field(default="", description="MITRE ATT&CK technique ID")
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# NetworkScanRequest / NetworkScanResult (POST /v1/scan)
# ---------------------------------------------------------------------------


class NetworkScanRequest(BaseModel):
    """Request payload for the POST /v1/scan endpoint."""

    scan_kind: ScanKind = Field(..., description="What to scan")
    url: str | None = Field(default=None, description="URL to scan (for url and dlp kinds)")
    text: str | None = Field(default=None, description="Text to scan (for injection and dlp kinds)")
    tool_args: dict[str, Any] | None = Field(
        default=None, description="Tool arguments to scan for DLP"
    )
    session_id: str | None = Field(
        default=None, description="Associate scan with session for taint propagation"
    )
    agent_id: str | None = Field(default=None, description="Agent context for per-agent filtering")


class NetworkScanResult(BaseModel):
    """Result from the POST /v1/scan endpoint."""

    allowed: bool = Field(default=True, description="Whether content passed all scans")
    blocked: bool = Field(default=False, description="Whether any scanner returned a block")
    findings: list[ScanFinding] = Field(default_factory=list)
    scanners_run: list[str] = Field(default_factory=list, description="Names of scanners executed")
    taint_assigned: str | None = Field(
        default=None, description="Taint level assigned if session_id provided"
    )
    mitre_technique_ids: list[str] = Field(default_factory=list)
    latency_ms: int = Field(default=0, description="Total scan latency in milliseconds")


# ---------------------------------------------------------------------------
# NetworkEvent (Kafka: agentpep.network)
# ---------------------------------------------------------------------------


class NetworkEvent(BaseModel):
    """Kafka event published to agentpep.network topic."""

    event_id: UUID = Field(default_factory=uuid4)
    session_id: str | None = None
    agent_id: str | None = None
    decision_id: UUID | None = None
    event_type: NetworkEventType
    scanner: str
    finding_rule_id: str = ""
    severity: ScanSeverity = ScanSeverity.MEDIUM
    mitre_technique_id: str = ""
    url: str | None = None
    blocked: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# DLP Pattern model (extends injection_signatures pattern)
# ---------------------------------------------------------------------------


class DLPPattern(BaseModel):
    """A DLP detection pattern for API keys, tokens, credentials."""

    pattern_id: str = Field(..., description="Unique pattern ID e.g. DLP-001")
    category: str = Field(..., description="Category: api_key, token, credential, secret, pii")
    pattern: str = Field(..., description="Compiled regex pattern string")
    severity: ScanSeverity = Field(default=ScanSeverity.HIGH)
    description: str = Field(default="")
    mitre_technique_id: str = Field(
        default="", description="MITRE ATT&CK technique (e.g. T1552.001)"
    )


# ---------------------------------------------------------------------------
# URL Scanner layer results
# ---------------------------------------------------------------------------


class URLScanLayerResult(BaseModel):
    """Result from a single layer in the 11-layer URL scanner pipeline."""

    layer_name: str
    passed: bool = True
    findings: list[ScanFinding] = Field(default_factory=list)
    latency_us: int = Field(default=0, description="Layer latency in microseconds")


class URLScanResult(BaseModel):
    """Aggregate result from the 11-layer URL scanner pipeline."""

    url: str
    allowed: bool = True
    blocked: bool = False
    layer_results: list[URLScanLayerResult] = Field(default_factory=list)
    findings: list[ScanFinding] = Field(default_factory=list)
    total_latency_us: int = 0


# ---------------------------------------------------------------------------
# Entropy analysis result
# ---------------------------------------------------------------------------


class EntropyResult(BaseModel):
    """Result from Shannon entropy analysis."""

    text_snippet: str = Field(default="", description="Analysed text (truncated)")
    entropy: float = Field(default=0.0, description="Shannon entropy value")
    is_suspicious: bool = Field(default=False, description="Whether entropy exceeds threshold")
    threshold: float = Field(default=4.5, description="Threshold used for detection")


# ---------------------------------------------------------------------------
# SSRF check result
# ---------------------------------------------------------------------------


class SSRFCheckResult(BaseModel):
    """Result from SSRF / DNS rebinding analysis."""

    url: str = ""
    hostname: str = ""
    resolved_ips: list[str] = Field(default_factory=list)
    is_private: bool = False
    is_loopback: bool = False
    is_link_local: bool = False
    blocked: bool = False
    reason: str = ""


# ---------------------------------------------------------------------------
# Domain rate limit tracking
# ---------------------------------------------------------------------------


class DomainRateLimitState(BaseModel):
    """Per-domain rate limit and data budget state."""

    domain: str
    request_count: int = 0
    request_limit: int = Field(default=100, description="Max requests per window")
    data_bytes_transferred: int = 0
    data_budget_bytes: int = Field(default=10_485_760, description="Max bytes per window (10MB)")
    window_start: datetime = Field(default_factory=lambda: datetime.now(UTC))
    window_seconds: int = Field(default=60, description="Rate limit window duration")
    exceeded: bool = False
    reason: str = ""
