"""Pydantic models for Sprint 46 — Fetch Proxy & Multi-Pass Response Injection Scanner.

APEP-364: GET /v1/fetch?url=... fetch proxy models.
APEP-365: 6-pass ResponseNormalizer models.
APEP-366: ResponseInjectionScanner models.
APEP-369: Configurable response actions models.
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


class FetchStatus(StrEnum):
    """Overall status of a fetch proxy request."""

    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    QUARANTINED = "QUARANTINED"
    SANITIZED = "SANITIZED"


class ResponseAction(StrEnum):
    """Configurable action to take on fetch response (APEP-369)."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    SANITIZE = "SANITIZE"
    REDACT = "REDACT"
    LOG_ONLY = "LOG_ONLY"


class NormalizationPass(StrEnum):
    """The 6 Unicode normalization passes (APEP-365)."""

    NFC = "NFC"
    NFKC = "NFKC"
    CONFUSABLE_MAP = "CONFUSABLE_MAP"
    ZERO_WIDTH_STRIP = "ZERO_WIDTH_STRIP"
    BIDI_STRIP = "BIDI_STRIP"
    HOMOGLYPH_NORMALIZE = "HOMOGLYPH_NORMALIZE"


class InjectionScanPassType(StrEnum):
    """Scanner pass types within ResponseInjectionScanner (APEP-366)."""

    RAW_SIGNATURE = "RAW_SIGNATURE"
    NORMALIZED_SIGNATURE = "NORMALIZED_SIGNATURE"
    STRUCTURAL_PATTERN = "STRUCTURAL_PATTERN"
    ENCODING_PROBE = "ENCODING_PROBE"
    SEMANTIC_HEURISTIC = "SEMANTIC_HEURISTIC"
    STATISTICAL_ANOMALY = "STATISTICAL_ANOMALY"


class FetchEventType(StrEnum):
    """Kafka event types for agentpep.fetch topic."""

    FETCH_ALLOWED = "FETCH_ALLOWED"
    FETCH_BLOCKED = "FETCH_BLOCKED"
    INJECTION_DETECTED = "INJECTION_DETECTED"
    DLP_HIT = "DLP_HIT"
    QUARANTINE_APPLIED = "QUARANTINE_APPLIED"


# ---------------------------------------------------------------------------
# Normalization result per pass (APEP-365)
# ---------------------------------------------------------------------------


class NormalizationPassResult(BaseModel):
    """Result from a single normalization pass."""

    pass_name: NormalizationPass
    applied: bool = Field(default=True, description="Whether the pass was applied")
    changes_made: int = Field(default=0, description="Number of characters changed")
    characters_stripped: int = Field(default=0, description="Number of characters stripped")
    description: str = Field(default="", description="Human-readable summary")


class NormalizationResult(BaseModel):
    """Aggregate result from the 6-pass ResponseNormalizer (APEP-365)."""

    original_length: int = Field(default=0)
    normalized_length: int = Field(default=0)
    total_changes: int = Field(default=0)
    passes: list[NormalizationPassResult] = Field(default_factory=list)
    normalized_text: str = Field(default="", description="Text after all normalization passes")


# ---------------------------------------------------------------------------
# Injection scan finding (APEP-366)
# ---------------------------------------------------------------------------


class InjectionFinding(BaseModel):
    """A single injection finding from ResponseInjectionScanner."""

    finding_id: UUID = Field(default_factory=uuid4)
    pass_type: InjectionScanPassType
    signature_id: str = Field(default="", description="Matched injection signature ID")
    severity: str = Field(default="HIGH")
    description: str = Field(default="")
    matched_text: str = Field(default="", description="Snippet that triggered the finding")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence")
    mitre_technique_id: str = Field(default="T1059.001", description="MITRE ATT&CK ID")


class InjectionScanResult(BaseModel):
    """Aggregate result from ResponseInjectionScanner (APEP-366)."""

    injection_detected: bool = Field(default=False)
    findings: list[InjectionFinding] = Field(default_factory=list)
    passes_run: list[InjectionScanPassType] = Field(default_factory=list)
    total_findings: int = Field(default=0)
    highest_severity: str = Field(default="INFO")
    scan_latency_us: int = Field(default=0, description="Scan latency in microseconds")


# ---------------------------------------------------------------------------
# Response action config (APEP-369)
# ---------------------------------------------------------------------------


class ResponseActionRule(BaseModel):
    """A configurable rule mapping findings to response actions (APEP-369)."""

    rule_id: str = Field(default="", description="Unique rule identifier")
    name: str = Field(default="", description="Human-readable rule name")
    min_severity: str = Field(default="HIGH", description="Minimum severity to trigger")
    min_findings: int = Field(default=1, ge=1, description="Minimum finding count to trigger")
    action: ResponseAction = Field(default=ResponseAction.BLOCK)
    enabled: bool = Field(default=True)


class ResponseActionConfig(BaseModel):
    """Configuration for response action rules (APEP-369)."""

    default_action: ResponseAction = Field(
        default=ResponseAction.ALLOW,
        description="Default action when no rules match",
    )
    rules: list[ResponseActionRule] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Fetch proxy request / response (APEP-364)
# ---------------------------------------------------------------------------


class FetchProxyRequest(BaseModel):
    """Parameters for the GET /v1/fetch endpoint (query-string mapped)."""

    url: str = Field(..., description="URL to fetch")
    session_id: str | None = Field(default=None, description="Session for taint propagation")
    agent_id: str | None = Field(default=None, description="Agent context")
    scan_response: bool = Field(default=True, description="Run injection + DLP scan on response")
    max_bytes: int = Field(default=1_048_576, ge=0, le=10_485_760, description="Max response size")


class FetchProxyResponse(BaseModel):
    """Response from the GET /v1/fetch endpoint (APEP-364)."""

    fetch_id: UUID = Field(default_factory=uuid4)
    url: str
    status: FetchStatus = Field(default=FetchStatus.ALLOWED)
    http_status: int = Field(default=200, description="Upstream HTTP status code")
    content_type: str = Field(default="", description="Upstream Content-Type header")
    body: str = Field(default="", description="Response body (may be sanitized/redacted)")
    body_length: int = Field(default=0)
    truncated: bool = Field(default=False, description="True if body was truncated at max_bytes")

    # Normalization results (APEP-365)
    normalization: NormalizationResult | None = Field(
        default=None, description="Results from 6-pass normalizer"
    )

    # Injection scan results (APEP-366)
    injection_scan: InjectionScanResult | None = Field(
        default=None, description="Results from injection scanner"
    )

    # DLP scan results (APEP-368)
    dlp_findings_count: int = Field(default=0, description="Number of DLP findings")
    dlp_blocked: bool = Field(default=False, description="Whether DLP scan triggered a block")

    # Taint info (APEP-367)
    taint_applied: str | None = Field(
        default=None, description="Taint level applied to session graph"
    )
    taint_node_id: str | None = Field(
        default=None, description="Node ID in session taint graph"
    )

    # Action taken (APEP-369)
    action_taken: ResponseAction = Field(
        default=ResponseAction.ALLOW, description="Final action applied"
    )

    latency_ms: int = Field(default=0, description="Total proxy latency in milliseconds")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Kafka fetch event (APEP-364)
# ---------------------------------------------------------------------------


class FetchEvent(BaseModel):
    """Kafka event published to agentpep.fetch topic."""

    event_id: UUID = Field(default_factory=uuid4)
    fetch_id: UUID | None = None
    session_id: str | None = None
    agent_id: str | None = None
    event_type: FetchEventType
    url: str = ""
    http_status: int = 0
    injection_detected: bool = False
    injection_finding_count: int = 0
    dlp_finding_count: int = 0
    action_taken: ResponseAction = ResponseAction.ALLOW
    taint_applied: str | None = None
    latency_ms: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
