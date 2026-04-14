"""Pydantic models for Sprint 51 — Rule Bundles, Security Assessment & Network Audit Events.

APEP-404: Rule bundle format — Ed25519-signed community rule bundles in YAML.
APEP-405: Rule bundle loader — load, verify, and hot-reload rule bundles.
APEP-406: Security assessment engine — attack simulation + config audit + deployment probe.
APEP-407: GET /v1/network/assess — security assessment endpoint.
APEP-408: MITRE ATT&CK technique mapping — technique ID enrichment on all TFN events.
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


class BundleStatus(StrEnum):
    """Lifecycle status of a rule bundle."""

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    INVALID = "INVALID"
    PENDING_REVIEW = "PENDING_REVIEW"


class BundleRuleType(StrEnum):
    """Types of rules that can appear in a bundle."""

    DLP = "DLP"
    INJECTION = "INJECTION"
    URL_BLOCK = "URL_BLOCK"
    CHAIN_PATTERN = "CHAIN_PATTERN"
    CUSTOM = "CUSTOM"


class AssessmentCategory(StrEnum):
    """12-category security assessment categories (config audit)."""

    DLP_COVERAGE = "DLP_COVERAGE"
    INJECTION_PROTECTION = "INJECTION_PROTECTION"
    SSRF_PREVENTION = "SSRF_PREVENTION"
    RATE_LIMITING = "RATE_LIMITING"
    AUTH_CONFIG = "AUTH_CONFIG"
    TAINT_TRACKING = "TAINT_TRACKING"
    KILL_SWITCH = "KILL_SWITCH"
    CHAIN_DETECTION = "CHAIN_DETECTION"
    FILESYSTEM_SENTINEL = "FILESYSTEM_SENTINEL"
    TLS_CONFIG = "TLS_CONFIG"
    AUDIT_INTEGRITY = "AUDIT_INTEGRITY"
    NETWORK_EGRESS = "NETWORK_EGRESS"


class AssessmentSeverity(StrEnum):
    """Severity for assessment findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASS = "PASS"


class AssessmentPhase(StrEnum):
    """Phases of the security assessment engine."""

    CONFIG_AUDIT = "CONFIG_AUDIT"
    ATTACK_SIMULATION = "ATTACK_SIMULATION"
    DEPLOYMENT_PROBE = "DEPLOYMENT_PROBE"


class MitreTactic(StrEnum):
    """MITRE ATT&CK tactics relevant to AI agent security."""

    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    EXFILTRATION = "TA0010"
    COMMAND_AND_CONTROL = "TA0011"
    IMPACT = "TA0040"


# ---------------------------------------------------------------------------
# APEP-404: Rule Bundle Format
# ---------------------------------------------------------------------------


class BundleRule(BaseModel):
    """A single rule within a rule bundle."""

    rule_id: str = Field(..., description="Unique rule identifier within the bundle")
    rule_type: BundleRuleType = Field(..., description="Type of rule")
    pattern: str = Field(default="", description="Regex or match pattern")
    severity: AssessmentSeverity = Field(default=AssessmentSeverity.MEDIUM)
    description: str = Field(default="", description="Human-readable description")
    mitre_technique_id: str = Field(default="", description="MITRE ATT&CK technique ID")
    enabled: bool = Field(default=True, description="Whether the rule is active")
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuleBundleManifest(BaseModel):
    """Metadata header for a rule bundle YAML file."""

    name: str = Field(..., description="Bundle name (e.g. 'community-dlp-v1')")
    version: str = Field(default="1.0.0", description="SemVer version")
    author: str = Field(default="", description="Bundle author or organization")
    description: str = Field(default="", description="Bundle purpose description")
    homepage: str = Field(default="", description="URL to bundle documentation")
    min_agentpep_version: str = Field(
        default="1.0.0", description="Minimum AgentPEP version required"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tags: list[str] = Field(default_factory=list, description="Categorization tags")


class RuleBundle(BaseModel):
    """An Ed25519-signed community rule bundle (YAML format).

    A rule bundle packages a set of detection rules (DLP patterns, injection
    signatures, URL blocklist entries, chain patterns) with a cryptographic
    signature for integrity verification.
    """

    bundle_id: UUID = Field(default_factory=uuid4)
    manifest: RuleBundleManifest
    rules: list[BundleRule] = Field(default_factory=list)
    status: BundleStatus = Field(default=BundleStatus.PENDING_REVIEW)
    signature: str = Field(
        default="",
        description="Base64-encoded Ed25519 signature of the canonical bundle content",
    )
    signing_key_id: str = Field(
        default="", description="Key ID of the Ed25519 public key used for verification"
    )
    verified: bool = Field(default=False, description="Whether the signature has been verified")
    loaded_at: datetime | None = Field(default=None, description="When the bundle was loaded")
    file_path: str = Field(default="", description="Source file path of the bundle")


class RuleBundleListResponse(BaseModel):
    """Response for listing loaded rule bundles."""

    bundles: list[RuleBundle] = Field(default_factory=list)
    total: int = Field(default=0)


class RuleBundleLoadRequest(BaseModel):
    """Request to load a rule bundle from a file path or inline YAML."""

    file_path: str | None = Field(default=None, description="Path to bundle YAML file")
    yaml_content: str | None = Field(default=None, description="Inline YAML content")
    verify_signature: bool = Field(
        default=True, description="Whether to verify the Ed25519 signature"
    )
    activate: bool = Field(
        default=False, description="Whether to activate the bundle immediately"
    )


class RuleBundleLoadResponse(BaseModel):
    """Response after loading a rule bundle."""

    bundle: RuleBundle
    rules_loaded: int = Field(default=0)
    rules_skipped: int = Field(default=0)
    warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# APEP-406: Security Assessment Engine
# ---------------------------------------------------------------------------


class AssessmentFinding(BaseModel):
    """A single finding from the security assessment engine."""

    finding_id: UUID = Field(default_factory=uuid4)
    category: AssessmentCategory
    phase: AssessmentPhase
    severity: AssessmentSeverity = Field(default=AssessmentSeverity.MEDIUM)
    title: str = Field(default="", description="Short finding title")
    description: str = Field(default="", description="Detailed finding description")
    recommendation: str = Field(default="", description="How to remediate")
    mitre_technique_id: str = Field(default="", description="MITRE ATT&CK technique ID")
    passed: bool = Field(default=False, description="Whether this check passed")
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Supporting evidence for the finding"
    )


class SecurityAssessmentRequest(BaseModel):
    """Request to run a security assessment."""

    phases: list[AssessmentPhase] = Field(
        default_factory=lambda: [
            AssessmentPhase.CONFIG_AUDIT,
            AssessmentPhase.ATTACK_SIMULATION,
            AssessmentPhase.DEPLOYMENT_PROBE,
        ],
        description="Which assessment phases to run",
    )
    categories: list[AssessmentCategory] | None = Field(
        default=None, description="Specific categories to assess (None = all)"
    )
    include_passed: bool = Field(
        default=True, description="Include passing checks in results"
    )


class SecurityAssessmentResult(BaseModel):
    """Full result from the security assessment engine."""

    assessment_id: UUID = Field(default_factory=uuid4)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = Field(default=None)
    phases_run: list[AssessmentPhase] = Field(default_factory=list)
    findings: list[AssessmentFinding] = Field(default_factory=list)
    total_checks: int = Field(default=0)
    passed_checks: int = Field(default=0)
    failed_checks: int = Field(default=0)
    critical_findings: int = Field(default=0)
    high_findings: int = Field(default=0)
    overall_score: float = Field(
        default=0.0, ge=0.0, le=100.0,
        description="Overall security score (0-100, higher is better)",
    )
    grade: str = Field(
        default="F",
        description="Letter grade: A (90+), B (80+), C (70+), D (60+), F (<60)",
    )
    latency_ms: int = Field(default=0, description="Total assessment latency")


# ---------------------------------------------------------------------------
# APEP-408: MITRE ATT&CK Technique Mapping
# ---------------------------------------------------------------------------


class MitreTechnique(BaseModel):
    """A single MITRE ATT&CK technique mapping."""

    technique_id: str = Field(..., description="MITRE technique ID (e.g. T1190)")
    technique_name: str = Field(default="", description="Human-readable technique name")
    tactic: MitreTactic | None = Field(default=None, description="Parent tactic")
    description: str = Field(default="", description="Technique description")
    url: str = Field(default="", description="MITRE ATT&CK URL")


class MitreTechniqueMap(BaseModel):
    """Complete mapping of event types / rule IDs to MITRE ATT&CK techniques."""

    techniques: dict[str, MitreTechnique] = Field(
        default_factory=dict,
        description="Map of technique_id -> MitreTechnique",
    )
    event_type_mappings: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Map of event_type -> list of technique_ids",
    )
    rule_id_mappings: dict[str, str] = Field(
        default_factory=dict,
        description="Map of rule_id -> technique_id",
    )
    last_updated: datetime = Field(default_factory=lambda: datetime.now(UTC))
