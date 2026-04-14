"""Sprint 43 models -- Enterprise Scope Pattern Library.

APEP-342: Pydantic models and MongoDB schema for the enterprise scope
pattern library.  Each ``ScopePatternTemplate`` is a curated,
reusable scope pattern with metadata (category, description, risk level)
that organizations can browse, clone, and apply to MissionPlans.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# APEP-342: Enums
# ---------------------------------------------------------------------------


class PatternCategory(StrEnum):
    """Top-level categories for enterprise scope patterns."""

    DATA_ACCESS = "data_access"
    CODE_EXECUTION = "code_execution"
    NETWORK = "network"
    SECRETS = "secrets"
    ADMIN = "admin"
    MESSAGING = "messaging"
    DEPLOYMENT = "deployment"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"


class PatternRiskLevel(StrEnum):
    """Indicative risk level for a scope pattern template."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# APEP-342: ScopePatternTemplate
# ---------------------------------------------------------------------------


class ScopePatternTemplate(BaseModel):
    """A curated enterprise scope pattern template.

    Templates are stored in MongoDB and exposed via the pattern library API.
    Each template contains one or more scope patterns in
    ``verb:namespace:resource`` notation along with human-readable metadata.
    """

    template_id: UUID = Field(default_factory=uuid4, description="Unique template ID")
    name: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Human-readable name (e.g. 'Read-Only Public Data')",
    )
    description: str = Field(
        default="",
        max_length=2000,
        description="Detailed description of what this pattern permits/restricts",
    )
    category: PatternCategory = Field(
        ...,
        description="Top-level category for browsing/filtering",
    )
    risk_level: PatternRiskLevel = Field(
        default=PatternRiskLevel.MEDIUM,
        description="Indicative risk level of activities this pattern permits",
    )
    scope_patterns: list[str] = Field(
        ...,
        min_length=1,
        description="Scope patterns in verb:namespace:resource notation",
    )
    checkpoint_patterns: list[str] = Field(
        default_factory=list,
        description="Recommended requires_checkpoint patterns for this template",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Searchable tags (e.g. 'finance', 'pci-dss', 'read-only')",
    )
    use_cases: list[str] = Field(
        default_factory=list,
        description="Example use cases where this template applies",
    )
    author: str = Field(
        default="agentpep",
        max_length=200,
        description="Author or organization that created this template",
    )
    version: str = Field(
        default="1.0",
        max_length=20,
        description="Template version string",
    )
    enabled: bool = Field(
        default=True,
        description="Whether this template is visible in the library",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# APEP-342: API Request/Response schemas
# ---------------------------------------------------------------------------


class CreatePatternTemplateRequest(BaseModel):
    """Request body for POST /v1/scope/patterns."""

    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    category: PatternCategory
    risk_level: PatternRiskLevel = PatternRiskLevel.MEDIUM
    scope_patterns: list[str] = Field(..., min_length=1)
    checkpoint_patterns: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    use_cases: list[str] = Field(default_factory=list)
    author: str = Field(default="agentpep", max_length=200)


class UpdatePatternTemplateRequest(BaseModel):
    """Request body for PATCH /v1/scope/patterns/{template_id}."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    category: PatternCategory | None = None
    risk_level: PatternRiskLevel | None = None
    scope_patterns: list[str] | None = Field(default=None, min_length=1)
    checkpoint_patterns: list[str] | None = None
    tags: list[str] | None = None
    use_cases: list[str] | None = None
    enabled: bool | None = None


class PatternTemplateResponse(BaseModel):
    """Response body for a single pattern template."""

    template_id: UUID
    name: str
    description: str
    category: PatternCategory
    risk_level: PatternRiskLevel
    scope_patterns: list[str]
    checkpoint_patterns: list[str]
    tags: list[str]
    use_cases: list[str]
    author: str
    version: str
    enabled: bool
    created_at: datetime
    updated_at: datetime


class PatternTemplateListResponse(BaseModel):
    """Paginated response for GET /v1/scope/patterns."""

    templates: list[PatternTemplateResponse] = Field(default_factory=list)
    total: int = 0
    offset: int = 0
    limit: int = 50


# ---------------------------------------------------------------------------
# APEP-342: Scope Simulation Models (used by simulator UI & CLI)
# ---------------------------------------------------------------------------


class ScopeSimulateRequest(BaseModel):
    """Request body for POST /v1/scope/simulate.

    Simulates what decision the scope filters would produce for a given
    tool call against a plan's scope configuration.
    """

    plan_id: UUID | None = Field(
        default=None,
        description="Existing plan ID to simulate against (mutually exclusive with inline scope)",
    )
    scope: list[str] | None = Field(
        default=None,
        description="Inline scope patterns to simulate (used when plan_id is not set)",
    )
    requires_checkpoint: list[str] | None = Field(
        default=None,
        description="Inline checkpoint patterns to simulate",
    )
    tool_name: str = Field(
        ...,
        min_length=1,
        description="Tool name to check",
    )
    action: str = Field(
        default="",
        description="Human-readable description of the simulated action",
    )


class ScopeSimulateResult(BaseModel):
    """Response body for POST /v1/scope/simulate."""

    tool_name: str
    action: str = ""
    scope_allowed: bool = Field(
        ..., description="Whether the tool is within the plan's allowed scope"
    )
    scope_matched_pattern: str | None = Field(
        default=None, description="The scope pattern that matched"
    )
    scope_reason: str = Field(default="", description="Explanation of scope check")
    checkpoint_triggered: bool = Field(
        ..., description="Whether the tool triggers a checkpoint"
    )
    checkpoint_matched_pattern: str | None = Field(
        default=None, description="The checkpoint pattern that matched"
    )
    checkpoint_reason: str = Field(
        default="", description="Explanation of checkpoint check"
    )
    effective_decision: str = Field(
        ...,
        description="Final decision: ALLOW, DENY, or ESCALATE",
    )
    compiled_rbac_patterns: list[str] = Field(
        default_factory=list,
        description="RBAC tool-name globs produced by scope compilation",
    )
