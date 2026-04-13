"""Data classification hierarchy and boundary models.

Sprint 31 — APEP-246: Data classification hierarchy:
    PUBLIC → INTERNAL → CONFIDENTIAL → PII → PHI → FINANCIAL

Sprint 31 — APEP-247: Data boundary enforcement:
    USER_ONLY → TEAM → ORGANISATION
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class DataClassification(StrEnum):
    """Ordered data classification levels.

    Hierarchy (lowest to highest sensitivity):
        PUBLIC < INTERNAL < CONFIDENTIAL < PII < PHI < FINANCIAL
    """

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    PII = "PII"
    PHI = "PHI"
    FINANCIAL = "FINANCIAL"


# Numeric ordering for comparison: higher number = higher sensitivity
CLASSIFICATION_LEVEL: dict[DataClassification, int] = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.PII: 3,
    DataClassification.PHI: 4,
    DataClassification.FINANCIAL: 5,
}

# Reverse lookup: level number → classification
LEVEL_TO_CLASSIFICATION: dict[int, DataClassification] = {
    v: k for k, v in CLASSIFICATION_LEVEL.items()
}


def classification_gte(
    agent_clearance: str, required: str
) -> bool:
    """Return True if the agent's clearance level is >= the required classification.

    Both arguments are classification level strings (e.g. ``"PII"``).
    Unknown levels default to ``PUBLIC`` (most permissive for agent, least
    for requirement).
    """
    agent_level = CLASSIFICATION_LEVEL.get(
        DataClassification(agent_clearance)
        if agent_clearance in DataClassification.__members__
        else DataClassification.PUBLIC,
        0,
    )
    required_level = CLASSIFICATION_LEVEL.get(
        DataClassification(required)
        if required in DataClassification.__members__
        else DataClassification.PUBLIC,
        0,
    )
    return agent_level >= required_level


class DataBoundary(StrEnum):
    """Data access scope boundaries.

    Hierarchy (narrowest to broadest):
        USER_ONLY < TEAM < ORGANISATION
    """

    USER_ONLY = "USER_ONLY"
    TEAM = "TEAM"
    ORGANISATION = "ORGANISATION"


BOUNDARY_LEVEL: dict[DataBoundary, int] = {
    DataBoundary.USER_ONLY: 0,
    DataBoundary.TEAM: 1,
    DataBoundary.ORGANISATION: 2,
}


def boundary_gte(agent_boundary: str, required: str) -> bool:
    """Return True if the agent's boundary scope is >= the required scope.

    Unknown levels default to ``USER_ONLY``.
    """
    agent_level = BOUNDARY_LEVEL.get(
        DataBoundary(agent_boundary)
        if agent_boundary in DataBoundary.__members__
        else DataBoundary.USER_ONLY,
        0,
    )
    required_level = BOUNDARY_LEVEL.get(
        DataBoundary(required)
        if required in DataBoundary.__members__
        else DataBoundary.USER_ONLY,
        0,
    )
    return agent_level >= required_level


class DataClassificationRule(BaseModel):
    """Maps tool patterns to data classification levels and boundary scopes.

    Used by the DataClassificationEngine to determine what classification
    level a tool call requires.
    """

    rule_id: UUID = Field(default_factory=uuid4)
    tool_pattern: str = Field(..., description="Glob pattern matching tool names")
    classification: DataClassification = Field(
        default=DataClassification.PUBLIC,
        description="Required data classification level for this tool",
    )
    boundary: DataBoundary = Field(
        default=DataBoundary.ORGANISATION,
        description="Required data boundary scope",
    )
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
