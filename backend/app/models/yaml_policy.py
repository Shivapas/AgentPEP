"""YAML-first policy schema models for declarative policy definition (APEP-233).

Sprint 30: Defines the YAML policy schema covering roles, rules, risk
thresholds, taint policies, and data classifications.  Each schema section
maps to a separate YAML file in the policy-as-code directory convention
(APEP-235) and is validated against a JSON Schema at parse time.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Schema version
# ---------------------------------------------------------------------------

YAML_POLICY_SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Data Classification (APEP-233)
# ---------------------------------------------------------------------------


class DataClassification(StrEnum):
    """Hierarchical data classification levels (lowest → highest sensitivity)."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    PII = "PII"
    PHI = "PHI"
    FINANCIAL = "FINANCIAL"


DATA_CLASSIFICATION_RANK: dict[DataClassification, int] = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.PII: 3,
    DataClassification.PHI: 4,
    DataClassification.FINANCIAL: 5,
}


# ---------------------------------------------------------------------------
# YAML Role Definition
# ---------------------------------------------------------------------------


class YAMLRoleDefinition(BaseModel):
    """Declarative role definition in YAML format."""

    role_id: str = Field(..., min_length=1, max_length=128, description="Unique role identifier")
    name: str = Field(..., min_length=1, max_length=256, description="Human-readable role name")
    parent_roles: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    max_risk_threshold: float = Field(default=1.0, ge=0.0, le=1.0)
    max_data_classification: DataClassification = Field(
        default=DataClassification.INTERNAL,
        description="Maximum data classification level this role can access",
    )
    enabled: bool = True


# ---------------------------------------------------------------------------
# YAML Rule Definition
# ---------------------------------------------------------------------------


class YAMLRateLimitDefinition(BaseModel):
    """Rate limit definition within a YAML rule."""

    count: int = Field(..., gt=0, le=100000)
    window_seconds: int = Field(..., gt=0, le=86400)
    algorithm: str = Field(default="SLIDING_WINDOW", pattern=r"^(SLIDING_WINDOW|FIXED_WINDOW)$")


class YAMLArgValidatorDefinition(BaseModel):
    """Argument validator definition within a YAML rule."""

    arg_name: str = Field(..., min_length=1)
    json_schema: dict[str, Any] | None = None
    regex_pattern: str | None = None
    allowlist: list[str] | None = None
    blocklist: list[str] | None = None


class YAMLRuleDefinition(BaseModel):
    """Declarative policy rule definition in YAML format."""

    rule_id: str = Field(
        default="",
        description="Optional stable rule identifier; auto-generated if empty",
    )
    name: str = Field(..., min_length=1, max_length=256)
    agent_roles: list[str] = Field(default_factory=list)
    tool_pattern: str = Field(..., min_length=1)
    action: str = Field(..., pattern=r"^(ALLOW|DENY|ESCALATE)$")
    taint_check: bool = False
    risk_threshold: float = Field(default=1.0, ge=0.0, le=1.0)
    data_classification: DataClassification | None = Field(
        default=None,
        description="Minimum data classification level required to trigger this rule",
    )
    rate_limit: YAMLRateLimitDefinition | None = None
    arg_validators: list[YAMLArgValidatorDefinition] = Field(default_factory=list)
    priority: int = Field(default=100, ge=1, le=10000)
    enabled: bool = True


# ---------------------------------------------------------------------------
# YAML Risk Configuration
# ---------------------------------------------------------------------------


class YAMLRiskWeights(BaseModel):
    """Risk factor weights in YAML format."""

    operation_type: float = Field(default=0.25, ge=0.0)
    data_sensitivity: float = Field(default=0.25, ge=0.0)
    taint: float = Field(default=0.20, ge=0.0)
    session_accumulated: float = Field(default=0.10, ge=0.0)
    delegation_depth: float = Field(default=0.20, ge=0.0)


class YAMLRiskConfig(BaseModel):
    """Declarative risk scoring configuration."""

    default_weights: YAMLRiskWeights = Field(default_factory=YAMLRiskWeights)
    role_overrides: dict[str, YAMLRiskWeights] = Field(default_factory=dict)
    escalation_threshold: float = Field(default=0.7, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# YAML Taint Policy
# ---------------------------------------------------------------------------


class YAMLSanitisationGate(BaseModel):
    """Sanitisation gate definition in YAML format."""

    name: str = Field(..., min_length=1)
    function_pattern: str = Field(..., min_length=1)
    downgrades_from: str = Field(..., pattern=r"^(TRUSTED|UNTRUSTED|QUARANTINE)$")
    downgrades_to: str = Field(..., pattern=r"^(TRUSTED|UNTRUSTED|QUARANTINE)$")
    requires_approval: bool = False


class YAMLTaintPolicy(BaseModel):
    """Declarative taint policy configuration."""

    max_hop_depth: int = Field(default=10, ge=1, le=100)
    quarantine_on_injection: bool = Field(default=True)
    sanitisation_gates: list[YAMLSanitisationGate] = Field(default_factory=list)
    auto_propagate_cross_agent: bool = Field(default=True)


# ---------------------------------------------------------------------------
# Top-Level Policy Document
# ---------------------------------------------------------------------------


class YAMLPolicyDocument(BaseModel):
    """Top-level container for a complete YAML policy definition.

    Each section maps to a separate file in the policy-as-code directory
    convention (APEP-235) or can be combined into a single document.
    """

    schema_version: str = Field(
        default=YAML_POLICY_SCHEMA_VERSION,
        description="Schema version for migration compatibility",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary metadata (author, description, labels)",
    )
    roles: list[YAMLRoleDefinition] = Field(default_factory=list)
    rules: list[YAMLRuleDefinition] = Field(default_factory=list)
    risk: YAMLRiskConfig = Field(default_factory=YAMLRiskConfig)
    taint: YAMLTaintPolicy = Field(default_factory=YAMLTaintPolicy)
    data_classifications: list[DataClassification] = Field(
        default_factory=lambda: list(DataClassification),
        description="Active data classification levels for this policy set",
    )

    @field_validator("schema_version")
    @classmethod
    def _validate_schema_version(cls, v: str) -> str:
        supported = {"1.0"}
        if v not in supported:
            raise ValueError(f"Unsupported schema_version '{v}'; supported: {supported}")
        return v


# ---------------------------------------------------------------------------
# JSON Schema for validation (APEP-233)
# ---------------------------------------------------------------------------


YAML_POLICY_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AgentPEP YAML Policy Schema v1.0",
    "type": "object",
    "properties": {
        "schema_version": {
            "type": "string",
            "enum": ["1.0"],
            "description": "Schema version identifier",
        },
        "metadata": {
            "type": "object",
            "additionalProperties": True,
        },
        "roles": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["role_id", "name"],
                "properties": {
                    "role_id": {"type": "string", "minLength": 1, "maxLength": 128},
                    "name": {"type": "string", "minLength": 1, "maxLength": 256},
                    "parent_roles": {"type": "array", "items": {"type": "string"}},
                    "allowed_tools": {"type": "array", "items": {"type": "string"}},
                    "denied_tools": {"type": "array", "items": {"type": "string"}},
                    "max_risk_threshold": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "max_data_classification": {
                        "type": "string",
                        "enum": ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "PII", "PHI", "FINANCIAL"],
                    },
                    "enabled": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
        },
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "tool_pattern", "action"],
                "properties": {
                    "rule_id": {"type": "string"},
                    "name": {"type": "string", "minLength": 1, "maxLength": 256},
                    "agent_roles": {"type": "array", "items": {"type": "string"}},
                    "tool_pattern": {"type": "string", "minLength": 1},
                    "action": {"type": "string", "enum": ["ALLOW", "DENY", "ESCALATE"]},
                    "taint_check": {"type": "boolean"},
                    "risk_threshold": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "data_classification": {
                        "type": "string",
                        "enum": ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "PII", "PHI", "FINANCIAL"],
                    },
                    "rate_limit": {
                        "type": "object",
                        "required": ["count", "window_seconds"],
                        "properties": {
                            "count": {"type": "integer", "minimum": 1, "maximum": 100000},
                            "window_seconds": {"type": "integer", "minimum": 1, "maximum": 86400},
                            "algorithm": {
                                "type": "string",
                                "enum": ["SLIDING_WINDOW", "FIXED_WINDOW"],
                            },
                        },
                        "additionalProperties": False,
                    },
                    "arg_validators": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["arg_name"],
                            "properties": {
                                "arg_name": {"type": "string", "minLength": 1},
                                "json_schema": {"type": "object"},
                                "regex_pattern": {"type": "string"},
                                "allowlist": {"type": "array", "items": {"type": "string"}},
                                "blocklist": {"type": "array", "items": {"type": "string"}},
                            },
                            "additionalProperties": False,
                        },
                    },
                    "priority": {"type": "integer", "minimum": 1, "maximum": 10000},
                    "enabled": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
        },
        "risk": {
            "type": "object",
            "properties": {
                "default_weights": {
                    "type": "object",
                    "properties": {
                        "operation_type": {"type": "number", "minimum": 0.0},
                        "data_sensitivity": {"type": "number", "minimum": 0.0},
                        "taint": {"type": "number", "minimum": 0.0},
                        "session_accumulated": {"type": "number", "minimum": 0.0},
                        "delegation_depth": {"type": "number", "minimum": 0.0},
                    },
                    "additionalProperties": False,
                },
                "role_overrides": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "object",
                        "properties": {
                            "operation_type": {"type": "number", "minimum": 0.0},
                            "data_sensitivity": {"type": "number", "minimum": 0.0},
                            "taint": {"type": "number", "minimum": 0.0},
                            "session_accumulated": {"type": "number", "minimum": 0.0},
                            "delegation_depth": {"type": "number", "minimum": 0.0},
                        },
                        "additionalProperties": False,
                    },
                },
                "escalation_threshold": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            },
            "additionalProperties": False,
        },
        "taint": {
            "type": "object",
            "properties": {
                "max_hop_depth": {"type": "integer", "minimum": 1, "maximum": 100},
                "quarantine_on_injection": {"type": "boolean"},
                "sanitisation_gates": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "function_pattern", "downgrades_from", "downgrades_to"],
                        "properties": {
                            "name": {"type": "string", "minLength": 1},
                            "function_pattern": {"type": "string", "minLength": 1},
                            "downgrades_from": {
                                "type": "string",
                                "enum": ["TRUSTED", "UNTRUSTED", "QUARANTINE"],
                            },
                            "downgrades_to": {
                                "type": "string",
                                "enum": ["TRUSTED", "UNTRUSTED", "QUARANTINE"],
                            },
                            "requires_approval": {"type": "boolean"},
                        },
                        "additionalProperties": False,
                    },
                },
                "auto_propagate_cross_agent": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        "data_classifications": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "PII", "PHI", "FINANCIAL"],
            },
        },
    },
    "additionalProperties": False,
}
