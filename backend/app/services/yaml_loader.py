"""YAML policy loader — parse, validate, and hydrate policy objects (APEP-234).

Sprint 30: Loads YAML policy files, validates them against the JSON Schema
defined in APEP-233, and hydrates them into the Pydantic models used by the
policy evaluation engine.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from uuid import uuid4

import jsonschema
import yaml

from app.models.policy import (
    AgentRole,
    ArgValidator,
    PolicyRule,
    RateLimit,
    RateLimitType,
    RiskModelConfig,
    RiskWeightConfig,
    SanitisationGate,
    TaintLevel,
)
from app.models.yaml_policy import (
    YAML_POLICY_JSON_SCHEMA,
    YAMLPolicyDocument,
    YAMLRiskConfig,
    YAMLRuleDefinition,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------


class YAMLPolicyValidationError(Exception):
    """Raised when a YAML policy document fails validation."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(f"YAML policy validation failed: {'; '.join(errors)}")


# ---------------------------------------------------------------------------
# Core loader
# ---------------------------------------------------------------------------


class YAMLPolicyLoader:
    """Parse, validate, and hydrate YAML policy documents.

    Supports loading from:
    - A single YAML string/file (combined document)
    - A policy-as-code directory (APEP-235)
    """

    # Max YAML payload size: 2 MB
    MAX_PAYLOAD_BYTES = 2_097_152

    def validate_schema(self, data: dict[str, Any]) -> list[str]:
        """Validate raw dict against the JSON Schema. Returns list of errors."""
        validator = jsonschema.Draft202012Validator(YAML_POLICY_JSON_SCHEMA)
        errors: list[str] = []
        for error in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
            path = ".".join(str(p) for p in error.absolute_path)
            msg = f"{path}: {error.message}" if path else error.message
            errors.append(msg)
        return errors

    def parse_yaml(self, content: str | bytes) -> dict[str, Any]:
        """Parse raw YAML content into a dict.

        Raises YAMLPolicyValidationError on parse failure or oversized input.
        """
        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
        else:
            content_bytes = content

        if len(content_bytes) > self.MAX_PAYLOAD_BYTES:
            raise YAMLPolicyValidationError(
                [f"Payload exceeds maximum size of {self.MAX_PAYLOAD_BYTES} bytes"]
            )

        try:
            data = yaml.safe_load(content_bytes)
        except yaml.YAMLError as exc:
            raise YAMLPolicyValidationError([f"Invalid YAML syntax: {exc}"]) from exc

        if not isinstance(data, dict):
            raise YAMLPolicyValidationError(["YAML document must be a mapping (dict)"])

        return data

    def load_and_validate(self, content: str | bytes) -> YAMLPolicyDocument:
        """Parse YAML, validate against JSON Schema, and hydrate into Pydantic model.

        This is the main entry point for loading a single YAML document.
        """
        data = self.parse_yaml(content)

        errors = self.validate_schema(data)
        if errors:
            raise YAMLPolicyValidationError(errors)

        return YAMLPolicyDocument.model_validate(data)

    def load_file(self, path: str | Path) -> YAMLPolicyDocument:
        """Load and validate a YAML policy file from disk."""
        path = Path(path)
        if not path.is_file():
            raise YAMLPolicyValidationError([f"File not found: {path}"])

        content = path.read_bytes()
        return self.load_and_validate(content)

    # ------------------------------------------------------------------
    # Hydration: YAML models → backend policy objects
    # ------------------------------------------------------------------

    def hydrate_roles(self, doc: YAMLPolicyDocument) -> list[AgentRole]:
        """Convert YAML role definitions to backend AgentRole objects."""
        roles: list[AgentRole] = []
        for r in doc.roles:
            roles.append(
                AgentRole(
                    role_id=r.role_id,
                    name=r.name,
                    parent_roles=r.parent_roles,
                    allowed_tools=r.allowed_tools,
                    denied_tools=r.denied_tools,
                    max_risk_threshold=r.max_risk_threshold,
                    enabled=r.enabled,
                )
            )
        return roles

    def hydrate_rules(self, doc: YAMLPolicyDocument) -> list[PolicyRule]:
        """Convert YAML rule definitions to backend PolicyRule objects."""
        rules: list[PolicyRule] = []
        for r in doc.rules:
            rate_limit = None
            if r.rate_limit:
                rate_limit = RateLimit(
                    count=r.rate_limit.count,
                    window_s=r.rate_limit.window_seconds,
                    limiter_type=RateLimitType(r.rate_limit.algorithm),
                )

            arg_validators = [
                ArgValidator(
                    arg_name=v.arg_name,
                    json_schema=v.json_schema,
                    regex_pattern=v.regex_pattern,
                    allowlist=v.allowlist,
                    blocklist=v.blocklist,
                )
                for v in r.arg_validators
            ]

            rules.append(
                PolicyRule(
                    rule_id=r.rule_id if r.rule_id else uuid4(),
                    name=r.name,
                    agent_role=r.agent_roles,
                    tool_pattern=r.tool_pattern,
                    action=r.action,
                    taint_check=r.taint_check,
                    risk_threshold=r.risk_threshold,
                    rate_limit=rate_limit,
                    arg_validators=arg_validators,
                    priority=r.priority,
                    enabled=r.enabled,
                )
            )
        return rules

    def hydrate_risk_config(self, doc: YAMLPolicyDocument) -> RiskModelConfig:
        """Convert YAML risk config to backend RiskModelConfig."""
        rc = doc.risk
        default_weights = RiskWeightConfig(
            operation_type=rc.default_weights.operation_type,
            data_sensitivity=rc.default_weights.data_sensitivity,
            taint=rc.default_weights.taint,
            session_accumulated=rc.default_weights.session_accumulated,
            delegation_depth=rc.default_weights.delegation_depth,
        )

        role_overrides: dict[str, RiskWeightConfig] = {}
        for role_id, weights in rc.role_overrides.items():
            role_overrides[role_id] = RiskWeightConfig(
                operation_type=weights.operation_type,
                data_sensitivity=weights.data_sensitivity,
                taint=weights.taint,
                session_accumulated=weights.session_accumulated,
                delegation_depth=weights.delegation_depth,
            )

        return RiskModelConfig(
            model_id="yaml-policy",
            default_weights=default_weights,
            role_overrides=role_overrides,
            escalation_threshold=rc.escalation_threshold,
        )

    def hydrate_sanitisation_gates(self, doc: YAMLPolicyDocument) -> list[SanitisationGate]:
        """Convert YAML taint policy sanitisation gates to backend objects."""
        gates: list[SanitisationGate] = []
        for g in doc.taint.sanitisation_gates:
            gates.append(
                SanitisationGate(
                    name=g.name,
                    function_pattern=g.function_pattern,
                    downgrades_from=TaintLevel(g.downgrades_from),
                    downgrades_to=TaintLevel(g.downgrades_to),
                    requires_approval=g.requires_approval,
                )
            )
        return gates


# Module-level singleton
yaml_policy_loader = YAMLPolicyLoader()
