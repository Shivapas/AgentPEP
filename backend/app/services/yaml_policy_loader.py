"""YAML policy loader — Sprint 30 (APEP-234 / APEP-235).

Parses YAML policy files, validates them against JSON Schema, and hydrates
Pydantic model objects.  Supports both single-file bundles and the directory
convention (APEP-235):

    policies/
      roles.yaml
      rules.yaml
      risk.yaml
      taint.yaml
      classifications.yaml

Usage::

    loader = YAMLPolicyLoader()
    bundle = loader.load_directory("policies/")
    bundle = loader.load_bundle("policy.yaml")
    bundle = loader.load_yaml_string(yaml_text)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import jsonschema
import yaml

from app.models.policy import (
    AgentRole,
    InjectionSignature,
    PolicyRule,
    RiskModelConfig,
    RiskWeightConfig,
    SanitisationGate,
)
from app.services.yaml_policy_schema import (
    CLASSIFICATIONS_SCHEMA,
    FILE_SCHEMA_MAP,
    POLICY_BUNDLE_SCHEMA,
    RISK_SCHEMA,
    ROLES_SCHEMA,
    RULES_SCHEMA,
    TAINT_SCHEMA,
)

logger = logging.getLogger(__name__)


def _log_info(msg: str, **kwargs: Any) -> None:
    """Log an info message with optional structured fields."""
    if kwargs:
        logger.info("%s %s", msg, kwargs)
    else:
        logger.info(msg)


def _log_warning(msg: str, **kwargs: Any) -> None:
    """Log a warning message with optional structured fields."""
    if kwargs:
        logger.warning("%s %s", msg, kwargs)
    else:
        logger.warning(msg)

# ---------------------------------------------------------------------------
# Data classification model (lightweight — no DB persistence needed yet)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DataClassificationLevel:
    """A data sensitivity level (e.g. PUBLIC, INTERNAL, CONFIDENTIAL)."""

    name: str
    rank: int
    description: str = ""


@dataclass(frozen=True)
class ToolClassification:
    """Maps a tool glob pattern to a data classification level."""

    tool_pattern: str
    classification: str
    description: str = ""


# ---------------------------------------------------------------------------
# Policy bundle — the hydrated result
# ---------------------------------------------------------------------------


@dataclass
class PolicyBundle:
    """Hydrated policy objects from YAML files."""

    version: str = "1.0"
    roles: list[AgentRole] = field(default_factory=list)
    rules: list[PolicyRule] = field(default_factory=list)
    risk_model: RiskModelConfig | None = None
    sanitisation_gates: list[SanitisationGate] = field(default_factory=list)
    injection_signatures: list[InjectionSignature] = field(default_factory=list)
    classification_levels: list[DataClassificationLevel] = field(default_factory=list)
    tool_classifications: list[ToolClassification] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return (
            not self.roles
            and not self.rules
            and self.risk_model is None
            and not self.sanitisation_gates
            and not self.injection_signatures
            and not self.classification_levels
            and not self.tool_classifications
        )


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------


class PolicyValidationError(Exception):
    """Raised when a YAML policy file fails JSON Schema validation."""

    def __init__(self, errors: list[str], file_name: str = "") -> None:
        self.errors = errors
        self.file_name = file_name
        detail = f" in '{file_name}'" if file_name else ""
        msg = f"Policy validation failed{detail}: {'; '.join(errors[:5])}"
        if len(errors) > 5:
            msg += f" ... and {len(errors) - 5} more"
        super().__init__(msg)


# ---------------------------------------------------------------------------
# Hydration helpers
# ---------------------------------------------------------------------------


def _hydrate_roles(data: list[dict[str, Any]]) -> list[AgentRole]:
    """Convert raw role dicts to AgentRole models."""
    roles: list[AgentRole] = []
    for r in data:
        roles.append(
            AgentRole(
                role_id=r["role_id"],
                name=r["name"],
                parent_roles=r.get("parent_roles", []),
                allowed_tools=r.get("allowed_tools", []),
                denied_tools=r.get("denied_tools", []),
                max_risk_threshold=r.get("max_risk_threshold", 1.0),
                enabled=r.get("enabled", True),
            )
        )
    return roles


def _hydrate_rules(data: list[dict[str, Any]]) -> list[PolicyRule]:
    """Convert raw rule dicts to PolicyRule models."""
    from app.models.policy import ArgValidator, RateLimit, RateLimitType

    rules: list[PolicyRule] = []
    for r in data:
        rate_limit = None
        if rl := r.get("rate_limit"):
            rate_limit = RateLimit(
                count=rl["count"],
                window_s=rl["window_s"],
                limiter_type=RateLimitType(rl.get("limiter_type", "SLIDING_WINDOW")),
            )

        arg_validators = []
        for av in r.get("arg_validators", []):
            arg_validators.append(
                ArgValidator(
                    arg_name=av["arg_name"],
                    json_schema=av.get("json_schema"),
                    regex_pattern=av.get("regex_pattern"),
                    allowlist=av.get("allowlist"),
                    blocklist=av.get("blocklist"),
                )
            )

        rules.append(
            PolicyRule(
                rule_id=r.get("rule_id", uuid4()),
                name=r["name"],
                agent_role=r.get("agent_role", []),
                tool_pattern=r["tool_pattern"],
                action=r["action"],
                taint_check=r.get("taint_check", False),
                risk_threshold=r.get("risk_threshold", 1.0),
                rate_limit=rate_limit,
                arg_validators=arg_validators,
                priority=r.get("priority", 100),
                enabled=r.get("enabled", True),
            )
        )
    return rules


def _hydrate_risk_model(data: dict[str, Any]) -> RiskModelConfig:
    """Convert raw risk dict to RiskModelConfig model."""
    default_weights = data.get("default_weights", {})
    role_overrides = {}
    for role_id, w in data.get("role_overrides", {}).items():
        role_overrides[role_id] = RiskWeightConfig(**w)

    return RiskModelConfig(
        model_id=data.get("model_id", "default"),
        default_weights=RiskWeightConfig(**default_weights) if default_weights else RiskWeightConfig(),
        role_overrides=role_overrides,
        escalation_threshold=data.get("escalation_threshold", 0.7),
        enabled=data.get("enabled", True),
    )


def _hydrate_sanitisation_gates(data: list[dict[str, Any]]) -> list[SanitisationGate]:
    """Convert raw gate dicts to SanitisationGate models."""
    gates: list[SanitisationGate] = []
    for g in data:
        gates.append(
            SanitisationGate(
                gate_id=g.get("gate_id", uuid4()),
                name=g["name"],
                function_pattern=g["function_pattern"],
                downgrades_from=g["downgrades_from"],
                downgrades_to=g["downgrades_to"],
                requires_approval=g.get("requires_approval", False),
                enabled=g.get("enabled", True),
            )
        )
    return gates


def _hydrate_injection_signatures(data: list[dict[str, Any]]) -> list[InjectionSignature]:
    """Convert raw signature dicts to InjectionSignature models."""
    sigs: list[InjectionSignature] = []
    for s in data:
        sigs.append(
            InjectionSignature(
                signature_id=s["signature_id"],
                category=s["category"],
                pattern=s["pattern"],
                severity=s.get("severity", "HIGH"),
                description=s.get("description", ""),
            )
        )
    return sigs


def _hydrate_classification_levels(data: list[dict[str, Any]]) -> list[DataClassificationLevel]:
    """Convert raw level dicts to DataClassificationLevel objects."""
    return [
        DataClassificationLevel(
            name=d["name"],
            rank=d["rank"],
            description=d.get("description", ""),
        )
        for d in data
    ]


def _hydrate_tool_classifications(data: list[dict[str, Any]]) -> list[ToolClassification]:
    """Convert raw tool-classification dicts to ToolClassification objects."""
    return [
        ToolClassification(
            tool_pattern=d["tool_pattern"],
            classification=d["classification"],
            description=d.get("description", ""),
        )
        for d in data
    ]


# ---------------------------------------------------------------------------
# YAML Policy Loader
# ---------------------------------------------------------------------------


class YAMLPolicyLoader:
    """Load, validate, and hydrate YAML policy files (APEP-234)."""

    # Maximum YAML payload size (1 MB)
    MAX_PAYLOAD_BYTES = 1_048_576

    def validate_yaml(
        self, data: dict[str, Any], schema: dict, file_name: str = ""
    ) -> list[str]:
        """Validate parsed YAML data against a JSON Schema.

        Returns a list of error messages (empty if valid).
        """
        validator = jsonschema.Draft202012Validator(schema)
        errors: list[str] = []
        for err in validator.iter_errors(data):
            path = ".".join(str(p) for p in err.absolute_path) if err.absolute_path else "(root)"
            errors.append(f"{path}: {err.message}")
        return errors

    def parse_yaml(self, content: str | bytes, file_name: str = "") -> dict[str, Any]:
        """Parse YAML string into a dict. Raises PolicyValidationError on failure."""
        if isinstance(content, bytes):
            if len(content) > self.MAX_PAYLOAD_BYTES:
                raise PolicyValidationError(
                    [f"Payload exceeds max size ({self.MAX_PAYLOAD_BYTES} bytes)"],
                    file_name,
                )
            content = content.decode("utf-8")

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise PolicyValidationError([f"YAML parse error: {exc}"], file_name) from exc

        if not isinstance(data, dict):
            raise PolicyValidationError(["YAML root must be a mapping"], file_name)
        return data

    def load_and_validate(
        self, content: str | bytes, schema: dict, file_name: str = ""
    ) -> dict[str, Any]:
        """Parse YAML and validate against schema. Raises on failure."""
        data = self.parse_yaml(content, file_name)
        errors = self.validate_yaml(data, schema, file_name)
        if errors:
            raise PolicyValidationError(errors, file_name)
        return data

    def hydrate_bundle(self, data: dict[str, Any]) -> PolicyBundle:
        """Hydrate a unified policy bundle dict into a PolicyBundle."""
        bundle = PolicyBundle(version=data.get("version", "1.0"))

        if "roles" in data:
            bundle.roles = _hydrate_roles(data["roles"])

        if "rules" in data:
            bundle.rules = _hydrate_rules(data["rules"])

        if "risk_model" in data and data["risk_model"]:
            bundle.risk_model = _hydrate_risk_model(data["risk_model"])

        if "sanitisation_gates" in data:
            bundle.sanitisation_gates = _hydrate_sanitisation_gates(data["sanitisation_gates"])

        if "injection_signatures" in data:
            bundle.injection_signatures = _hydrate_injection_signatures(
                data["injection_signatures"]
            )

        if "classification_levels" in data:
            bundle.classification_levels = _hydrate_classification_levels(
                data["classification_levels"]
            )

        if "tool_classifications" in data:
            bundle.tool_classifications = _hydrate_tool_classifications(
                data["tool_classifications"]
            )

        return bundle

    def load_bundle(self, path: str | Path) -> PolicyBundle:
        """Load a unified policy bundle YAML file (APEP-234).

        Validates against POLICY_BUNDLE_SCHEMA and returns a hydrated PolicyBundle.
        """
        path = Path(path)
        content = path.read_bytes()
        data = self.load_and_validate(content, POLICY_BUNDLE_SCHEMA, path.name)
        return self.hydrate_bundle(data)

    def load_yaml_string(self, content: str | bytes) -> PolicyBundle:
        """Load a unified policy bundle from a YAML string."""
        data = self.load_and_validate(content, POLICY_BUNDLE_SCHEMA, "<string>")
        return self.hydrate_bundle(data)

    # -----------------------------------------------------------------------
    # APEP-235: Directory convention loading
    # -----------------------------------------------------------------------

    def load_directory(self, directory: str | Path) -> PolicyBundle:
        """Load policies from a directory following the convention (APEP-235).

        Expects files like:
            policies/roles.yaml
            policies/rules.yaml
            policies/risk.yaml
            policies/taint.yaml
            policies/classifications.yaml

        All files are optional — only files present are loaded and merged.
        """
        directory = Path(directory)
        if not directory.is_dir():
            raise PolicyValidationError(
                [f"Policy directory not found: {directory}"],
                str(directory),
            )

        bundle = PolicyBundle()
        loaded_files: list[str] = []

        for file_name, schema in FILE_SCHEMA_MAP.items():
            file_path = directory / file_name
            if not file_path.exists():
                continue

            content = file_path.read_bytes()
            if len(content) > self.MAX_PAYLOAD_BYTES:
                raise PolicyValidationError(
                    [f"File exceeds max size ({self.MAX_PAYLOAD_BYTES} bytes)"],
                    file_name,
                )

            data = self.load_and_validate(content, schema, file_name)
            self._merge_file_into_bundle(bundle, data, file_name)
            loaded_files.append(file_name)

        if not loaded_files:
            _log_warning("yaml_policy_empty_directory", directory=str(directory))

        _log_info(
            "yaml_policy_directory_loaded",
            directory=str(directory),
            files=loaded_files,
        )
        return bundle

    def _merge_file_into_bundle(
        self, bundle: PolicyBundle, data: dict[str, Any], file_name: str
    ) -> None:
        """Merge data from a single file into the bundle."""
        base = file_name.removesuffix(".yaml").removesuffix(".yml")

        if base == "roles" and "roles" in data:
            bundle.roles = _hydrate_roles(data["roles"])
            bundle.version = data.get("version", bundle.version)

        elif base == "rules" and "rules" in data:
            bundle.rules = _hydrate_rules(data["rules"])

        elif base == "risk" and "risk_model" in data:
            bundle.risk_model = _hydrate_risk_model(data["risk_model"])

        elif base == "taint":
            if "sanitisation_gates" in data:
                bundle.sanitisation_gates = _hydrate_sanitisation_gates(
                    data["sanitisation_gates"]
                )
            if "injection_signatures" in data:
                bundle.injection_signatures = _hydrate_injection_signatures(
                    data["injection_signatures"]
                )

        elif base == "classifications":
            if "levels" in data:
                bundle.classification_levels = _hydrate_classification_levels(data["levels"])
            if "tool_classifications" in data:
                bundle.tool_classifications = _hydrate_tool_classifications(
                    data["tool_classifications"]
                )

    # -----------------------------------------------------------------------
    # Validation-only helpers
    # -----------------------------------------------------------------------

    def validate_file(self, path: str | Path) -> list[str]:
        """Validate a single YAML policy file without hydrating. Returns errors."""
        path = Path(path)
        schema = FILE_SCHEMA_MAP.get(path.name, POLICY_BUNDLE_SCHEMA)
        try:
            content = path.read_bytes()
            data = self.parse_yaml(content, path.name)
        except PolicyValidationError as exc:
            return exc.errors
        return self.validate_yaml(data, schema, path.name)

    def validate_directory(self, directory: str | Path) -> dict[str, list[str]]:
        """Validate all YAML files in a policy directory. Returns {file: errors}."""
        directory = Path(directory)
        results: dict[str, list[str]] = {}
        for file_name in FILE_SCHEMA_MAP:
            file_path = directory / file_name
            if file_path.exists():
                results[file_name] = self.validate_file(file_path)
        return results
