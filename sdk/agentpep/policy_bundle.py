"""Policy bundle for SDK offline evaluation with full policy stack (APEP-238).

Sprint 30: Bundles the complete policy stack (RBAC roles, rules, risk config,
taint policy, injection signatures) into a single serializable object that
can be loaded by the enhanced OfflineEvaluator for local evaluation without
a running AgentPEP server.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class BundledRole:
    """A role from the policy bundle."""

    role_id: str
    name: str
    parent_roles: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    denied_tools: list[str] = field(default_factory=list)
    max_risk_threshold: float = 1.0
    enabled: bool = True


@dataclass
class BundledRule:
    """A rule from the policy bundle."""

    name: str
    tool_pattern: str
    action: str = "DENY"
    agent_roles: list[str] = field(default_factory=list)
    taint_check: bool = False
    risk_threshold: float = 1.0
    priority: int = 100
    enabled: bool = True


@dataclass
class BundledRiskConfig:
    """Risk scoring configuration from the policy bundle."""

    escalation_threshold: float = 0.7
    weights: dict[str, float] = field(default_factory=lambda: {
        "operation_type": 0.25,
        "data_sensitivity": 0.25,
        "taint": 0.20,
        "session_accumulated": 0.10,
        "delegation_depth": 0.20,
    })


@dataclass
class BundledTaintPolicy:
    """Taint policy from the bundle."""

    max_hop_depth: int = 10
    quarantine_on_injection: bool = True


@dataclass
class InjectionPattern:
    """A compiled injection detection pattern."""

    pattern_id: str
    category: str
    regex: re.Pattern[str]
    severity: str = "HIGH"


@dataclass
class PolicyBundle:
    """Complete policy stack bundle for offline evaluation.

    Contains all the information needed to evaluate tool calls locally:
    roles, rules, risk config, taint policy, and injection patterns.
    """

    schema_version: str = "1.0"
    roles: list[BundledRole] = field(default_factory=list)
    rules: list[BundledRule] = field(default_factory=list)
    risk_config: BundledRiskConfig = field(default_factory=BundledRiskConfig)
    taint_policy: BundledTaintPolicy = field(default_factory=BundledTaintPolicy)
    injection_patterns: list[InjectionPattern] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, content: str | bytes) -> PolicyBundle:
        """Load a PolicyBundle from YAML content."""
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise ValueError("YAML must be a mapping")
        return cls.from_dict(data)

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> PolicyBundle:
        """Load a PolicyBundle from a YAML file."""
        path = Path(path)
        return cls.from_yaml(path.read_bytes())

    @classmethod
    def from_yaml_directory(cls, directory: str | Path) -> PolicyBundle:
        """Load a PolicyBundle from a policy-as-code directory."""
        directory = Path(directory)
        combined: dict[str, Any] = {"schema_version": "1.0"}

        for filename, key in [
            ("roles.yaml", "roles"),
            ("rules.yaml", "rules"),
            ("risk.yaml", "risk"),
            ("taint.yaml", "taint"),
            ("metadata.yaml", "metadata"),
        ]:
            filepath = directory / filename
            if filepath.is_file():
                data = yaml.safe_load(filepath.read_bytes())
                if isinstance(data, dict):
                    # Unwrap if nested under the section key
                    combined[key] = data.get(key, data)
                elif isinstance(data, list):
                    combined[key] = data

        return cls.from_dict(combined)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyBundle:
        """Build a PolicyBundle from a parsed dict."""
        bundle = cls(
            schema_version=data.get("schema_version", "1.0"),
            metadata=data.get("metadata", {}),
        )

        # Roles
        for r in data.get("roles", []):
            bundle.roles.append(BundledRole(
                role_id=r["role_id"],
                name=r.get("name", r["role_id"]),
                parent_roles=r.get("parent_roles", []),
                allowed_tools=r.get("allowed_tools", []),
                denied_tools=r.get("denied_tools", []),
                max_risk_threshold=r.get("max_risk_threshold", 1.0),
                enabled=r.get("enabled", True),
            ))

        # Rules
        for r in data.get("rules", []):
            bundle.rules.append(BundledRule(
                name=r["name"],
                tool_pattern=r["tool_pattern"],
                action=r.get("action", "DENY"),
                agent_roles=r.get("agent_roles", []),
                taint_check=r.get("taint_check", False),
                risk_threshold=r.get("risk_threshold", 1.0),
                priority=r.get("priority", 100),
                enabled=r.get("enabled", True),
            ))

        # Risk config
        risk_data = data.get("risk", {})
        if risk_data:
            weights = risk_data.get("default_weights", {})
            bundle.risk_config = BundledRiskConfig(
                escalation_threshold=risk_data.get("escalation_threshold", 0.7),
                weights={
                    "operation_type": weights.get("operation_type", 0.25),
                    "data_sensitivity": weights.get("data_sensitivity", 0.25),
                    "taint": weights.get("taint", 0.20),
                    "session_accumulated": weights.get("session_accumulated", 0.10),
                    "delegation_depth": weights.get("delegation_depth", 0.20),
                },
            )

        # Taint policy
        taint_data = data.get("taint", {})
        if taint_data:
            bundle.taint_policy = BundledTaintPolicy(
                max_hop_depth=taint_data.get("max_hop_depth", 10),
                quarantine_on_injection=taint_data.get("quarantine_on_injection", True),
            )

        # Injection patterns
        for p in data.get("injection_patterns", []):
            try:
                bundle.injection_patterns.append(InjectionPattern(
                    pattern_id=p["pattern_id"],
                    category=p.get("category", "unknown"),
                    regex=re.compile(p["pattern"]),
                    severity=p.get("severity", "HIGH"),
                ))
            except re.error:
                logger.warning("Invalid injection pattern regex: %s", p.get("pattern"))

        return bundle

    def to_dict(self) -> dict[str, Any]:
        """Serialize the bundle to a dict suitable for YAML/JSON export."""
        return {
            "schema_version": self.schema_version,
            "metadata": self.metadata,
            "roles": [
                {
                    "role_id": r.role_id,
                    "name": r.name,
                    "parent_roles": r.parent_roles,
                    "allowed_tools": r.allowed_tools,
                    "denied_tools": r.denied_tools,
                    "max_risk_threshold": r.max_risk_threshold,
                    "enabled": r.enabled,
                }
                for r in self.roles
            ],
            "rules": [
                {
                    "name": r.name,
                    "tool_pattern": r.tool_pattern,
                    "action": r.action,
                    "agent_roles": r.agent_roles,
                    "taint_check": r.taint_check,
                    "risk_threshold": r.risk_threshold,
                    "priority": r.priority,
                    "enabled": r.enabled,
                }
                for r in self.rules
            ],
            "risk": {
                "escalation_threshold": self.risk_config.escalation_threshold,
                "default_weights": self.risk_config.weights,
            },
            "taint": {
                "max_hop_depth": self.taint_policy.max_hop_depth,
                "quarantine_on_injection": self.taint_policy.quarantine_on_injection,
            },
        }

    def to_yaml(self) -> str:
        """Serialize the bundle to YAML."""
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)

    def to_json(self) -> str:
        """Serialize the bundle to JSON."""
        return json.dumps(self.to_dict(), indent=2, default=str)
