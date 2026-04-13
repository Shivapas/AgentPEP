"""Policy-as-code directory convention — load policies from filesystem (APEP-235).

Sprint 30: Supports a standard directory layout for GitOps workflows:

    policies/
    ├── roles.yaml       # Agent role definitions
    ├── rules.yaml       # Policy rule definitions
    ├── risk.yaml        # Risk scoring configuration
    ├── taint.yaml       # Taint tracking policy
    └── metadata.yaml    # Optional metadata (author, description, labels)

Each file is loaded, validated, and merged into a single YAMLPolicyDocument.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from app.models.yaml_policy import (
    YAML_POLICY_SCHEMA_VERSION,
    YAMLPolicyDocument,
    YAMLRiskConfig,
    YAMLTaintPolicy,
)
from app.services.yaml_loader import YAMLPolicyLoader, YAMLPolicyValidationError

logger = logging.getLogger(__name__)


# Standard file names in the policy-as-code directory
ROLES_FILE = "roles.yaml"
RULES_FILE = "rules.yaml"
RISK_FILE = "risk.yaml"
TAINT_FILE = "taint.yaml"
METADATA_FILE = "metadata.yaml"


class PolicyDirectoryLoader:
    """Load policies from a policy-as-code directory structure.

    Reads individual YAML files from the directory, merges them into a
    single YAMLPolicyDocument, and validates the combined document.
    """

    def __init__(self, loader: YAMLPolicyLoader | None = None) -> None:
        self._loader = loader or YAMLPolicyLoader()

    def load_directory(self, directory: str | Path) -> YAMLPolicyDocument:
        """Load and merge all policy files from the given directory.

        Raises YAMLPolicyValidationError if any file is invalid or the
        merged document fails validation.
        """
        directory = Path(directory)
        if not directory.is_dir():
            raise YAMLPolicyValidationError([f"Policy directory not found: {directory}"])

        combined: dict[str, Any] = {
            "schema_version": YAML_POLICY_SCHEMA_VERSION,
        }

        # Load metadata (optional)
        metadata_path = directory / METADATA_FILE
        if metadata_path.is_file():
            metadata = self._load_yaml_file(metadata_path)
            if isinstance(metadata, dict):
                combined["metadata"] = metadata

        # Load roles
        roles_path = directory / ROLES_FILE
        if roles_path.is_file():
            roles_data = self._load_yaml_file(roles_path)
            if isinstance(roles_data, dict) and "roles" in roles_data:
                combined["roles"] = roles_data["roles"]
            elif isinstance(roles_data, list):
                combined["roles"] = roles_data

        # Load rules
        rules_path = directory / RULES_FILE
        if rules_path.is_file():
            rules_data = self._load_yaml_file(rules_path)
            if isinstance(rules_data, dict) and "rules" in rules_data:
                combined["rules"] = rules_data["rules"]
            elif isinstance(rules_data, list):
                combined["rules"] = rules_data

        # Load risk config
        risk_path = directory / RISK_FILE
        if risk_path.is_file():
            risk_data = self._load_yaml_file(risk_path)
            if isinstance(risk_data, dict):
                # Unwrap if nested under 'risk' key
                combined["risk"] = risk_data.get("risk", risk_data)

        # Load taint policy
        taint_path = directory / TAINT_FILE
        if taint_path.is_file():
            taint_data = self._load_yaml_file(taint_path)
            if isinstance(taint_data, dict):
                combined["taint"] = taint_data.get("taint", taint_data)

        # Validate the merged document
        errors = self._loader.validate_schema(combined)
        if errors:
            raise YAMLPolicyValidationError(errors)

        return YAMLPolicyDocument.model_validate(combined)

    def list_files(self, directory: str | Path) -> list[str]:
        """List recognized policy files in the directory."""
        directory = Path(directory)
        if not directory.is_dir():
            return []

        recognized = [ROLES_FILE, RULES_FILE, RISK_FILE, TAINT_FILE, METADATA_FILE]
        found: list[str] = []
        for name in recognized:
            if (directory / name).is_file():
                found.append(name)
        return found

    @staticmethod
    def _load_yaml_file(path: Path) -> Any:
        """Load a single YAML file, returning the parsed data."""
        content = path.read_bytes()
        if len(content) > YAMLPolicyLoader.MAX_PAYLOAD_BYTES:
            raise YAMLPolicyValidationError(
                [f"File {path.name} exceeds maximum size of {YAMLPolicyLoader.MAX_PAYLOAD_BYTES} bytes"]
            )
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise YAMLPolicyValidationError(
                [f"Invalid YAML in {path.name}: {exc}"]
            ) from exc


# Module-level singleton
policy_directory_loader = PolicyDirectoryLoader()
