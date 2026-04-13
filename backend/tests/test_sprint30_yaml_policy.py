"""Tests for Sprint 30 — ToolTrust: YAML Policy Loading & Offline Evaluation.

APEP-233: YAML policy schema design
APEP-234: YAML policy loader with JSON Schema validation
APEP-235: Policy-as-code directory convention
APEP-236: GitOps sync endpoint POST /v1/policies/sync
APEP-237: Policy diff engine
APEP-238: Enhanced SDK offline evaluation (SDK tests in sdk/tests/)
APEP-240: Integration tests for YAML load → evaluate → diff → sync lifecycle
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml
from httpx import ASGITransport, AsyncClient

from tests.conftest import _get_auth_headers


# ---------------------------------------------------------------------------
# APEP-233: YAML Policy Schema
# ---------------------------------------------------------------------------


class TestYAMLPolicySchema:
    """Verify YAML policy schema models and JSON Schema validation."""

    def test_yaml_policy_document_defaults(self):
        from app.models.yaml_policy import YAMLPolicyDocument

        doc = YAMLPolicyDocument()
        assert doc.schema_version == "1.0"
        assert doc.roles == []
        assert doc.rules == []
        assert doc.risk is not None
        assert doc.taint is not None

    def test_yaml_role_definition(self):
        from app.models.yaml_policy import YAMLRoleDefinition

        role = YAMLRoleDefinition(
            role_id="test-role",
            name="Test Role",
            allowed_tools=["read_*"],
            max_risk_threshold=0.8,
        )
        assert role.role_id == "test-role"
        assert role.max_risk_threshold == 0.8
        assert role.enabled is True

    def test_yaml_rule_definition(self):
        from app.models.yaml_policy import YAMLRuleDefinition

        rule = YAMLRuleDefinition(
            name="Allow reads",
            tool_pattern="read_*",
            action="ALLOW",
            priority=10,
        )
        assert rule.action == "ALLOW"
        assert rule.priority == 10

    def test_data_classification_ranking(self):
        from app.models.yaml_policy import DATA_CLASSIFICATION_RANK, DataClassification

        assert DATA_CLASSIFICATION_RANK[DataClassification.PUBLIC] == 0
        assert DATA_CLASSIFICATION_RANK[DataClassification.FINANCIAL] == 5
        assert DATA_CLASSIFICATION_RANK[DataClassification.PII] > DATA_CLASSIFICATION_RANK[DataClassification.INTERNAL]

    def test_invalid_schema_version_rejected(self):
        from app.models.yaml_policy import YAMLPolicyDocument
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="Unsupported schema_version"):
            YAMLPolicyDocument(schema_version="99.0")

    def test_json_schema_structure(self):
        from app.models.yaml_policy import YAML_POLICY_JSON_SCHEMA

        assert YAML_POLICY_JSON_SCHEMA["title"] == "AgentPEP YAML Policy Schema v1.0"
        assert "roles" in YAML_POLICY_JSON_SCHEMA["properties"]
        assert "rules" in YAML_POLICY_JSON_SCHEMA["properties"]
        assert "risk" in YAML_POLICY_JSON_SCHEMA["properties"]
        assert "taint" in YAML_POLICY_JSON_SCHEMA["properties"]


# ---------------------------------------------------------------------------
# APEP-234: YAML Policy Loader
# ---------------------------------------------------------------------------


SAMPLE_YAML = """
schema_version: "1.0"
roles:
  - role_id: reader
    name: Read-Only Agent
    allowed_tools:
      - "read_*"
    max_risk_threshold: 0.5
  - role_id: writer
    name: Writer Agent
    parent_roles:
      - reader
    allowed_tools:
      - "write_*"
    max_risk_threshold: 0.8
rules:
  - name: Allow reads
    agent_roles:
      - reader
    tool_pattern: "read_*"
    action: ALLOW
    priority: 10
  - name: Deny deletes
    agent_roles: ["*"]
    tool_pattern: "delete_*"
    action: DENY
    priority: 5
risk:
  default_weights:
    operation_type: 0.3
    data_sensitivity: 0.2
    taint: 0.2
    session_accumulated: 0.1
    delegation_depth: 0.2
  escalation_threshold: 0.7
taint:
  max_hop_depth: 8
  quarantine_on_injection: true
  sanitisation_gates:
    - name: HTML Sanitiser
      function_pattern: "sanitise_html_*"
      downgrades_from: UNTRUSTED
      downgrades_to: TRUSTED
"""


class TestYAMLPolicyLoader:
    """Test YAML policy loader (APEP-234)."""

    def test_parse_valid_yaml(self):
        from app.services.yaml_loader import yaml_policy_loader

        data = yaml_policy_loader.parse_yaml(SAMPLE_YAML)
        assert isinstance(data, dict)
        assert data["schema_version"] == "1.0"
        assert len(data["roles"]) == 2
        assert len(data["rules"]) == 2

    def test_validate_schema_valid(self):
        from app.services.yaml_loader import yaml_policy_loader

        data = yaml_policy_loader.parse_yaml(SAMPLE_YAML)
        errors = yaml_policy_loader.validate_schema(data)
        assert errors == []

    def test_validate_schema_invalid_action(self):
        from app.services.yaml_loader import yaml_policy_loader

        data = yaml_policy_loader.parse_yaml(SAMPLE_YAML)
        data["rules"][0]["action"] = "INVALID_ACTION"
        errors = yaml_policy_loader.validate_schema(data)
        assert len(errors) > 0
        assert any("action" in e for e in errors)

    def test_load_and_validate(self):
        from app.services.yaml_loader import yaml_policy_loader

        doc = yaml_policy_loader.load_and_validate(SAMPLE_YAML)
        assert doc.schema_version == "1.0"
        assert len(doc.roles) == 2
        assert len(doc.rules) == 2
        assert doc.roles[0].role_id == "reader"
        assert doc.rules[0].name == "Allow reads"

    def test_load_invalid_yaml_raises(self):
        from app.services.yaml_loader import YAMLPolicyValidationError, yaml_policy_loader

        with pytest.raises(YAMLPolicyValidationError, match="Invalid YAML syntax"):
            yaml_policy_loader.load_and_validate("{{invalid: yaml::")

    def test_load_oversized_payload_raises(self):
        from app.services.yaml_loader import YAMLPolicyValidationError, yaml_policy_loader

        big = "x" * 3_000_000
        with pytest.raises(YAMLPolicyValidationError, match="exceeds maximum size"):
            yaml_policy_loader.load_and_validate(big)

    def test_hydrate_roles(self):
        from app.services.yaml_loader import yaml_policy_loader

        doc = yaml_policy_loader.load_and_validate(SAMPLE_YAML)
        roles = yaml_policy_loader.hydrate_roles(doc)
        assert len(roles) == 2
        assert roles[0].role_id == "reader"
        assert roles[1].parent_roles == ["reader"]

    def test_hydrate_rules(self):
        from app.services.yaml_loader import yaml_policy_loader

        doc = yaml_policy_loader.load_and_validate(SAMPLE_YAML)
        rules = yaml_policy_loader.hydrate_rules(doc)
        assert len(rules) == 2
        assert str(rules[0].action) == "ALLOW"
        assert rules[0].priority == 10
        assert rules[1].priority == 5

    def test_hydrate_risk_config(self):
        from app.services.yaml_loader import yaml_policy_loader

        doc = yaml_policy_loader.load_and_validate(SAMPLE_YAML)
        config = yaml_policy_loader.hydrate_risk_config(doc)
        assert config.escalation_threshold == 0.7
        assert config.default_weights.operation_type == 0.3

    def test_hydrate_sanitisation_gates(self):
        from app.services.yaml_loader import yaml_policy_loader

        doc = yaml_policy_loader.load_and_validate(SAMPLE_YAML)
        gates = yaml_policy_loader.hydrate_sanitisation_gates(doc)
        assert len(gates) == 1
        assert gates[0].name == "HTML Sanitiser"

    def test_load_from_file(self, tmp_path):
        from app.services.yaml_loader import yaml_policy_loader

        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(SAMPLE_YAML)

        doc = yaml_policy_loader.load_file(policy_file)
        assert len(doc.roles) == 2


# ---------------------------------------------------------------------------
# APEP-235: Policy-as-Code Directory Convention
# ---------------------------------------------------------------------------


class TestPolicyDirectoryLoader:
    """Test policy-as-code directory loading (APEP-235)."""

    @pytest.fixture
    def policy_dir(self, tmp_path) -> Path:
        """Create a temporary policy directory with sample files."""
        roles_yaml = """
roles:
  - role_id: admin
    name: Administrator
    allowed_tools: ["*"]
    max_risk_threshold: 0.9
  - role_id: viewer
    name: Viewer
    allowed_tools: ["read_*"]
"""
        rules_yaml = """
rules:
  - name: Allow all for admin
    agent_roles: [admin]
    tool_pattern: "*"
    action: ALLOW
    priority: 1
  - name: Allow reads for viewer
    agent_roles: [viewer]
    tool_pattern: "read_*"
    action: ALLOW
    priority: 10
"""
        risk_yaml = """
risk:
  escalation_threshold: 0.8
  default_weights:
    operation_type: 0.25
    data_sensitivity: 0.25
    taint: 0.20
    session_accumulated: 0.10
    delegation_depth: 0.20
"""
        taint_yaml = """
taint:
  max_hop_depth: 5
  quarantine_on_injection: true
"""
        metadata_yaml = """
author: test
description: Test policies
"""
        (tmp_path / "roles.yaml").write_text(roles_yaml)
        (tmp_path / "rules.yaml").write_text(rules_yaml)
        (tmp_path / "risk.yaml").write_text(risk_yaml)
        (tmp_path / "taint.yaml").write_text(taint_yaml)
        (tmp_path / "metadata.yaml").write_text(metadata_yaml)
        return tmp_path

    def test_load_directory(self, policy_dir):
        from app.services.policy_directory import policy_directory_loader

        doc = policy_directory_loader.load_directory(policy_dir)
        assert len(doc.roles) == 2
        assert len(doc.rules) == 2
        assert doc.risk.escalation_threshold == 0.8
        assert doc.taint.max_hop_depth == 5
        assert doc.metadata.get("author") == "test"

    def test_list_files(self, policy_dir):
        from app.services.policy_directory import policy_directory_loader

        files = policy_directory_loader.list_files(policy_dir)
        assert "roles.yaml" in files
        assert "rules.yaml" in files
        assert "risk.yaml" in files
        assert "taint.yaml" in files
        assert "metadata.yaml" in files

    def test_missing_directory_raises(self):
        from app.services.policy_directory import policy_directory_loader
        from app.services.yaml_loader import YAMLPolicyValidationError

        with pytest.raises(YAMLPolicyValidationError, match="not found"):
            policy_directory_loader.load_directory("/nonexistent/path")

    def test_partial_directory_ok(self, tmp_path):
        """Loading a directory with only some files should work."""
        from app.services.policy_directory import policy_directory_loader

        roles_yaml = """
roles:
  - role_id: minimal
    name: Minimal Role
"""
        (tmp_path / "roles.yaml").write_text(roles_yaml)

        doc = policy_directory_loader.load_directory(tmp_path)
        assert len(doc.roles) == 1
        assert doc.rules == []

    def test_load_sample_policies_directory(self):
        """Load the actual sample policies/ directory from the repo."""
        from app.services.policy_directory import policy_directory_loader

        policies_dir = Path(__file__).resolve().parent.parent.parent / "policies"
        if not policies_dir.is_dir():
            pytest.skip("policies/ directory not found")

        doc = policy_directory_loader.load_directory(policies_dir)
        assert len(doc.roles) >= 1
        assert len(doc.rules) >= 1


# ---------------------------------------------------------------------------
# APEP-237: Policy Diff Engine
# ---------------------------------------------------------------------------


class TestPolicyDiffEngine:
    """Test the policy diff engine (APEP-237)."""

    def test_identical_docs_no_diff(self):
        from app.services.policy_differ import policy_diff_engine
        from app.services.yaml_loader import yaml_policy_loader

        doc = yaml_policy_loader.load_and_validate(SAMPLE_YAML)
        result = policy_diff_engine.diff(doc, doc)
        assert not result.has_changes
        assert result.added_count == 0
        assert result.removed_count == 0
        assert result.changed_count == 0

    def test_added_role(self):
        from app.models.yaml_policy import YAMLPolicyDocument, YAMLRoleDefinition
        from app.services.policy_differ import policy_diff_engine

        old = YAMLPolicyDocument()
        new = YAMLPolicyDocument(roles=[
            YAMLRoleDefinition(role_id="new-role", name="New Role"),
        ])

        result = policy_diff_engine.diff(old, new)
        assert result.has_changes
        assert result.added_count == 1
        assert result.entries[0].section == "roles"
        assert result.entries[0].identifier == "new-role"

    def test_removed_rule(self):
        from app.models.yaml_policy import YAMLPolicyDocument, YAMLRuleDefinition
        from app.services.policy_differ import policy_diff_engine

        old = YAMLPolicyDocument(rules=[
            YAMLRuleDefinition(name="Old Rule", tool_pattern="old_*", action="DENY"),
        ])
        new = YAMLPolicyDocument()

        result = policy_diff_engine.diff(old, new)
        assert result.has_changes
        assert result.removed_count == 1

    def test_changed_role(self):
        from app.models.yaml_policy import YAMLPolicyDocument, YAMLRoleDefinition
        from app.services.policy_differ import policy_diff_engine

        old = YAMLPolicyDocument(roles=[
            YAMLRoleDefinition(role_id="role-1", name="Role One", max_risk_threshold=0.5),
        ])
        new = YAMLPolicyDocument(roles=[
            YAMLRoleDefinition(role_id="role-1", name="Role One", max_risk_threshold=0.9),
        ])

        result = policy_diff_engine.diff(old, new)
        assert result.has_changes
        assert result.changed_count == 1
        assert "max_risk_threshold" in result.entries[0].changed_fields

    def test_changed_risk_config(self):
        from app.models.yaml_policy import YAMLPolicyDocument, YAMLRiskConfig
        from app.services.policy_differ import policy_diff_engine

        old = YAMLPolicyDocument(risk=YAMLRiskConfig(escalation_threshold=0.7))
        new = YAMLPolicyDocument(risk=YAMLRiskConfig(escalation_threshold=0.9))

        result = policy_diff_engine.diff(old, new)
        assert result.has_changes
        assert any(e.section == "risk" for e in result.entries)

    def test_diff_to_dict(self):
        from app.models.yaml_policy import YAMLPolicyDocument, YAMLRoleDefinition
        from app.services.policy_differ import policy_diff_engine

        old = YAMLPolicyDocument()
        new = YAMLPolicyDocument(roles=[
            YAMLRoleDefinition(role_id="r1", name="R1"),
        ])

        result = policy_diff_engine.diff(old, new)
        d = result.to_dict()
        assert d["has_changes"] is True
        assert d["summary"]["added"] == 1
        assert len(d["entries"]) == 1


# ---------------------------------------------------------------------------
# APEP-236: GitOps Sync Endpoint
# ---------------------------------------------------------------------------


class TestGitOpsSyncEndpoint:
    """Test POST /v1/policies/sync (APEP-236)."""

    @pytest.fixture
    def headers(self) -> dict[str, str]:
        return _get_auth_headers()

    @pytest.mark.asyncio
    async def test_sync_dry_run(self, mock_mongodb, headers):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/policies/sync?dry_run=true",
                content=SAMPLE_YAML,
                headers={**headers, "Content-Type": "text/yaml"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "validated"
            assert data["roles_synced"] == 2
            assert data["rules_synced"] == 2

    @pytest.mark.asyncio
    async def test_sync_apply(self, mock_mongodb, headers):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/policies/sync",
                content=SAMPLE_YAML,
                headers={**headers, "Content-Type": "text/yaml"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "applied"
            assert data["roles_synced"] == 2
            assert data["rules_synced"] == 2
            assert data["risk_config_synced"] is True

            # Verify sync actually wrote data by listing roles/rules via API
            roles_resp = await client.get("/v1/roles", headers=headers)
            assert roles_resp.status_code == 200
            assert len(roles_resp.json()) == 2

            rules_resp = await client.get("/v1/rules/conflicts", headers=headers)
            assert rules_resp.status_code == 200

    @pytest.mark.asyncio
    async def test_sync_invalid_yaml_returns_400(self, mock_mongodb, headers):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/policies/sync",
                content="{{invalid yaml::",
                headers={**headers, "Content-Type": "text/yaml"},
            )
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_sync_invalid_schema_returns_400(self, mock_mongodb, headers):
        from app.main import app

        invalid_policy = """
schema_version: "1.0"
rules:
  - name: Bad Rule
    tool_pattern: "test"
    action: INVALID_ACTION
"""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/policies/sync",
                content=invalid_policy,
                headers={**headers, "Content-Type": "text/yaml"},
            )
            assert resp.status_code == 400


# ---------------------------------------------------------------------------
# APEP-237: Policy Diff Endpoint
# ---------------------------------------------------------------------------


class TestPolicyDiffEndpoint:
    """Test POST /v1/policies/diff (APEP-237)."""

    @pytest.fixture
    def headers(self) -> dict[str, str]:
        return _get_auth_headers()

    @pytest.mark.asyncio
    async def test_diff_against_empty(self, mock_mongodb, headers):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/policies/diff",
                content=SAMPLE_YAML,
                headers={**headers, "Content-Type": "text/yaml"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["has_changes"] is True
            # Against empty DB, roles and rules show as added;
            # risk/taint may show as changed (default vs custom)
            assert data["summary"]["total"] > 0

    @pytest.mark.asyncio
    async def test_diff_after_sync_shows_minimal_changes(self, mock_mongodb, headers):
        from app.main import app

        # Use YAML without custom taint section (taint is not persisted in sync)
        yaml_no_taint = """
schema_version: "1.0"
roles:
  - role_id: reader
    name: Read-Only Agent
    allowed_tools:
      - "read_*"
    max_risk_threshold: 0.5
  - role_id: writer
    name: Writer Agent
    parent_roles:
      - reader
    allowed_tools:
      - "write_*"
    max_risk_threshold: 0.8
rules:
  - name: Allow reads
    agent_roles:
      - reader
    tool_pattern: "read_*"
    action: ALLOW
    priority: 10
  - name: Deny deletes
    agent_roles: ["*"]
    tool_pattern: "delete_*"
    action: DENY
    priority: 5
risk:
  default_weights:
    operation_type: 0.3
    data_sensitivity: 0.2
    taint: 0.2
    session_accumulated: 0.1
    delegation_depth: 0.2
  escalation_threshold: 0.7
"""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # First, sync the policy
            await client.post(
                "/v1/policies/sync",
                content=yaml_no_taint,
                headers={**headers, "Content-Type": "text/yaml"},
            )
            # Then diff the same policy — roles, rules, risk should be unchanged
            resp = await client.post(
                "/v1/policies/diff",
                content=yaml_no_taint,
                headers={**headers, "Content-Type": "text/yaml"},
            )
            assert resp.status_code == 200
            data = resp.json()
            # Only taint may differ (not persisted); roles, rules, risk match
            role_changes = [e for e in data["entries"] if e["section"] == "roles"]
            rule_changes = [e for e in data["entries"] if e["section"] == "rules"]
            risk_changes = [e for e in data["entries"] if e["section"] == "risk"]
            assert len(role_changes) == 0
            assert len(rule_changes) == 0
            assert len(risk_changes) == 0


# ---------------------------------------------------------------------------
# APEP-240: Integration Tests — Full Lifecycle
# ---------------------------------------------------------------------------


class TestYAMLPolicyLifecycle:
    """End-to-end lifecycle: YAML load → evaluate → diff → sync."""

    @pytest.fixture
    def headers(self) -> dict[str, str]:
        return _get_auth_headers()

    @pytest.mark.asyncio
    async def test_full_lifecycle(self, mock_mongodb, headers):
        """Test the complete lifecycle: load → sync → diff → update → sync."""
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Step 1: Sync initial policy
            resp = await client.post(
                "/v1/policies/sync",
                content=SAMPLE_YAML,
                headers={**headers, "Content-Type": "text/yaml"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "applied"

            # Step 2: Diff same policy — roles/rules/risk should match
            resp = await client.post(
                "/v1/policies/diff",
                content=SAMPLE_YAML,
                headers={**headers, "Content-Type": "text/yaml"},
            )
            assert resp.status_code == 200
            diff_data = resp.json()
            # Roles, rules, and risk config should have no changes after sync
            role_changes = [e for e in diff_data["entries"] if e["section"] == "roles"]
            rule_changes = [e for e in diff_data["entries"] if e["section"] == "rules"]
            risk_changes = [e for e in diff_data["entries"] if e["section"] == "risk"]
            assert len(role_changes) == 0
            assert len(rule_changes) == 0
            assert len(risk_changes) == 0

            # Step 3: Create updated policy with a new role
            updated_yaml = """
schema_version: "1.0"
roles:
  - role_id: reader
    name: Read-Only Agent
    allowed_tools:
      - "read_*"
    max_risk_threshold: 0.5
  - role_id: writer
    name: Writer Agent
    parent_roles:
      - reader
    allowed_tools:
      - "write_*"
    max_risk_threshold: 0.8
  - role_id: admin
    name: Administrator
    allowed_tools:
      - "*"
    max_risk_threshold: 0.95
rules:
  - name: Allow reads
    agent_roles:
      - reader
    tool_pattern: "read_*"
    action: ALLOW
    priority: 10
  - name: Deny deletes
    agent_roles: ["*"]
    tool_pattern: "delete_*"
    action: DENY
    priority: 5
  - name: Allow all for admin
    agent_roles:
      - admin
    tool_pattern: "*"
    action: ALLOW
    priority: 1
risk:
  default_weights:
    operation_type: 0.3
    data_sensitivity: 0.2
    taint: 0.2
    session_accumulated: 0.1
    delegation_depth: 0.2
  escalation_threshold: 0.7
taint:
  max_hop_depth: 8
  quarantine_on_injection: true
  sanitisation_gates:
    - name: HTML Sanitiser
      function_pattern: "sanitise_html_*"
      downgrades_from: UNTRUSTED
      downgrades_to: TRUSTED
"""

            # Step 4: Diff updated policy — should show changes
            resp = await client.post(
                "/v1/policies/diff",
                content=updated_yaml,
                headers={**headers, "Content-Type": "text/yaml"},
            )
            assert resp.status_code == 200
            diff = resp.json()
            assert diff["has_changes"] is True
            assert diff["summary"]["added"] >= 1  # New admin role + admin rule

            # Step 5: Dry-run sync of updated policy
            resp = await client.post(
                "/v1/policies/sync?dry_run=true",
                content=updated_yaml,
                headers={**headers, "Content-Type": "text/yaml"},
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "validated"

            # Step 6: Actually sync the updated policy
            resp = await client.post(
                "/v1/policies/sync",
                content=updated_yaml,
                headers={**headers, "Content-Type": "text/yaml"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "applied"
            assert data["roles_synced"] == 3  # reader + writer + admin
            assert data["rules_synced"] == 3  # reads + deletes + admin

    @pytest.mark.asyncio
    async def test_directory_load_and_hydrate(self, tmp_path):
        """Load from directory, hydrate, and verify policy objects."""
        from app.services.policy_directory import policy_directory_loader
        from app.services.yaml_loader import yaml_policy_loader

        # Create policy directory
        (tmp_path / "roles.yaml").write_text("""
roles:
  - role_id: agent
    name: Agent Role
    allowed_tools: ["read_*", "write_*"]
    max_risk_threshold: 0.7
""")
        (tmp_path / "rules.yaml").write_text("""
rules:
  - name: Allow reads
    tool_pattern: "read_*"
    action: ALLOW
    priority: 10
  - name: Escalate writes
    tool_pattern: "write_*"
    action: ESCALATE
    taint_check: true
    priority: 20
""")
        (tmp_path / "risk.yaml").write_text("""
risk:
  escalation_threshold: 0.6
""")

        # Load directory
        doc = policy_directory_loader.load_directory(tmp_path)
        assert len(doc.roles) == 1
        assert len(doc.rules) == 2

        # Hydrate
        roles = yaml_policy_loader.hydrate_roles(doc)
        rules = yaml_policy_loader.hydrate_rules(doc)
        risk_config = yaml_policy_loader.hydrate_risk_config(doc)

        assert roles[0].role_id == "agent"
        assert len(rules) == 2
        assert rules[1].taint_check is True
        assert risk_config.escalation_threshold == 0.6

    def test_diff_between_directories(self, tmp_path):
        """Load two directories and diff them."""
        from app.services.policy_differ import policy_diff_engine
        from app.services.policy_directory import policy_directory_loader

        dir_a = tmp_path / "v1"
        dir_a.mkdir()
        (dir_a / "roles.yaml").write_text("""
roles:
  - role_id: dev
    name: Developer
""")
        (dir_a / "rules.yaml").write_text("""
rules:
  - name: Allow code
    tool_pattern: "code.*"
    action: ALLOW
    priority: 10
""")

        dir_b = tmp_path / "v2"
        dir_b.mkdir()
        (dir_b / "roles.yaml").write_text("""
roles:
  - role_id: dev
    name: Developer (Updated)
  - role_id: ops
    name: Operations
""")
        (dir_b / "rules.yaml").write_text("""
rules:
  - name: Allow code
    tool_pattern: "code.*"
    action: ALLOW
    priority: 5
  - name: Allow deploy
    tool_pattern: "deploy.*"
    action: ESCALATE
    priority: 20
""")

        doc_a = policy_directory_loader.load_directory(dir_a)
        doc_b = policy_directory_loader.load_directory(dir_b)

        result = policy_diff_engine.diff(doc_a, doc_b)
        assert result.has_changes
        # Added: ops role, deploy rule
        assert result.added_count >= 2
        # Changed: dev role name, code rule priority
        assert result.changed_count >= 2
