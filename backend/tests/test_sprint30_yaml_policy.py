"""Sprint 30 integration tests — YAML policy loading, diff, sync lifecycle (APEP-240).

Covers:
- APEP-233: YAML policy schema validation
- APEP-234: YAML policy loader (parse, validate, hydrate)
- APEP-235: Policy-as-code directory convention
- APEP-236: GitOps sync endpoint (POST /v1/policies/sync)
- APEP-237: Policy diff engine
- APEP-238: Enhanced SDK offline evaluation (tested in sdk/tests/)
- APEP-240: Full lifecycle integration tests
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.services.policy_diff import ChangeType, PolicyDiffEngine, PolicyDiffResult
from app.services.yaml_policy_loader import (
    PolicyBundle,
    PolicyValidationError,
    YAMLPolicyLoader,
)
from app.services.yaml_policy_schema import (
    CLASSIFICATIONS_SCHEMA,
    POLICY_BUNDLE_SCHEMA,
    RISK_SCHEMA,
    ROLES_SCHEMA,
    RULES_SCHEMA,
    TAINT_SCHEMA,
)

# Re-use conftest helpers
from tests.conftest import _get_auth_headers


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def loader() -> YAMLPolicyLoader:
    return YAMLPolicyLoader()


@pytest.fixture
def differ() -> PolicyDiffEngine:
    return PolicyDiffEngine()


@pytest.fixture
def sample_roles_yaml() -> str:
    return textwrap.dedent("""\
        version: "1.0"
        roles:
          - role_id: admin
            name: Administrator
            allowed_tools: ["*"]
            denied_tools: []
            max_risk_threshold: 0.9
            enabled: true
          - role_id: reader
            name: Read-Only
            parent_roles: []
            allowed_tools: ["read_*", "list_*"]
            denied_tools: ["delete_*"]
            max_risk_threshold: 0.5
    """)


@pytest.fixture
def sample_rules_yaml() -> str:
    return textwrap.dedent("""\
        version: "1.0"
        rules:
          - name: deny-exec
            agent_role: ["*"]
            tool_pattern: "exec_command"
            action: DENY
            priority: 1
          - name: allow-reads
            agent_role: ["reader", "admin"]
            tool_pattern: "read_*"
            action: ALLOW
            priority: 50
          - name: escalate-deletes
            agent_role: ["admin"]
            tool_pattern: "delete_*"
            action: ESCALATE
            taint_check: true
            risk_threshold: 0.5
            priority: 10
    """)


@pytest.fixture
def sample_risk_yaml() -> str:
    return textwrap.dedent("""\
        version: "1.0"
        risk_model:
          model_id: default
          default_weights:
            operation_type: 0.25
            data_sensitivity: 0.25
            taint: 0.20
            session_accumulated: 0.10
            delegation_depth: 0.20
          escalation_threshold: 0.7
          enabled: true
    """)


@pytest.fixture
def sample_taint_yaml() -> str:
    return textwrap.dedent("""\
        version: "1.0"
        sanitisation_gates:
          - name: html-sanitiser
            function_pattern: "sanitise_html*"
            downgrades_from: UNTRUSTED
            downgrades_to: TRUSTED
            requires_approval: false
            enabled: true
        injection_signatures:
          - signature_id: INJ-001
            category: prompt_override
            pattern: "(?i)ignore\\\\s+all\\\\s+previous"
            severity: CRITICAL
            description: "Override attempt"
    """)


@pytest.fixture
def sample_classifications_yaml() -> str:
    return textwrap.dedent("""\
        version: "1.0"
        levels:
          - name: PUBLIC
            rank: 0
            description: "Public data"
          - name: PII
            rank: 3
            description: "Personal data"
        tool_classifications:
          - tool_pattern: "read_public_*"
            classification: PUBLIC
          - tool_pattern: "read_user_*"
            classification: PII
    """)


@pytest.fixture
def sample_bundle_yaml() -> str:
    return textwrap.dedent("""\
        version: "1.0"
        roles:
          - role_id: admin
            name: Admin
            allowed_tools: ["*"]
            max_risk_threshold: 0.9
          - role_id: reader
            name: Reader
            allowed_tools: ["read_*"]
            denied_tools: ["delete_*"]
            max_risk_threshold: 0.5
        rules:
          - name: deny-exec
            tool_pattern: "exec_command"
            action: DENY
            priority: 1
          - name: allow-reads
            agent_role: ["reader", "admin"]
            tool_pattern: "read_*"
            action: ALLOW
            priority: 50
        risk_model:
          model_id: default
          default_weights:
            operation_type: 0.30
            data_sensitivity: 0.20
            taint: 0.20
            session_accumulated: 0.10
            delegation_depth: 0.20
          escalation_threshold: 0.7
        sanitisation_gates:
          - name: html-sanitiser
            function_pattern: "sanitise_html*"
            downgrades_from: UNTRUSTED
            downgrades_to: TRUSTED
        injection_signatures:
          - signature_id: INJ-001
            category: prompt_override
            pattern: "(?i)ignore\\\\s+all"
            severity: CRITICAL
        classification_levels:
          - name: PUBLIC
            rank: 0
          - name: PII
            rank: 3
        tool_classifications:
          - tool_pattern: "read_user_*"
            classification: PII
    """)


@pytest.fixture
def policy_dir(tmp_path: Path, sample_roles_yaml, sample_rules_yaml, sample_risk_yaml,
               sample_taint_yaml, sample_classifications_yaml) -> Path:
    """Create a temporary policy directory with all YAML files."""
    d = tmp_path / "policies"
    d.mkdir()
    (d / "roles.yaml").write_text(sample_roles_yaml)
    (d / "rules.yaml").write_text(sample_rules_yaml)
    (d / "risk.yaml").write_text(sample_risk_yaml)
    (d / "taint.yaml").write_text(sample_taint_yaml)
    (d / "classifications.yaml").write_text(sample_classifications_yaml)
    return d


# ---------------------------------------------------------------------------
# APEP-233: Schema validation tests
# ---------------------------------------------------------------------------


class TestYAMLPolicySchema:
    """Test JSON Schema validation for YAML policy files (APEP-233)."""

    def test_valid_roles_schema(self, loader: YAMLPolicyLoader, sample_roles_yaml: str) -> None:
        data = loader.parse_yaml(sample_roles_yaml)
        errors = loader.validate_yaml(data, ROLES_SCHEMA, "roles.yaml")
        assert errors == []

    def test_valid_rules_schema(self, loader: YAMLPolicyLoader, sample_rules_yaml: str) -> None:
        data = loader.parse_yaml(sample_rules_yaml)
        errors = loader.validate_yaml(data, RULES_SCHEMA, "rules.yaml")
        assert errors == []

    def test_valid_risk_schema(self, loader: YAMLPolicyLoader, sample_risk_yaml: str) -> None:
        data = loader.parse_yaml(sample_risk_yaml)
        errors = loader.validate_yaml(data, RISK_SCHEMA, "risk.yaml")
        assert errors == []

    def test_valid_taint_schema(self, loader: YAMLPolicyLoader, sample_taint_yaml: str) -> None:
        data = loader.parse_yaml(sample_taint_yaml)
        errors = loader.validate_yaml(data, TAINT_SCHEMA, "taint.yaml")
        assert errors == []

    def test_valid_classifications_schema(
        self, loader: YAMLPolicyLoader, sample_classifications_yaml: str
    ) -> None:
        data = loader.parse_yaml(sample_classifications_yaml)
        errors = loader.validate_yaml(data, CLASSIFICATIONS_SCHEMA, "classifications.yaml")
        assert errors == []

    def test_valid_bundle_schema(
        self, loader: YAMLPolicyLoader, sample_bundle_yaml: str
    ) -> None:
        data = loader.parse_yaml(sample_bundle_yaml)
        errors = loader.validate_yaml(data, POLICY_BUNDLE_SCHEMA, "bundle.yaml")
        assert errors == []

    def test_missing_version_fails(self, loader: YAMLPolicyLoader) -> None:
        data = loader.parse_yaml("roles:\n  - role_id: x\n    name: X\n")
        errors = loader.validate_yaml(data, ROLES_SCHEMA, "roles.yaml")
        assert len(errors) > 0
        assert any("version" in e for e in errors)

    def test_invalid_action_fails(self, loader: YAMLPolicyLoader) -> None:
        yaml_str = textwrap.dedent("""\
            version: "1.0"
            rules:
              - name: bad-rule
                tool_pattern: "foo"
                action: INVALID_ACTION
        """)
        data = loader.parse_yaml(yaml_str)
        errors = loader.validate_yaml(data, RULES_SCHEMA, "rules.yaml")
        assert len(errors) > 0

    def test_invalid_risk_threshold_fails(self, loader: YAMLPolicyLoader) -> None:
        yaml_str = textwrap.dedent("""\
            version: "1.0"
            roles:
              - role_id: bad
                name: Bad
                max_risk_threshold: 1.5
        """)
        data = loader.parse_yaml(yaml_str)
        errors = loader.validate_yaml(data, ROLES_SCHEMA, "roles.yaml")
        assert len(errors) > 0

    def test_invalid_yaml_syntax(self, loader: YAMLPolicyLoader) -> None:
        with pytest.raises(PolicyValidationError, match="YAML parse error"):
            loader.parse_yaml("invalid: [yaml: {broken")

    def test_non_mapping_root(self, loader: YAMLPolicyLoader) -> None:
        with pytest.raises(PolicyValidationError, match="must be a mapping"):
            loader.parse_yaml("- just\n- a\n- list\n")

    def test_payload_size_limit(self, loader: YAMLPolicyLoader) -> None:
        huge = b"x" * (loader.MAX_PAYLOAD_BYTES + 1)
        with pytest.raises(PolicyValidationError, match="max size"):
            loader.parse_yaml(huge, "big.yaml")


# ---------------------------------------------------------------------------
# APEP-234: YAML policy loader tests
# ---------------------------------------------------------------------------


class TestYAMLPolicyLoader:
    """Test YAML policy loader hydration (APEP-234)."""

    def test_load_bundle_string(
        self, loader: YAMLPolicyLoader, sample_bundle_yaml: str
    ) -> None:
        bundle = loader.load_yaml_string(sample_bundle_yaml)
        assert len(bundle.roles) == 2
        assert len(bundle.rules) == 2
        assert bundle.risk_model is not None
        assert bundle.risk_model.escalation_threshold == 0.7
        assert len(bundle.sanitisation_gates) == 1
        assert len(bundle.injection_signatures) == 1
        assert len(bundle.classification_levels) == 2
        assert len(bundle.tool_classifications) == 1

    def test_hydrate_roles(
        self, loader: YAMLPolicyLoader, sample_roles_yaml: str
    ) -> None:
        data = loader.parse_yaml(sample_roles_yaml)
        from app.services.yaml_policy_loader import _hydrate_roles
        roles = _hydrate_roles(data["roles"])
        assert len(roles) == 2
        assert roles[0].role_id == "admin"
        assert roles[0].max_risk_threshold == 0.9
        assert roles[1].role_id == "reader"
        assert "delete_*" in roles[1].denied_tools

    def test_hydrate_rules(
        self, loader: YAMLPolicyLoader, sample_rules_yaml: str
    ) -> None:
        data = loader.parse_yaml(sample_rules_yaml)
        from app.services.yaml_policy_loader import _hydrate_rules
        rules = _hydrate_rules(data["rules"])
        assert len(rules) == 3
        assert rules[0].name == "deny-exec"
        assert str(rules[0].action) == "DENY"
        assert rules[2].taint_check is True

    def test_hydrate_risk_model(
        self, loader: YAMLPolicyLoader, sample_risk_yaml: str
    ) -> None:
        data = loader.parse_yaml(sample_risk_yaml)
        from app.services.yaml_policy_loader import _hydrate_risk_model
        model = _hydrate_risk_model(data["risk_model"])
        assert model.model_id == "default"
        assert model.escalation_threshold == 0.7
        assert model.default_weights.operation_type == 0.25

    def test_hydrate_sanitisation_gates(
        self, loader: YAMLPolicyLoader, sample_taint_yaml: str
    ) -> None:
        data = loader.parse_yaml(sample_taint_yaml)
        from app.services.yaml_policy_loader import _hydrate_sanitisation_gates
        gates = _hydrate_sanitisation_gates(data["sanitisation_gates"])
        assert len(gates) == 1
        assert gates[0].name == "html-sanitiser"
        assert gates[0].downgrades_from == "UNTRUSTED"

    def test_hydrate_injection_signatures(
        self, loader: YAMLPolicyLoader, sample_taint_yaml: str
    ) -> None:
        data = loader.parse_yaml(sample_taint_yaml)
        from app.services.yaml_policy_loader import _hydrate_injection_signatures
        sigs = _hydrate_injection_signatures(data["injection_signatures"])
        assert len(sigs) == 1
        assert sigs[0].signature_id == "INJ-001"
        assert sigs[0].severity == "CRITICAL"

    def test_bundle_is_empty(self) -> None:
        bundle = PolicyBundle()
        assert bundle.is_empty

    def test_bundle_not_empty(
        self, loader: YAMLPolicyLoader, sample_bundle_yaml: str
    ) -> None:
        bundle = loader.load_yaml_string(sample_bundle_yaml)
        assert not bundle.is_empty

    def test_validation_error_contains_file_name(
        self, loader: YAMLPolicyLoader
    ) -> None:
        with pytest.raises(PolicyValidationError) as exc_info:
            loader.load_and_validate("not yaml: [{{", ROLES_SCHEMA, "bad.yaml")
        assert "bad.yaml" in str(exc_info.value)
        assert exc_info.value.file_name == "bad.yaml"


# ---------------------------------------------------------------------------
# APEP-235: Directory convention tests
# ---------------------------------------------------------------------------


class TestPolicyDirectory:
    """Test policy-as-code directory convention (APEP-235)."""

    def test_load_full_directory(
        self, loader: YAMLPolicyLoader, policy_dir: Path
    ) -> None:
        bundle = loader.load_directory(policy_dir)
        assert len(bundle.roles) == 2
        assert len(bundle.rules) == 3
        assert bundle.risk_model is not None
        assert len(bundle.sanitisation_gates) == 1
        assert len(bundle.injection_signatures) == 1
        assert len(bundle.classification_levels) == 2
        assert len(bundle.tool_classifications) == 2

    def test_load_partial_directory(
        self, tmp_path: Path, sample_roles_yaml: str
    ) -> None:
        d = tmp_path / "partial"
        d.mkdir()
        (d / "roles.yaml").write_text(sample_roles_yaml)
        loader = YAMLPolicyLoader()
        bundle = loader.load_directory(d)
        assert len(bundle.roles) == 2
        assert len(bundle.rules) == 0

    def test_load_empty_directory(self, tmp_path: Path) -> None:
        d = tmp_path / "empty"
        d.mkdir()
        loader = YAMLPolicyLoader()
        bundle = loader.load_directory(d)
        assert bundle.is_empty

    def test_nonexistent_directory_raises(self) -> None:
        loader = YAMLPolicyLoader()
        with pytest.raises(PolicyValidationError, match="not found"):
            loader.load_directory("/nonexistent/path")

    def test_validate_directory(
        self, loader: YAMLPolicyLoader, policy_dir: Path
    ) -> None:
        results = loader.validate_directory(policy_dir)
        # All files should be valid
        for fname, errs in results.items():
            assert errs == [], f"{fname} had errors: {errs}"

    def test_validate_file(
        self, loader: YAMLPolicyLoader, policy_dir: Path
    ) -> None:
        errors = loader.validate_file(policy_dir / "roles.yaml")
        assert errors == []

    def test_yml_extension_supported(
        self, tmp_path: Path, sample_roles_yaml: str
    ) -> None:
        d = tmp_path / "yml_test"
        d.mkdir()
        (d / "roles.yml").write_text(sample_roles_yaml)
        loader = YAMLPolicyLoader()
        bundle = loader.load_directory(d)
        assert len(bundle.roles) == 2

    def test_load_example_policies_directory(self, loader: YAMLPolicyLoader) -> None:
        """Test loading the example policies/ directory at repo root."""
        example_dir = Path(__file__).parent.parent.parent / "policies"
        if not example_dir.is_dir():
            pytest.skip("No example policies/ directory found at repo root")
        bundle = loader.load_directory(example_dir)
        assert not bundle.is_empty


# ---------------------------------------------------------------------------
# APEP-237: Policy diff engine tests
# ---------------------------------------------------------------------------


class TestPolicyDiffEngine:
    """Test structured policy diff (APEP-237)."""

    def test_identical_bundles_no_diff(
        self, loader: YAMLPolicyLoader, differ: PolicyDiffEngine, sample_bundle_yaml: str
    ) -> None:
        bundle_a = loader.load_yaml_string(sample_bundle_yaml)
        bundle_b = loader.load_yaml_string(sample_bundle_yaml)
        result = differ.diff(bundle_a, bundle_b)
        assert not result.has_changes
        assert result.total_changes == 0
        assert result.summary() == "No changes detected."

    def test_added_role(self, differ: PolicyDiffEngine) -> None:
        old = PolicyBundle()
        new = PolicyBundle()
        from app.models.policy import AgentRole
        new.roles = [AgentRole(role_id="new-role", name="New Role")]
        result = differ.diff(old, new)
        assert result.has_changes
        assert len(result.added) == 1
        assert result.added[0].category == "role"
        assert result.added[0].key == "new-role"

    def test_removed_role(self, differ: PolicyDiffEngine) -> None:
        from app.models.policy import AgentRole
        old = PolicyBundle(roles=[AgentRole(role_id="old-role", name="Old")])
        new = PolicyBundle()
        result = differ.diff(old, new)
        assert len(result.removed) == 1
        assert result.removed[0].key == "old-role"

    def test_changed_role(self, differ: PolicyDiffEngine) -> None:
        from app.models.policy import AgentRole
        old = PolicyBundle(roles=[AgentRole(role_id="r1", name="V1", max_risk_threshold=0.5)])
        new = PolicyBundle(roles=[AgentRole(role_id="r1", name="V2", max_risk_threshold=0.8)])
        result = differ.diff(old, new)
        assert len(result.changed) == 1
        assert "name" in result.changed[0].changed_fields
        assert "max_risk_threshold" in result.changed[0].changed_fields

    def test_added_rule(self, differ: PolicyDiffEngine) -> None:
        from app.models.policy import PolicyRule
        old = PolicyBundle()
        new = PolicyBundle(rules=[
            PolicyRule(name="new-rule", agent_role=["*"], tool_pattern="*", action="ALLOW")
        ])
        result = differ.diff(old, new)
        assert len(result.added) == 1
        assert result.added[0].category == "rule"

    def test_risk_model_added(self, differ: PolicyDiffEngine) -> None:
        from app.models.policy import RiskModelConfig
        old = PolicyBundle()
        new = PolicyBundle(risk_model=RiskModelConfig())
        result = differ.diff(old, new)
        assert len(result.added) == 1
        assert result.added[0].category == "risk_model"

    def test_risk_model_changed(self, differ: PolicyDiffEngine) -> None:
        from app.models.policy import RiskModelConfig
        old = PolicyBundle(risk_model=RiskModelConfig(escalation_threshold=0.7))
        new = PolicyBundle(risk_model=RiskModelConfig(escalation_threshold=0.5))
        result = differ.diff(old, new)
        assert len(result.changed) == 1
        assert "escalation_threshold" in result.changed[0].changed_fields

    def test_risk_model_removed(self, differ: PolicyDiffEngine) -> None:
        from app.models.policy import RiskModelConfig
        old = PolicyBundle(risk_model=RiskModelConfig())
        new = PolicyBundle()
        result = differ.diff(old, new)
        assert len(result.removed) == 1
        assert result.removed[0].category == "risk_model"

    def test_diff_to_dict(self, differ: PolicyDiffEngine) -> None:
        from app.models.policy import AgentRole
        old = PolicyBundle()
        new = PolicyBundle(roles=[AgentRole(role_id="r1", name="R1")])
        result = differ.diff(old, new)
        d = result.to_dict()
        assert d["total_changes"] == 1
        assert d["added"] == 1
        assert d["removed"] == 0
        assert d["changed"] == 0
        assert len(d["entries"]) == 1

    def test_diff_summary(self, differ: PolicyDiffEngine) -> None:
        from app.models.policy import AgentRole
        old = PolicyBundle(roles=[AgentRole(role_id="r1", name="R1")])
        new = PolicyBundle(roles=[
            AgentRole(role_id="r1", name="R1-updated"),
            AgentRole(role_id="r2", name="R2"),
        ])
        result = differ.diff(old, new)
        summary = result.summary()
        assert "added" in summary
        assert "changed" in summary


# ---------------------------------------------------------------------------
# APEP-236: GitOps sync endpoint tests
# ---------------------------------------------------------------------------


class TestPolicySyncEndpoint:
    """Test GitOps sync, validate, and diff endpoints (APEP-236)."""

    @pytest.fixture
    async def client(self, mock_mongodb) -> AsyncClient:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    async def test_validate_valid_yaml(self, client: AsyncClient) -> None:
        yaml_str = textwrap.dedent("""\
            version: "1.0"
            roles:
              - role_id: admin
                name: Admin
                allowed_tools: ["*"]
            rules:
              - name: allow-all
                tool_pattern: "*"
                action: ALLOW
        """)
        resp = await client.post(
            "/v1/policies/validate",
            content=yaml_str.encode(),
            headers={**_get_auth_headers(), "Content-Type": "text/yaml"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["errors"] == []

    async def test_validate_invalid_yaml(self, client: AsyncClient) -> None:
        yaml_str = textwrap.dedent("""\
            version: "1.0"
            rules:
              - name: bad
                tool_pattern: "foo"
                action: INVALID
        """)
        resp = await client.post(
            "/v1/policies/validate",
            content=yaml_str.encode(),
            headers={**_get_auth_headers(), "Content-Type": "text/yaml"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False
        assert len(data["errors"]) > 0

    async def test_validate_malformed_yaml(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/v1/policies/validate",
            content=b"not: [valid: {yaml",
            headers={**_get_auth_headers(), "Content-Type": "text/yaml"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False

    async def test_sync_applies_roles_and_rules(self, client: AsyncClient) -> None:
        yaml_str = textwrap.dedent("""\
            version: "1.0"
            roles:
              - role_id: synced-admin
                name: Synced Admin
                allowed_tools: ["*"]
              - role_id: synced-reader
                name: Synced Reader
                allowed_tools: ["read_*"]
            rules:
              - name: synced-rule
                tool_pattern: "read_*"
                action: ALLOW
                priority: 10
        """)
        resp = await client.post(
            "/v1/policies/sync",
            content=yaml_str.encode(),
            headers={**_get_auth_headers(), "Content-Type": "text/yaml"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "applied"
        assert data["roles_count"] == 2
        assert data["rules_count"] == 1
        assert "applied_at" in data

    async def test_sync_returns_diff(self, client: AsyncClient) -> None:
        # First sync
        yaml_v1 = textwrap.dedent("""\
            version: "1.0"
            roles:
              - role_id: role-a
                name: Role A
            rules:
              - name: rule-a
                tool_pattern: "read_*"
                action: ALLOW
        """)
        await client.post(
            "/v1/policies/sync",
            content=yaml_v1.encode(),
            headers={**_get_auth_headers(), "Content-Type": "text/yaml"},
        )

        # Second sync with changes
        yaml_v2 = textwrap.dedent("""\
            version: "1.0"
            roles:
              - role_id: role-a
                name: Role A Updated
              - role_id: role-b
                name: Role B
            rules:
              - name: rule-a
                tool_pattern: "read_*"
                action: DENY
        """)
        resp = await client.post(
            "/v1/policies/sync",
            content=yaml_v2.encode(),
            headers={**_get_auth_headers(), "Content-Type": "text/yaml"},
        )
        assert resp.status_code == 200
        data = resp.json()
        diff = data["diff"]
        assert diff["total_changes"] > 0

    async def test_sync_invalid_yaml_returns_400(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/v1/policies/sync",
            content=b"version: '1.0'\nrules:\n  - name: bad\n    tool_pattern: x\n    action: BOGUS\n",
            headers={**_get_auth_headers(), "Content-Type": "text/yaml"},
        )
        assert resp.status_code == 400

    async def test_diff_endpoint(self, client: AsyncClient) -> None:
        yaml_str = textwrap.dedent("""\
            version: "1.0"
            roles:
              - role_id: diff-role
                name: Diff Role
            rules:
              - name: diff-rule
                tool_pattern: "*"
                action: ALLOW
        """)
        resp = await client.post(
            "/v1/policies/diff",
            content=yaml_str.encode(),
            headers={**_get_auth_headers(), "Content-Type": "text/yaml"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "diff" in data
        assert "total_changes" in data["diff"]

    async def test_sync_payload_size_limit(self, client: AsyncClient) -> None:
        huge = b"x" * (1_048_576 + 1)
        resp = await client.post(
            "/v1/policies/sync",
            content=huge,
            headers={**_get_auth_headers(), "Content-Type": "text/yaml"},
        )
        assert resp.status_code == 413


# ---------------------------------------------------------------------------
# APEP-240: Full lifecycle integration tests
# ---------------------------------------------------------------------------


class TestYAMLPolicyLifecycle:
    """End-to-end lifecycle: load → validate → diff → sync (APEP-240)."""

    @pytest.fixture
    async def client(self, mock_mongodb) -> AsyncClient:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    async def test_full_lifecycle(
        self,
        client: AsyncClient,
        sample_bundle_yaml: str,
    ) -> None:
        """Test: validate → sync → diff → re-sync with changes."""
        headers = {**_get_auth_headers(), "Content-Type": "text/yaml"}
        payload = sample_bundle_yaml.encode()

        # Step 1: Validate
        resp = await client.post("/v1/policies/validate", content=payload, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

        # Step 2: Sync (initial)
        resp = await client.post("/v1/policies/sync", content=payload, headers=headers)
        assert resp.status_code == 200
        sync1 = resp.json()
        assert sync1["status"] == "applied"
        assert sync1["roles_count"] == 2
        assert sync1["rules_count"] == 2

        # Step 3: Diff with identical payload
        # Note: sanitisation_gates, injection_signatures, classification_levels,
        # and tool_classifications are not persisted to MongoDB (only roles, rules,
        # and risk_model are), so they appear as additions in the diff.
        resp = await client.post("/v1/policies/diff", content=payload, headers=headers)
        assert resp.status_code == 200
        diff1 = resp.json()["diff"]
        # Roles and rules should have no changes (they were persisted)
        role_changes = [e for e in diff1["entries"] if e["category"] == "role"]
        rule_changes = [e for e in diff1["entries"] if e["category"] == "rule"]
        assert len([e for e in role_changes if e["change_type"] == "CHANGED"]) == 0
        assert len([e for e in rule_changes if e["change_type"] == "CHANGED"]) == 0

        # Step 4: Modify and sync again
        updated_yaml = textwrap.dedent("""\
            version: "1.0"
            roles:
              - role_id: admin
                name: Admin V2
                allowed_tools: ["*"]
                max_risk_threshold: 0.95
              - role_id: reader
                name: Reader
                allowed_tools: ["read_*"]
                denied_tools: ["delete_*"]
                max_risk_threshold: 0.5
              - role_id: writer
                name: Writer
                allowed_tools: ["write_*", "read_*"]
                max_risk_threshold: 0.7
            rules:
              - name: deny-exec
                tool_pattern: "exec_command"
                action: DENY
                priority: 1
              - name: allow-reads
                agent_role: ["reader", "admin"]
                tool_pattern: "read_*"
                action: ALLOW
                priority: 50
              - name: allow-writes
                agent_role: ["writer"]
                tool_pattern: "write_*"
                action: ALLOW
                priority: 60
            risk_model:
              model_id: default
              default_weights:
                operation_type: 0.30
                data_sensitivity: 0.20
                taint: 0.20
                session_accumulated: 0.10
                delegation_depth: 0.20
              escalation_threshold: 0.6
        """)
        resp = await client.post(
            "/v1/policies/sync",
            content=updated_yaml.encode(),
            headers=headers,
        )
        assert resp.status_code == 200
        sync2 = resp.json()
        assert sync2["status"] == "applied"
        assert sync2["roles_count"] == 3
        assert sync2["rules_count"] == 3
        diff2 = sync2["diff"]
        assert diff2["total_changes"] > 0

    def test_directory_load_and_diff(
        self,
        loader: YAMLPolicyLoader,
        differ: PolicyDiffEngine,
        policy_dir: Path,
    ) -> None:
        """Load from directory, modify, diff."""
        bundle_v1 = loader.load_directory(policy_dir)

        # Create a modified version
        bundle_v2 = loader.load_directory(policy_dir)
        from app.models.policy import AgentRole
        bundle_v2.roles.append(AgentRole(role_id="new-role", name="New Role"))

        result = differ.diff(bundle_v1, bundle_v2)
        assert result.has_changes
        assert len(result.added) == 1
        assert result.added[0].key == "new-role"

    def test_load_validate_hydrate_roundtrip(
        self, loader: YAMLPolicyLoader, sample_bundle_yaml: str
    ) -> None:
        """Parse → validate → hydrate → verify objects."""
        bundle = loader.load_yaml_string(sample_bundle_yaml)

        # Verify all object types are properly hydrated
        assert all(hasattr(r, "role_id") for r in bundle.roles)
        assert all(hasattr(r, "tool_pattern") for r in bundle.rules)
        assert bundle.risk_model is not None
        assert hasattr(bundle.risk_model, "escalation_threshold")
        assert all(hasattr(g, "function_pattern") for g in bundle.sanitisation_gates)
        assert all(hasattr(s, "signature_id") for s in bundle.injection_signatures)
        assert all(hasattr(l, "rank") for l in bundle.classification_levels)
        assert all(hasattr(t, "tool_pattern") for t in bundle.tool_classifications)
