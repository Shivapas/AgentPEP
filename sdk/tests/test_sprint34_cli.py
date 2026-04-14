"""Sprint 34 — APEP-275: CLI integration tests.

End-to-end tests for the agentpep CLI workflow:
  validate → diff → simulate → redteam generate → redteam run →
  policy migrate → receipt verify → health check.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml


# ---------------------------------------------------------------------------
# Fixtures — policy YAML files
# ---------------------------------------------------------------------------

POLICY_V1_YAML = textwrap.dedent("""\
    schema_version: "1.0"
    metadata:
      name: test-policy
      author: test-suite

    roles:
      - role_id: admin
        name: Administrator
        allowed_tools: ["*"]
        denied_tools: []
        max_risk_threshold: 1.0
      - role_id: reader
        name: Read-only Agent
        allowed_tools: ["file.read", "web.search"]
        denied_tools: ["admin.*", "db.execute", "system.*"]
        max_risk_threshold: 0.5

    rules:
      - name: allow-read-ops
        tool_pattern: "file.read"
        action: ALLOW
        agent_roles: ["reader", "admin"]
        priority: 10
      - name: allow-web-search
        tool_pattern: "web.search"
        action: ALLOW
        agent_roles: ["reader", "admin"]
        priority: 20
      - name: deny-admin-tools
        tool_pattern: "admin.*"
        action: DENY
        agent_roles: ["reader"]
        priority: 5
      - name: deny-destructive
        tool_pattern: "db.execute"
        action: DENY
        agent_roles: ["reader"]
        priority: 5
      - name: deny-system
        tool_pattern: "system.*"
        action: DENY
        agent_roles: ["reader"]
        priority: 5
      - name: allow-admin-all
        tool_pattern: "*"
        action: ALLOW
        agent_roles: ["admin"]
        priority: 100

    risk:
      escalation_threshold: 0.7
      default_weights:
        operation_type: 0.25
        data_sensitivity: 0.25
        taint: 0.20
        session_accumulated: 0.10
        delegation_depth: 0.20

    taint:
      max_hop_depth: 10
      quarantine_on_injection: true
""")

POLICY_V2_YAML = textwrap.dedent("""\
    schema_version: "1.0"
    metadata:
      name: test-policy-v2
      author: test-suite

    roles:
      - role_id: admin
        name: Administrator
        allowed_tools: ["*"]
        denied_tools: []
        max_risk_threshold: 1.0
      - role_id: reader
        name: Read-only Agent
        allowed_tools: ["file.read", "web.search", "math.calculate"]
        denied_tools: ["admin.*", "db.execute", "system.*"]
        max_risk_threshold: 0.6
      - role_id: analyst
        name: Analyst Agent
        allowed_tools: ["db.query", "file.read"]
        denied_tools: ["admin.*"]
        max_risk_threshold: 0.8

    rules:
      - name: allow-read-ops
        tool_pattern: "file.read"
        action: ALLOW
        agent_roles: ["reader", "admin", "analyst"]
        priority: 10
      - name: allow-web-search
        tool_pattern: "web.search"
        action: ALLOW
        agent_roles: ["reader", "admin"]
        priority: 20
      - name: deny-admin-tools
        tool_pattern: "admin.*"
        action: DENY
        agent_roles: ["reader", "analyst"]
        priority: 5
      - name: deny-destructive
        tool_pattern: "db.execute"
        action: DENY
        agent_roles: ["reader"]
        priority: 5
      - name: deny-system
        tool_pattern: "system.*"
        action: DENY
        agent_roles: ["reader"]
        priority: 5
      - name: allow-admin-all
        tool_pattern: "*"
        action: ALLOW
        agent_roles: ["admin"]
        priority: 100
      - name: allow-math
        tool_pattern: "math.*"
        action: ALLOW
        agent_roles: ["reader"]
        priority: 30

    risk:
      escalation_threshold: 0.8
      default_weights:
        operation_type: 0.25
        data_sensitivity: 0.25
        taint: 0.20
        session_accumulated: 0.10
        delegation_depth: 0.20

    taint:
      max_hop_depth: 15
      quarantine_on_injection: true
""")


@pytest.fixture()
def policy_v1_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy_v1.yaml"
    p.write_text(POLICY_V1_YAML)
    return p


@pytest.fixture()
def policy_v2_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy_v2.yaml"
    p.write_text(POLICY_V2_YAML)
    return p


@pytest.fixture()
def invalid_policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "invalid.yaml"
    p.write_text(textwrap.dedent("""\
        schema_version: "1.0"
        roles:
          - role_id: admin
            name: Admin
        rules: []
    """))
    return p


# ===================================================================
# APEP-267: CLI foundation — policy validate, diff, simulate
# ===================================================================


class TestPolicyValidate:
    """APEP-267: agentpep policy validate"""

    def test_validate_valid_policy(self, policy_v1_file: Path) -> None:
        from agentpep.cli import cmd_policy_validate
        import argparse

        args = argparse.Namespace(file=str(policy_v1_file))
        rc = cmd_policy_validate(args)
        assert rc == 0

    def test_validate_missing_file(self, tmp_path: Path) -> None:
        from agentpep.cli import cmd_policy_validate
        import argparse

        args = argparse.Namespace(file=str(tmp_path / "nonexistent.yaml"))
        rc = cmd_policy_validate(args)
        assert rc == 1

    def test_validate_empty_rules(self, invalid_policy_file: Path) -> None:
        from agentpep.cli import cmd_policy_validate
        import argparse

        args = argparse.Namespace(file=str(invalid_policy_file))
        rc = cmd_policy_validate(args)
        assert rc == 1  # No rules defined

    def test_validate_duplicate_roles(self, tmp_path: Path) -> None:
        from agentpep.cli import cmd_policy_validate
        import argparse

        p = tmp_path / "dup_roles.yaml"
        p.write_text(textwrap.dedent("""\
            schema_version: "1.0"
            roles:
              - role_id: reader
                name: Reader One
              - role_id: reader
                name: Reader Two
            rules:
              - name: allow-read
                tool_pattern: "file.read"
                action: ALLOW
        """))
        args = argparse.Namespace(file=str(p))
        rc = cmd_policy_validate(args)
        assert rc == 1

    def test_validate_unknown_role_reference(self, tmp_path: Path) -> None:
        from agentpep.cli import cmd_policy_validate
        import argparse

        p = tmp_path / "bad_ref.yaml"
        p.write_text(textwrap.dedent("""\
            schema_version: "1.0"
            roles:
              - role_id: admin
                name: Admin
            rules:
              - name: allow-read
                tool_pattern: "file.read"
                action: ALLOW
                agent_roles: ["nonexistent_role"]
        """))
        args = argparse.Namespace(file=str(p))
        rc = cmd_policy_validate(args)
        assert rc == 1


class TestPolicyDiff:
    """APEP-267: agentpep policy diff"""

    def test_diff_identical(self, policy_v1_file: Path) -> None:
        from agentpep.cli import cmd_policy_diff
        import argparse

        args = argparse.Namespace(
            file_a=str(policy_v1_file),
            file_b=str(policy_v1_file),
            json=False,
        )
        rc = cmd_policy_diff(args)
        assert rc == 0

    def test_diff_with_changes(
        self, policy_v1_file: Path, policy_v2_file: Path
    ) -> None:
        from agentpep.cli import cmd_policy_diff
        import argparse

        args = argparse.Namespace(
            file_a=str(policy_v1_file),
            file_b=str(policy_v2_file),
            json=False,
        )
        rc = cmd_policy_diff(args)
        # Changes detected — returns 0 (diff succeeded, not an error)
        assert rc == 0

    def test_diff_json_output(
        self, policy_v1_file: Path, policy_v2_file: Path, capsys: Any
    ) -> None:
        from agentpep.cli import cmd_policy_diff
        import argparse

        args = argparse.Namespace(
            file_a=str(policy_v1_file),
            file_b=str(policy_v2_file),
            json=True,
        )
        cmd_policy_diff(args)
        captured = capsys.readouterr()
        assert "JSON Output" in captured.out

    def test_diff_missing_file(self, policy_v1_file: Path, tmp_path: Path) -> None:
        from agentpep.cli import cmd_policy_diff
        import argparse

        args = argparse.Namespace(
            file_a=str(policy_v1_file),
            file_b=str(tmp_path / "missing.yaml"),
            json=False,
        )
        rc = cmd_policy_diff(args)
        assert rc == 1


class TestSimulate:
    """APEP-267: agentpep simulate"""

    def test_simulate_allowed_call(self, policy_v1_file: Path) -> None:
        from agentpep.cli import cmd_simulate
        import argparse

        args = argparse.Namespace(
            policy_file=str(policy_v1_file),
            agent_id="bot",
            tool_name="file.read",
            tool_args=None,
            role="reader",
            taint_flags=None,
            delegation_chain=None,
            json=False,
        )
        rc = cmd_simulate(args)
        assert rc == 0

    def test_simulate_denied_call(self, policy_v1_file: Path) -> None:
        from agentpep.cli import cmd_simulate
        import argparse

        args = argparse.Namespace(
            policy_file=str(policy_v1_file),
            agent_id="bot",
            tool_name="admin.delete_user",
            tool_args=None,
            role="reader",
            taint_flags=None,
            delegation_chain=None,
            json=False,
        )
        rc = cmd_simulate(args)
        assert rc == 1  # DENY = exit code 1

    def test_simulate_json_output(
        self, policy_v1_file: Path, capsys: Any
    ) -> None:
        from agentpep.cli import cmd_simulate
        import argparse

        args = argparse.Namespace(
            policy_file=str(policy_v1_file),
            agent_id="bot",
            tool_name="file.read",
            tool_args=None,
            role="reader",
            taint_flags=None,
            delegation_chain=None,
            json=True,
        )
        cmd_simulate(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["decision"] == "ALLOW"

    def test_simulate_with_tool_args(self, policy_v1_file: Path) -> None:
        from agentpep.cli import cmd_simulate
        import argparse

        args = argparse.Namespace(
            policy_file=str(policy_v1_file),
            agent_id="bot",
            tool_name="file.read",
            tool_args='{"path": "/data/report.csv"}',
            role="reader",
            taint_flags=None,
            delegation_chain=None,
            json=False,
        )
        rc = cmd_simulate(args)
        assert rc == 0

    def test_simulate_missing_policy(self, tmp_path: Path) -> None:
        from agentpep.cli import cmd_simulate
        import argparse

        args = argparse.Namespace(
            policy_file=str(tmp_path / "missing.yaml"),
            agent_id="bot",
            tool_name="file.read",
            tool_args=None,
            role="*",
            taint_flags=None,
            delegation_chain=None,
            json=False,
        )
        rc = cmd_simulate(args)
        assert rc == 1


# ===================================================================
# APEP-268: redteam generate
# ===================================================================


class TestRedTeamGenerate:
    """APEP-268: agentpep redteam generate"""

    def test_generate_default(self, policy_v1_file: Path) -> None:
        from agentpep.redteam import RedTeamGenerator

        gen = RedTeamGenerator.from_policy_file(policy_v1_file)
        vectors = gen.generate()
        assert len(vectors) > 0
        # Check all expected categories are covered
        categories = {v.category for v in vectors}
        assert "privilege_escalation" in categories
        assert "injection" in categories

    def test_generate_specific_category(self, policy_v1_file: Path) -> None:
        from agentpep.redteam import RedTeamGenerator

        gen = RedTeamGenerator.from_policy_file(policy_v1_file)
        vectors = gen.generate(categories=["injection"], count=5)
        assert len(vectors) <= 5
        assert all(v.category == "injection" for v in vectors)

    def test_generate_serializable(self, policy_v1_file: Path) -> None:
        from agentpep.redteam import RedTeamGenerator

        gen = RedTeamGenerator.from_policy_file(policy_v1_file)
        vectors = gen.generate(count=3)
        # All should be serializable to dict/JSON
        for v in vectors:
            d = v.to_dict()
            assert isinstance(d, dict)
            assert "vector_id" in d
            json.dumps(d)  # Must not raise

    def test_generate_to_file(self, policy_v1_file: Path, tmp_path: Path) -> None:
        from agentpep.cli import cmd_redteam_generate
        import argparse

        out = tmp_path / "vectors.json"
        args = argparse.Namespace(
            policy_file=str(policy_v1_file),
            output=str(out),
            categories=None,
            count=5,
        )
        rc = cmd_redteam_generate(args)
        assert rc == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert isinstance(data, list)
        assert len(data) > 0

    def test_generate_all_categories(self, policy_v1_file: Path) -> None:
        from agentpep.redteam import RedTeamGenerator

        gen = RedTeamGenerator.from_policy_file(policy_v1_file)
        vectors = gen.generate(count=3)
        categories = {v.category for v in vectors}
        expected = {
            "privilege_escalation", "injection", "data_exfiltration",
            "confused_deputy", "taint_bypass",
        }
        assert categories == expected


# ===================================================================
# APEP-269: redteam run
# ===================================================================


class TestRedTeamRun:
    """APEP-269: agentpep redteam run"""

    def test_run_default_suite(self, policy_v1_file: Path) -> None:
        from agentpep.redteam import RedTeamRunner

        runner = RedTeamRunner.from_policy_file(policy_v1_file)
        report = runner.run()
        assert report.total > 0
        assert report.passed + report.failed == report.total

    def test_run_from_file(
        self, policy_v1_file: Path, tmp_path: Path
    ) -> None:
        from agentpep.redteam import RedTeamGenerator, RedTeamRunner

        # Generate vectors
        gen = RedTeamGenerator.from_policy_file(policy_v1_file)
        vectors = gen.generate(count=3)
        suite_file = tmp_path / "suite.json"
        suite_file.write_text(
            json.dumps([v.to_dict() for v in vectors], default=str)
        )

        # Run from file
        runner = RedTeamRunner.from_policy_file(policy_v1_file)
        suite_data = json.loads(suite_file.read_text())
        report = runner.run(vectors=suite_data)
        assert report.total == len(vectors)

    def test_run_report_serializable(self, policy_v1_file: Path) -> None:
        from agentpep.redteam import RedTeamRunner

        runner = RedTeamRunner.from_policy_file(policy_v1_file)
        report = runner.run()
        d = report.to_dict()
        assert "total" in d
        assert "passed" in d
        assert "failed" in d
        assert "pass_rate" in d
        json.dumps(d)  # Must not raise

    def test_run_cli_command(self, policy_v1_file: Path) -> None:
        from agentpep.cli import cmd_redteam_run
        import argparse

        args = argparse.Namespace(
            policy_file=str(policy_v1_file),
            suite=None,
            output=None,
            json=True,
        )
        # Should return 0 or 1 depending on results — no exceptions
        rc = cmd_redteam_run(args)
        assert rc in (0, 1)


# ===================================================================
# APEP-271: Policy migration
# ===================================================================


class TestPolicyMigration:
    """APEP-271: agentpep policy migrate"""

    def test_migrate_1_0_to_2_0(self, policy_v1_file: Path) -> None:
        from agentpep.policy_migration import PolicyMigrator

        migrator = PolicyMigrator()
        result = migrator.migrate_file(policy_v1_file, target_version="2.0")
        assert result.source_version == "1.0"
        assert result.target_version == "2.0"
        assert len(result.changes) > 0

        # Verify migrated data
        migrated = result.migrated_data
        assert migrated["schema_version"] == "2.0"
        assert "context_authority" in migrated
        assert "trust_degradation" in migrated

    def test_migrate_preserves_roles(self, policy_v1_file: Path) -> None:
        from agentpep.policy_migration import PolicyMigrator

        migrator = PolicyMigrator()
        result = migrator.migrate_file(policy_v1_file, target_version="2.0")
        migrated = result.migrated_data

        roles = migrated["roles"]
        assert len(roles) == 2
        role_ids = {r["role_id"] for r in roles}
        assert role_ids == {"admin", "reader"}
        # New field added
        for role in roles:
            assert "max_delegation_depth" in role

    def test_migrate_preserves_rules(self, policy_v1_file: Path) -> None:
        from agentpep.policy_migration import PolicyMigrator

        migrator = PolicyMigrator()
        result = migrator.migrate_file(policy_v1_file, target_version="2.0")
        migrated = result.migrated_data

        rules = migrated["rules"]
        assert len(rules) == 6  # Same as v1

    def test_migrate_same_version(self, policy_v1_file: Path) -> None:
        from agentpep.policy_migration import PolicyMigrator

        migrator = PolicyMigrator()
        result = migrator.migrate_file(policy_v1_file, target_version="1.0")
        assert "No migration needed" in result.warnings[0]

    def test_migrate_output_parseable(self, policy_v1_file: Path) -> None:
        from agentpep.policy_migration import PolicyMigrator

        migrator = PolicyMigrator()
        result = migrator.migrate_file(policy_v1_file, target_version="2.0")
        # Output should be valid YAML
        parsed = yaml.safe_load(result.yaml_output)
        assert parsed["schema_version"] == "2.0"

    def test_migrate_cli_command(
        self, policy_v1_file: Path, tmp_path: Path
    ) -> None:
        from agentpep.cli import cmd_policy_migrate
        import argparse

        out = tmp_path / "migrated.yaml"
        args = argparse.Namespace(
            file=str(policy_v1_file),
            target_version="2.0",
            output=str(out),
        )
        rc = cmd_policy_migrate(args)
        assert rc == 0
        assert out.exists()
        parsed = yaml.safe_load(out.read_text())
        assert parsed["schema_version"] == "2.0"


# ===================================================================
# APEP-272: Simulation comparison
# ===================================================================


class TestSimulationCompare:
    """APEP-272: Simulation result comparison"""

    def test_compare_identical_policies(self, policy_v1_file: Path) -> None:
        from agentpep.simulation_compare import (
            SimulationComparator,
            ToolCallSpec,
        )

        comparator = SimulationComparator()
        report = comparator.compare(
            policy_a=policy_v1_file,
            policy_b=policy_v1_file,
            tool_calls=[
                ToolCallSpec(agent_id="bot", tool_name="file.read", role="reader"),
            ],
        )
        assert report.decision_changes == 0

    def test_compare_different_policies(
        self, policy_v1_file: Path, policy_v2_file: Path
    ) -> None:
        from agentpep.simulation_compare import (
            SimulationComparator,
            ToolCallSpec,
        )

        comparator = SimulationComparator()
        report = comparator.compare(
            policy_a=policy_v1_file,
            policy_b=policy_v2_file,
            tool_calls=[
                ToolCallSpec(agent_id="bot", tool_name="file.read", role="reader"),
                ToolCallSpec(agent_id="bot", tool_name="math.calculate", role="reader"),
                ToolCallSpec(agent_id="bot", tool_name="admin.delete", role="reader"),
            ],
            label_a="v1",
            label_b="v2",
        )
        assert report.total_compared == 3

    def test_compare_report_serializable(
        self, policy_v1_file: Path, policy_v2_file: Path
    ) -> None:
        from agentpep.simulation_compare import (
            SimulationComparator,
            ToolCallSpec,
        )

        comparator = SimulationComparator()
        report = comparator.compare(
            policy_a=policy_v1_file,
            policy_b=policy_v2_file,
            tool_calls=[
                ToolCallSpec(agent_id="bot", tool_name="file.read", role="reader"),
            ],
        )
        d = report.to_dict()
        assert "summary" in d
        json.dumps(d, default=str)

    def test_compare_visual_output(
        self, policy_v1_file: Path, policy_v2_file: Path
    ) -> None:
        from agentpep.simulation_compare import (
            SimulationComparator,
            ToolCallSpec,
        )

        comparator = SimulationComparator()
        report = comparator.compare(
            policy_a=policy_v1_file,
            policy_b=policy_v2_file,
            tool_calls=[
                ToolCallSpec(agent_id="bot", tool_name="file.read", role="reader"),
            ],
            label_a="before",
            label_b="after",
        )
        visual = report.format_visual()
        assert "Simulation Comparison" in visual
        assert "before" in visual
        assert "after" in visual


# ===================================================================
# APEP-273: Receipt verify CLI
# ===================================================================


class TestReceiptVerify:
    """APEP-273: agentpep receipt verify"""

    @pytest.fixture()
    def hmac_key_and_receipt(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create a valid HMAC key file and receipts file."""
        # Generate key
        key_bytes = b"test-secret-key-for-hmac-256!!"
        b64_key = base64.urlsafe_b64encode(key_bytes).decode()
        key_file = tmp_path / "verify.key"
        key_file.write_text(f"hmac-sha256:{b64_key}")

        # Create a record and sign it
        record = {"decision_id": "d-001", "decision": "ALLOW", "tool": "file.read"}
        canonical = json.dumps(record, sort_keys=True, default=str).encode("utf-8")
        content_hash = hashlib.sha256(canonical).digest()
        signature = hmac.new(key_bytes, canonical, hashlib.sha256).digest()

        receipt = (
            f"agentpep-receipt-v1|default|hmac-sha256|"
            f"{base64.urlsafe_b64encode(content_hash).decode()}|"
            f"{base64.urlsafe_b64encode(signature).decode()}"
        )

        receipts_file = tmp_path / "receipts.jsonl"
        receipts_file.write_text(
            json.dumps({"receipt": receipt, "record": record}) + "\n"
        )

        return key_file, receipts_file

    def test_verify_valid_receipt(
        self, hmac_key_and_receipt: tuple[Path, Path]
    ) -> None:
        from agentpep.receipt_verify import batch_verify_receipts

        key_file, receipts_file = hmac_key_and_receipt
        rc = batch_verify_receipts(
            receipts_file=str(receipts_file),
            key_file=str(key_file),
        )
        assert rc == 0

    def test_verify_invalid_receipt(self, tmp_path: Path) -> None:
        from agentpep.receipt_verify import batch_verify_receipts

        key_bytes = b"test-key"
        b64_key = base64.urlsafe_b64encode(key_bytes).decode()
        key_file = tmp_path / "verify.key"
        key_file.write_text(f"hmac-sha256:{b64_key}")

        receipts_file = tmp_path / "receipts.jsonl"
        receipts_file.write_text(
            json.dumps({
                "receipt": "agentpep-receipt-v1|default|hmac-sha256|AAAA|BBBB",
                "record": {"decision_id": "d-002"},
            }) + "\n"
        )

        rc = batch_verify_receipts(
            receipts_file=str(receipts_file),
            key_file=str(key_file),
        )
        assert rc == 1

    def test_verify_missing_key_file(self, tmp_path: Path) -> None:
        from agentpep.receipt_verify import batch_verify_receipts

        receipts_file = tmp_path / "receipts.jsonl"
        receipts_file.write_text("{}\n")

        rc = batch_verify_receipts(
            receipts_file=str(receipts_file),
            key_file=str(tmp_path / "missing.key"),
        )
        assert rc == 1

    def test_verify_cli_command(
        self, hmac_key_and_receipt: tuple[Path, Path]
    ) -> None:
        from agentpep.cli import cmd_receipt_verify
        import argparse

        key_file, receipts_file = hmac_key_and_receipt
        args = argparse.Namespace(
            receipts_file=str(receipts_file),
            key_file=str(key_file),
            key_id="default",
            verbose=True,
        )
        rc = cmd_receipt_verify(args)
        assert rc == 0


# ===================================================================
# APEP-274: Health CLI
# ===================================================================


class TestHealthCheck:
    """APEP-274: agentpep health"""

    def test_health_unreachable_server(self) -> None:
        from agentpep.health_check import check_health

        # Use a port that's definitely not running AgentPEP
        rc = check_health(
            base_url="http://127.0.0.1:19999",
            timeout=1.0,
        )
        assert rc == 1

    def test_health_cli_command(self) -> None:
        from agentpep.cli import cmd_health
        import argparse

        args = argparse.Namespace(
            base_url="http://127.0.0.1:19999",
            api_key=None,
            timeout=1.0,
            verbose=False,
        )
        rc = cmd_health(args)
        assert rc == 1


# ===================================================================
# APEP-275: End-to-end CLI workflow test
# ===================================================================


class TestE2EWorkflow:
    """APEP-275: End-to-end validate -> simulate -> redteam -> verify"""

    def test_full_workflow(
        self, policy_v1_file: Path, policy_v2_file: Path, tmp_path: Path
    ) -> None:
        """Integration test: validate -> diff -> simulate -> redteam -> migrate."""
        import argparse
        from agentpep.cli import (
            cmd_policy_validate,
            cmd_policy_diff,
            cmd_simulate,
            cmd_redteam_generate,
            cmd_redteam_run,
            cmd_policy_migrate,
        )

        # Step 1: Validate policy
        rc = cmd_policy_validate(argparse.Namespace(file=str(policy_v1_file)))
        assert rc == 0, "Policy validation failed"

        # Step 2: Diff two policies
        rc = cmd_policy_diff(argparse.Namespace(
            file_a=str(policy_v1_file),
            file_b=str(policy_v2_file),
            json=False,
        ))
        assert rc == 0, "Policy diff failed"

        # Step 3: Simulate a tool call
        rc = cmd_simulate(argparse.Namespace(
            policy_file=str(policy_v1_file),
            agent_id="bot",
            tool_name="file.read",
            tool_args=None,
            role="reader",
            taint_flags=None,
            delegation_chain=None,
            json=False,
        ))
        assert rc == 0, "Simulation failed — expected ALLOW"

        # Step 4: Generate adversarial suite
        suite_file = tmp_path / "adversarial.json"
        rc = cmd_redteam_generate(argparse.Namespace(
            policy_file=str(policy_v1_file),
            output=str(suite_file),
            categories=None,
            count=3,
        ))
        assert rc == 0, "Red team generation failed"
        assert suite_file.exists()

        # Step 5: Run adversarial suite
        rc = cmd_redteam_run(argparse.Namespace(
            policy_file=str(policy_v1_file),
            suite=str(suite_file),
            output=None,
            json=True,
        ))
        # rc may be 0 (all denied correctly) or 1 (some passed)
        assert rc in (0, 1), "Red team run errored out"

        # Step 6: Migrate policy
        migrated_file = tmp_path / "migrated.yaml"
        rc = cmd_policy_migrate(argparse.Namespace(
            file=str(policy_v1_file),
            target_version="2.0",
            output=str(migrated_file),
        ))
        assert rc == 0, "Policy migration failed"
        assert migrated_file.exists()

        # Verify migrated file is valid YAML
        migrated_data = yaml.safe_load(migrated_file.read_text())
        assert migrated_data["schema_version"] == "2.0"

    def test_cli_parser_construction(self) -> None:
        """Verify the argument parser can be constructed without errors."""
        from agentpep.cli import build_parser

        parser = build_parser()
        assert parser is not None
        assert parser.prog == "agentpep"

    def test_cli_main_no_args(self) -> None:
        """agentpep with no args shows help and exits 0."""
        from agentpep.cli import main

        rc = main([])
        assert rc == 0
