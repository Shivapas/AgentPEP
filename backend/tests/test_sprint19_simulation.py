"""Tests for Sprint 19 — Policy Simulation Engine.

APEP-151: POST /v1/simulate endpoint
APEP-152: Full simulation result (decision, matched rule, risk score, taint, chain)
APEP-154: Simulation comparison (two policy versions, diff)
APEP-155: Test vector library
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.policy import Decision, PolicyRule
from app.services.test_vectors import (
    ALL_VECTORS,
    BENIGN_VECTORS,
    VECTORS_BY_CATEGORY,
    VECTORS_BY_ID,
    get_vectors,
)


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# APEP-151: POST /v1/simulate
# ---------------------------------------------------------------------------


class TestSimulateEndpoint:
    """APEP-151: Simulate endpoint evaluates without enforcement."""

    @pytest.mark.asyncio
    async def test_simulate_returns_decision(self, client: AsyncClient):
        """POST /v1/simulate returns a simulation result with decision."""
        resp = await client.post("/v1/simulate", json={
            "agent_id": "test-agent",
            "tool_name": "file.read",
            "tool_args": {"path": "/tmp/test.txt"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "decision" in data
        assert data["decision"] in ["ALLOW", "DENY", "ESCALATE", "DRY_RUN", "TIMEOUT"]

    @pytest.mark.asyncio
    async def test_simulate_deny_by_default(self, client: AsyncClient):
        """With no rules configured, simulation should result in DENY."""
        resp = await client.post("/v1/simulate", json={
            "agent_id": "unknown-agent",
            "tool_name": "unknown.tool",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "DENY"

    @pytest.mark.asyncio
    async def test_simulate_with_matching_rule(self, client: AsyncClient, mock_mongodb):
        """Simulation matches a configured rule and returns its details."""
        await mock_mongodb["policy_rules"].insert_one({
            "rule_id": "00000000-0000-0000-0000-000000000001",
            "name": "allow-file-read",
            "agent_role": ["*"],
            "tool_pattern": "file.read",
            "action": "ALLOW",
            "priority": 10,
            "enabled": True,
            "taint_check": False,
            "risk_threshold": 0.5,
            "arg_validators": [],
        })

        # Clear rule cache so it picks up the new rule
        from app.services.rule_cache import rule_cache
        rule_cache.invalidate()

        resp = await client.post("/v1/simulate", json={
            "agent_id": "test-agent",
            "tool_name": "file.read",
            "tool_args": {"path": "/data/report.csv"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "ALLOW"
        assert data["matched_rule_name"] == "allow-file-read"

    @pytest.mark.asyncio
    async def test_simulate_with_explicit_rules(self, client: AsyncClient):
        """Simulation can use explicitly provided policy rules."""
        resp = await client.post("/v1/simulate", json={
            "agent_id": "test-agent",
            "tool_name": "db.query",
            "policy_rules": [
                {
                    "name": "allow-db",
                    "agent_role": ["*"],
                    "tool_pattern": "db.*",
                    "action": "ALLOW",
                    "priority": 10,
                    "enabled": True,
                },
            ],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "ALLOW"
        assert data["matched_rule_name"] == "allow-db"


# ---------------------------------------------------------------------------
# APEP-152: Full simulation result
# ---------------------------------------------------------------------------


class TestSimulationResult:
    """APEP-152: Full simulation result includes all evaluation details."""

    @pytest.mark.asyncio
    async def test_result_has_all_fields(self, client: AsyncClient):
        """Simulation result contains decision, steps, roles, taint, chain."""
        resp = await client.post("/v1/simulate", json={
            "agent_id": "test-agent",
            "tool_name": "file.read",
        })
        assert resp.status_code == 200
        data = resp.json()

        # Required fields
        assert "request_id" in data
        assert "decision" in data
        assert "risk_score" in data
        assert "taint_eval" in data
        assert "chain_result" in data
        assert "resolved_roles" in data
        assert "steps" in data
        assert "reason" in data
        assert "latency_ms" in data
        assert "policy_version" in data

    @pytest.mark.asyncio
    async def test_result_has_evaluation_steps(self, client: AsyncClient):
        """Simulation trace includes step-by-step evaluation details."""
        resp = await client.post("/v1/simulate", json={
            "agent_id": "test-agent",
            "tool_name": "file.read",
        })
        data = resp.json()
        steps = data["steps"]
        assert len(steps) > 0
        for step in steps:
            assert "step" in step
            assert "passed" in step
            assert "detail" in step

    @pytest.mark.asyncio
    async def test_result_includes_resolved_roles(self, client: AsyncClient):
        """Simulation result includes resolved agent roles."""
        resp = await client.post("/v1/simulate", json={
            "agent_id": "test-agent",
            "tool_name": "file.read",
        })
        data = resp.json()
        assert isinstance(data["resolved_roles"], list)

    @pytest.mark.asyncio
    async def test_result_latency_is_positive(self, client: AsyncClient):
        """Simulation latency is recorded."""
        resp = await client.post("/v1/simulate", json={
            "agent_id": "test-agent",
            "tool_name": "file.read",
        })
        data = resp.json()
        assert data["latency_ms"] >= 0


# ---------------------------------------------------------------------------
# APEP-154: Simulation comparison
# ---------------------------------------------------------------------------


class TestSimulationCompare:
    """APEP-154: Compare simulation results across two policy versions."""

    @pytest.mark.asyncio
    async def test_compare_same_rules_no_changes(self, client: AsyncClient):
        """Identical rules produce no decision or risk diff."""
        rule_id = "00000000-0000-0000-0000-000000000099"
        rules = [
            {
                "rule_id": rule_id,
                "name": "allow-read",
                "agent_role": ["*"],
                "tool_pattern": "file.read",
                "action": "ALLOW",
                "priority": 10,
                "enabled": True,
            },
        ]
        resp = await client.post("/v1/simulate/compare", json={
            "agent_id": "test-agent",
            "tool_name": "file.read",
            "version_a_label": "v1",
            "version_a_rules": rules,
            "version_b_label": "v2",
            "version_b_rules": rules,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision_changed"] is False
        assert data["matched_rule_changed"] is False
        assert data["risk_score_changed"] is False

    @pytest.mark.asyncio
    async def test_compare_different_decisions(self, client: AsyncClient):
        """Different rules produce a decision diff."""
        rules_a = [
            {
                "name": "allow-read",
                "agent_role": ["*"],
                "tool_pattern": "file.read",
                "action": "ALLOW",
                "priority": 10,
                "enabled": True,
            },
        ]
        rules_b = [
            {
                "name": "deny-read",
                "agent_role": ["*"],
                "tool_pattern": "file.read",
                "action": "DENY",
                "priority": 10,
                "enabled": True,
            },
        ]
        resp = await client.post("/v1/simulate/compare", json={
            "agent_id": "test-agent",
            "tool_name": "file.read",
            "version_a_label": "permissive",
            "version_a_rules": rules_a,
            "version_b_label": "restrictive",
            "version_b_rules": rules_b,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision_changed"] is True
        assert data["version_a"]["decision"] == "ALLOW"
        assert data["version_b"]["decision"] == "DENY"

    @pytest.mark.asyncio
    async def test_compare_returns_both_versions(self, client: AsyncClient):
        """Compare response includes full results for both versions."""
        rules = [{"name": "r", "agent_role": ["*"], "tool_pattern": "*", "action": "ALLOW", "priority": 1, "enabled": True}]
        resp = await client.post("/v1/simulate/compare", json={
            "agent_id": "agent",
            "tool_name": "tool",
            "version_a_label": "a",
            "version_a_rules": rules,
            "version_b_label": "b",
            "version_b_rules": rules,
        })
        data = resp.json()
        assert "version_a" in data
        assert "version_b" in data
        assert data["version_a"]["policy_version"] == "a"
        assert data["version_b"]["policy_version"] == "b"


# ---------------------------------------------------------------------------
# APEP-155: Test vector library
# ---------------------------------------------------------------------------


class TestTestVectorLibrary:
    """APEP-155: Curated library of benign and adversarial test vectors."""

    def test_library_has_vectors(self):
        """Library contains test vectors."""
        assert len(ALL_VECTORS) > 0

    def test_vectors_have_unique_ids(self):
        """All vector IDs are unique."""
        ids = [v.vector_id for v in ALL_VECTORS]
        assert len(ids) == len(set(ids))

    def test_vectors_by_category(self):
        """Vectors are categorised correctly."""
        assert "benign" in VECTORS_BY_CATEGORY
        assert "privilege_escalation" in VECTORS_BY_CATEGORY
        assert "injection" in VECTORS_BY_CATEGORY
        assert "data_exfiltration" in VECTORS_BY_CATEGORY
        assert "confused_deputy" in VECTORS_BY_CATEGORY
        assert "taint_bypass" in VECTORS_BY_CATEGORY

    def test_benign_vectors_expect_allow(self):
        """Benign vectors expect ALLOW decision."""
        for v in BENIGN_VECTORS:
            assert v.expected_decision == Decision.ALLOW, f"{v.vector_id} should expect ALLOW"

    def test_adversarial_vectors_expect_deny(self):
        """Adversarial vectors expect DENY decision."""
        adversarial = get_vectors(category="privilege_escalation") + \
                      get_vectors(category="injection") + \
                      get_vectors(category="data_exfiltration") + \
                      get_vectors(category="taint_bypass")
        for v in adversarial:
            assert v.expected_decision == Decision.DENY, f"{v.vector_id} should expect DENY"

    def test_filter_by_category(self):
        """get_vectors filters by category."""
        benign = get_vectors(category="benign")
        assert all(v.category == "benign" for v in benign)

    def test_filter_by_tag(self):
        """get_vectors filters by tag."""
        web = get_vectors(tags=["web"])
        assert all("web" in v.tags for v in web)

    def test_vector_lookup_by_id(self):
        """VECTORS_BY_ID provides O(1) lookup."""
        assert "TV-001" in VECTORS_BY_ID
        assert VECTORS_BY_ID["TV-001"].name == "Simple read operation"


class TestTestVectorAPI:
    """APEP-155: Test vector REST API endpoints."""

    @pytest.mark.asyncio
    async def test_list_vectors(self, client: AsyncClient):
        """GET /v1/simulate/vectors returns all vectors."""
        resp = await client.get("/v1/simulate/vectors")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == len(ALL_VECTORS)

    @pytest.mark.asyncio
    async def test_list_vectors_filter_category(self, client: AsyncClient):
        """GET /v1/simulate/vectors?category=benign filters correctly."""
        resp = await client.get("/v1/simulate/vectors", params={"category": "benign"})
        assert resp.status_code == 200
        data = resp.json()
        assert all(v["category"] == "benign" for v in data)

    @pytest.mark.asyncio
    async def test_list_categories(self, client: AsyncClient):
        """GET /v1/simulate/vectors/categories returns category list."""
        resp = await client.get("/v1/simulate/vectors/categories")
        assert resp.status_code == 200
        data = resp.json()
        assert "benign" in data
        assert "injection" in data

    @pytest.mark.asyncio
    async def test_get_vector_by_id(self, client: AsyncClient):
        """GET /v1/simulate/vectors/TV-001 returns specific vector."""
        resp = await client.get("/v1/simulate/vectors/TV-001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["vector_id"] == "TV-001"

    @pytest.mark.asyncio
    async def test_get_vector_not_found(self, client: AsyncClient):
        """GET /v1/simulate/vectors/NONEXISTENT returns 404."""
        resp = await client.get("/v1/simulate/vectors/NONEXISTENT")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_run_vector_suite(self, client: AsyncClient):
        """POST /v1/simulate/vectors/run executes test vector suite."""
        resp = await client.post("/v1/simulate/vectors/run", params={"category": "benign"})
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "passed" in data
        assert "failed" in data
        assert "results" in data
        assert data["total"] == len(BENIGN_VECTORS)
        # Results should have per-vector detail
        for r in data["results"]:
            assert "vector_id" in r
            assert "expected_decision" in r
            assert "actual_decision" in r
            assert "passed" in r
