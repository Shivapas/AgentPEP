"""Sprint 31 tests — Data Classification, Boundary Enforcement & Clearance.

APEP-246: Data classification hierarchy —
          PUBLIC → INTERNAL → CONFIDENTIAL → PII → PHI → FINANCIAL.
APEP-247: Data boundary enforcement — USER_ONLY → TEAM → ORGANISATION.
APEP-248: Clearance-level checking — agent roles mapped to max classification.
APEP-249: Integration tests for data classification enforcement.
"""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.models.data_classification import (
    BOUNDARY_LEVEL,
    CLASSIFICATION_LEVEL,
    DataBoundary,
    DataClassification,
    DataClassificationRule,
    boundary_gte,
    classification_gte,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    from app.main import app
    from tests.conftest import _get_auth_headers

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test", headers=_get_auth_headers()
    ) as ac:
        yield ac


def _make_request(**overrides):
    """Helper to build a valid ToolCallRequest payload."""
    payload = {
        "request_id": str(uuid.uuid4()),
        "session_id": "test-session",
        "agent_id": "test-agent",
        "tool_name": "read_file",
        "tool_args": {"path": "/tmp/test.txt"},
        "delegation_chain": [],
        "dry_run": False,
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# APEP-246: Data Classification Hierarchy
# ---------------------------------------------------------------------------


class TestDataClassificationHierarchy:
    """Tests for the classification level ordering."""

    def test_classification_ordering(self):
        """Classifications are ordered by sensitivity level."""
        assert CLASSIFICATION_LEVEL[DataClassification.PUBLIC] == 0
        assert CLASSIFICATION_LEVEL[DataClassification.INTERNAL] == 1
        assert CLASSIFICATION_LEVEL[DataClassification.CONFIDENTIAL] == 2
        assert CLASSIFICATION_LEVEL[DataClassification.PII] == 3
        assert CLASSIFICATION_LEVEL[DataClassification.PHI] == 4
        assert CLASSIFICATION_LEVEL[DataClassification.FINANCIAL] == 5

    def test_classification_monotonic(self):
        """Classification levels are strictly monotonically increasing."""
        levels = list(CLASSIFICATION_LEVEL.values())
        for i in range(1, len(levels)):
            assert levels[i] > levels[i - 1]

    def test_all_classifications_have_levels(self):
        """Every DataClassification enum value has a numeric level."""
        for cls in DataClassification:
            assert cls in CLASSIFICATION_LEVEL

    def test_classification_gte(self):
        """classification_gte correctly compares clearance levels."""
        # Agent with PII clearance can access PII and below
        assert classification_gte("PII", "PUBLIC") is True
        assert classification_gte("PII", "INTERNAL") is True
        assert classification_gte("PII", "CONFIDENTIAL") is True
        assert classification_gte("PII", "PII") is True

        # Agent with PII clearance cannot access PHI or FINANCIAL
        assert classification_gte("PII", "PHI") is False
        assert classification_gte("PII", "FINANCIAL") is False

    def test_classification_gte_same_level(self):
        """Agent with exact clearance level passes."""
        for cls in DataClassification:
            assert classification_gte(cls.value, cls.value) is True

    def test_classification_gte_unknown_defaults_public(self):
        """Unknown classification levels default to PUBLIC."""
        assert classification_gte("UNKNOWN", "PUBLIC") is True
        assert classification_gte("UNKNOWN", "INTERNAL") is False

    def test_classification_rule_model(self):
        """DataClassificationRule model validates correctly."""
        rule = DataClassificationRule(
            tool_pattern="db.read_*",
            classification=DataClassification.PII,
            boundary=DataBoundary.TEAM,
        )
        assert rule.classification == DataClassification.PII
        assert rule.boundary == DataBoundary.TEAM
        assert rule.enabled is True
        assert rule.rule_id is not None


# ---------------------------------------------------------------------------
# APEP-247: Data Boundary Enforcement
# ---------------------------------------------------------------------------


class TestDataBoundaryEnforcement:
    """Tests for data boundary scope ordering and checks."""

    def test_boundary_ordering(self):
        """Boundaries are ordered from narrowest to broadest."""
        assert BOUNDARY_LEVEL[DataBoundary.USER_ONLY] == 0
        assert BOUNDARY_LEVEL[DataBoundary.TEAM] == 1
        assert BOUNDARY_LEVEL[DataBoundary.ORGANISATION] == 2

    def test_boundary_gte(self):
        """boundary_gte correctly compares boundary scopes."""
        # ORGANISATION boundary can access everything
        assert boundary_gte("ORGANISATION", "USER_ONLY") is True
        assert boundary_gte("ORGANISATION", "TEAM") is True
        assert boundary_gte("ORGANISATION", "ORGANISATION") is True

        # USER_ONLY boundary can only access USER_ONLY
        assert boundary_gte("USER_ONLY", "USER_ONLY") is True
        assert boundary_gte("USER_ONLY", "TEAM") is False
        assert boundary_gte("USER_ONLY", "ORGANISATION") is False

        # TEAM boundary can access TEAM and USER_ONLY
        assert boundary_gte("TEAM", "USER_ONLY") is True
        assert boundary_gte("TEAM", "TEAM") is True
        assert boundary_gte("TEAM", "ORGANISATION") is False

    def test_boundary_gte_unknown_defaults_user_only(self):
        """Unknown boundary levels default to USER_ONLY."""
        assert boundary_gte("UNKNOWN", "USER_ONLY") is True
        assert boundary_gte("UNKNOWN", "TEAM") is False


# ---------------------------------------------------------------------------
# APEP-248: Clearance-Level Checking
# ---------------------------------------------------------------------------


class TestClearanceLevelChecking:
    """Tests for clearance-level checking via DataClassificationEngine."""

    @pytest.mark.asyncio
    async def test_engine_no_classification_rule(self, mock_mongodb):
        """Tools without classification rules are allowed."""
        from app.services.data_classification import data_classification_engine

        allowed, reason = await data_classification_engine.enforce(
            agent_roles=["default"],
            tool_name="unclassified_tool",
            agent_id="test-agent",
        )
        assert allowed is True
        assert reason == ""

    @pytest.mark.asyncio
    async def test_engine_clearance_sufficient(self, mock_mongodb):
        """Agent with sufficient clearance is allowed."""
        from app.services.data_classification import (
            DATA_CLASSIFICATION_RULES,
            data_classification_engine,
        )

        db = mock_mongodb

        # Insert a classification rule for the tool
        await db[DATA_CLASSIFICATION_RULES].insert_one({
            "rule_id": str(uuid.uuid4()),
            "tool_pattern": "db.read_users",
            "classification": "PII",
            "boundary": "TEAM",
            "enabled": True,
        })

        # Insert a role with PII clearance and TEAM boundary
        await db["agent_roles"].insert_one({
            "role_id": "pii-reader",
            "name": "PII Reader",
            "parent_roles": [],
            "allowed_tools": ["db.*"],
            "denied_tools": [],
            "max_risk_threshold": 1.0,
            "clearance_level": "PII",
            "data_boundary": "TEAM",
            "enabled": True,
        })

        allowed, reason = await data_classification_engine.enforce(
            agent_roles=["pii-reader"],
            tool_name="db.read_users",
            agent_id="test-agent",
        )
        assert allowed is True

    @pytest.mark.asyncio
    async def test_engine_clearance_insufficient(self, mock_mongodb):
        """Agent with insufficient clearance is denied."""
        from app.services.data_classification import (
            DATA_CLASSIFICATION_RULES,
            data_classification_engine,
        )

        db = mock_mongodb

        # Insert a classification rule requiring FINANCIAL
        await db[DATA_CLASSIFICATION_RULES].insert_one({
            "rule_id": str(uuid.uuid4()),
            "tool_pattern": "billing.*",
            "classification": "FINANCIAL",
            "boundary": "USER_ONLY",
            "enabled": True,
        })

        # Insert a role with only INTERNAL clearance
        await db["agent_roles"].insert_one({
            "role_id": "basic-reader",
            "name": "Basic Reader",
            "parent_roles": [],
            "allowed_tools": ["*"],
            "denied_tools": [],
            "max_risk_threshold": 1.0,
            "clearance_level": "INTERNAL",
            "data_boundary": "ORGANISATION",
            "enabled": True,
        })

        allowed, reason = await data_classification_engine.enforce(
            agent_roles=["basic-reader"],
            tool_name="billing.get_invoices",
            agent_id="test-agent",
        )
        assert allowed is False
        assert "classification" in reason.lower()
        assert "FINANCIAL" in reason

    @pytest.mark.asyncio
    async def test_engine_boundary_insufficient(self, mock_mongodb):
        """Agent with insufficient boundary scope is denied."""
        from app.services.data_classification import (
            DATA_CLASSIFICATION_RULES,
            data_classification_engine,
        )

        db = mock_mongodb

        # Insert a classification rule requiring ORGANISATION boundary
        await db[DATA_CLASSIFICATION_RULES].insert_one({
            "rule_id": str(uuid.uuid4()),
            "tool_pattern": "org.analytics.*",
            "classification": "INTERNAL",
            "boundary": "ORGANISATION",
            "enabled": True,
        })

        # Insert a role with INTERNAL clearance but USER_ONLY boundary
        await db["agent_roles"].insert_one({
            "role_id": "user-scoped",
            "name": "User Scoped",
            "parent_roles": [],
            "allowed_tools": ["*"],
            "denied_tools": [],
            "max_risk_threshold": 1.0,
            "clearance_level": "INTERNAL",
            "data_boundary": "USER_ONLY",
            "enabled": True,
        })

        allowed, reason = await data_classification_engine.enforce(
            agent_roles=["user-scoped"],
            tool_name="org.analytics.report",
            agent_id="test-agent",
        )
        assert allowed is False
        assert "boundary" in reason.lower()

    @pytest.mark.asyncio
    async def test_engine_max_clearance_across_roles(self, mock_mongodb):
        """Engine uses the highest clearance from any of the agent's roles."""
        from app.services.data_classification import (
            DATA_CLASSIFICATION_RULES,
            data_classification_engine,
        )

        db = mock_mongodb

        # Insert a classification rule requiring CONFIDENTIAL
        await db[DATA_CLASSIFICATION_RULES].insert_one({
            "rule_id": str(uuid.uuid4()),
            "tool_pattern": "secret.*",
            "classification": "CONFIDENTIAL",
            "boundary": "USER_ONLY",
            "enabled": True,
        })

        # Insert two roles: one with PUBLIC, one with CONFIDENTIAL clearance
        await db["agent_roles"].insert_many([
            {
                "role_id": "low-role",
                "name": "Low",
                "parent_roles": [],
                "allowed_tools": [],
                "denied_tools": [],
                "max_risk_threshold": 1.0,
                "clearance_level": "PUBLIC",
                "data_boundary": "USER_ONLY",
                "enabled": True,
            },
            {
                "role_id": "high-role",
                "name": "High",
                "parent_roles": [],
                "allowed_tools": [],
                "denied_tools": [],
                "max_risk_threshold": 1.0,
                "clearance_level": "CONFIDENTIAL",
                "data_boundary": "USER_ONLY",
                "enabled": True,
            },
        ])

        allowed, reason = await data_classification_engine.enforce(
            agent_roles=["low-role", "high-role"],
            tool_name="secret.get",
            agent_id="test-agent",
        )
        assert allowed is True

    @pytest.mark.asyncio
    async def test_engine_glob_pattern_matching(self, mock_mongodb):
        """Classification rules match via glob patterns."""
        from app.services.data_classification import (
            DATA_CLASSIFICATION_RULES,
            data_classification_engine,
        )

        db = mock_mongodb

        # Insert rules with different patterns
        await db[DATA_CLASSIFICATION_RULES].insert_many([
            {
                "rule_id": str(uuid.uuid4()),
                "tool_pattern": "*.pii_*",
                "classification": "PII",
                "boundary": "USER_ONLY",
                "enabled": True,
            },
            {
                "rule_id": str(uuid.uuid4()),
                "tool_pattern": "db.*",
                "classification": "INTERNAL",
                "boundary": "TEAM",
                "enabled": True,
            },
        ])

        # Test the specific PII pattern match
        rule = await data_classification_engine.get_tool_classification("users.pii_ssn")
        assert rule is not None
        assert rule.classification == DataClassification.PII

        # Test the broader db.* pattern match
        rule = await data_classification_engine.get_tool_classification("db.query")
        assert rule is not None
        assert rule.classification == DataClassification.INTERNAL

        # Test no match
        rule = await data_classification_engine.get_tool_classification("unmatched_tool")
        assert rule is None


# ---------------------------------------------------------------------------
# APEP-249: Integration Tests — End-to-End
# ---------------------------------------------------------------------------


class TestDataClassificationIntegration:
    """End-to-end integration tests for data classification with the intercept API."""

    @pytest.mark.asyncio
    async def test_intercept_with_classification_deny(self, client, mock_mongodb):
        """Intercept API denies tool call when agent lacks clearance."""
        from app.services.rule_cache import rule_cache

        rule_cache.invalidate()
        db = mock_mongodb

        # Set up a classification rule requiring FINANCIAL
        await db["data_classification_rules"].insert_one({
            "rule_id": str(uuid.uuid4()),
            "tool_pattern": "finance.*",
            "classification": "FINANCIAL",
            "boundary": "USER_ONLY",
            "enabled": True,
        })

        # Set up an agent profile with default role
        await db["agent_profiles"].insert_one({
            "agent_id": "low-clearance-agent",
            "name": "Low Clearance",
            "roles": ["basic"],
            "allowed_tools": ["*"],
            "risk_budget": 1.0,
            "max_delegation_depth": 5,
            "session_limit": 100,
            "enabled": True,
        })

        # Set up the role with only PUBLIC clearance
        await db["agent_roles"].insert_one({
            "role_id": "basic",
            "name": "Basic Role",
            "parent_roles": [],
            "allowed_tools": ["*"],
            "denied_tools": [],
            "max_risk_threshold": 1.0,
            "clearance_level": "PUBLIC",
            "data_boundary": "USER_ONLY",
            "enabled": True,
        })

        # Set up a matching policy rule
        await db["policy_rules"].insert_one({
            "rule_id": str(uuid.uuid4()),
            "name": "Allow finance tools",
            "agent_role": ["basic"],
            "tool_pattern": "finance.*",
            "action": "ALLOW",
            "priority": 100,
            "enabled": True,
        })

        resp = await client.post(
            "/v1/intercept",
            json=_make_request(
                agent_id="low-clearance-agent",
                tool_name="finance.get_transactions",
            ),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "DENY"
        assert "classification" in data["reason"].lower()

    @pytest.mark.asyncio
    async def test_intercept_without_classification_allows(self, client, mock_mongodb):
        """Intercept API allows tool call when no classification is required."""
        from app.services.rule_cache import rule_cache

        rule_cache.invalidate()
        db = mock_mongodb

        # Set up an agent profile
        await db["agent_profiles"].insert_one({
            "agent_id": "normal-agent",
            "name": "Normal Agent",
            "roles": ["standard"],
            "allowed_tools": ["*"],
            "risk_budget": 1.0,
            "max_delegation_depth": 5,
            "session_limit": 100,
            "enabled": True,
        })

        # Set up the role (no special clearance needed for unclassified tools)
        await db["agent_roles"].insert_one({
            "role_id": "standard",
            "name": "Standard Role",
            "parent_roles": [],
            "allowed_tools": ["*"],
            "denied_tools": [],
            "max_risk_threshold": 1.0,
            "clearance_level": "PUBLIC",
            "data_boundary": "USER_ONLY",
            "enabled": True,
        })

        # Set up a matching policy rule for the tool
        await db["policy_rules"].insert_one({
            "rule_id": str(uuid.uuid4()),
            "name": "Allow read_file",
            "agent_role": ["standard"],
            "tool_pattern": "read_file",
            "action": "ALLOW",
            "priority": 100,
            "enabled": True,
        })

        resp = await client.post(
            "/v1/intercept",
            json=_make_request(agent_id="normal-agent", tool_name="read_file"),
        )
        assert resp.status_code == 200
        data = resp.json()
        # Should be ALLOW (or at least not denied for classification reasons)
        assert data["decision"] in ("ALLOW", "DRY_RUN")
