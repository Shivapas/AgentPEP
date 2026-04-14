"""Tests for Sprint 3 — RBAC Policy Engine — Core.

Covers APEP-020 through APEP-028:
- AgentRole model and hierarchy (APEP-020)
- RoleResolver hierarchy walking (APEP-021)
- RuleMatcher glob/regex tool matching (APEP-022)
- Priority-ordered first-match with deny-by-default (APEP-023)
- JSON schema argument validation (APEP-024)
- Regex allowlist/blocklist validators (APEP-025)
- Rule caching with TTL (APEP-026)
- Property-based tests (APEP-027)
- Rule conflict detection (APEP-028)
"""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    from app.main import app
    from tests.conftest import _get_auth_headers

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers=_get_auth_headers()) as ac:
        yield ac


@pytest.fixture(autouse=True)
async def clear_rule_cache():
    """Clear the rule cache before each test to prevent cross-test pollution."""
    from app.services.rule_cache import rule_cache

    rule_cache.invalidate()
    yield
    rule_cache.invalidate()


def _make_request(**overrides):
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
# APEP-020: AgentRole model with multi-inheritance hierarchy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_role_model_stored_in_mongodb(mock_mongodb):
    """AgentRole documents can be stored and retrieved from MongoDB."""
    from app.db.mongodb import AGENT_ROLES

    role = {
        "role_id": "admin",
        "name": "Administrator",
        "parent_roles": ["base_user"],
        "allowed_tools": ["*"],
        "denied_tools": [],
        "max_risk_threshold": 0.9,
        "enabled": True,
    }
    await mock_mongodb[AGENT_ROLES].insert_one(role)

    fetched = await mock_mongodb[AGENT_ROLES].find_one({"role_id": "admin"})
    assert fetched is not None
    assert fetched["name"] == "Administrator"
    assert fetched["parent_roles"] == ["base_user"]
    assert fetched["allowed_tools"] == ["*"]


@pytest.mark.asyncio
async def test_agent_role_multi_inheritance(mock_mongodb):
    """AgentRole supports multiple parent roles."""
    from app.db.mongodb import AGENT_ROLES

    roles = [
        {
            "role_id": "reader",
            "name": "Reader",
            "parent_roles": [],
            "allowed_tools": ["read_*"],
            "denied_tools": [],
            "max_risk_threshold": 1.0,
            "enabled": True,
        },
        {
            "role_id": "writer",
            "name": "Writer",
            "parent_roles": [],
            "allowed_tools": ["write_*"],
            "denied_tools": [],
            "max_risk_threshold": 0.8,
            "enabled": True,
        },
        {
            "role_id": "editor",
            "name": "Editor",
            "parent_roles": ["reader", "writer"],
            "allowed_tools": ["edit_*"],
            "denied_tools": [],
            "max_risk_threshold": 0.7,
            "enabled": True,
        },
    ]
    await mock_mongodb[AGENT_ROLES].insert_many(roles)

    editor = await mock_mongodb[AGENT_ROLES].find_one({"role_id": "editor"})
    assert editor is not None
    assert set(editor["parent_roles"]) == {"reader", "writer"}


# ---------------------------------------------------------------------------
# APEP-021: RoleResolver — hierarchy walking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_role_resolver_returns_default_for_unknown_agent(mock_mongodb):
    """Unknown agent should resolve to ['default']."""
    from app.services.role_resolver import role_resolver

    roles = await role_resolver.resolve_roles("nonexistent-agent")
    assert roles == ["default"]


@pytest.mark.asyncio
async def test_role_resolver_direct_roles(mock_mongodb):
    """Agent with direct roles (no hierarchy) should return those roles."""
    from app.db.mongodb import AGENT_PROFILES
    from app.services.role_resolver import role_resolver

    await mock_mongodb[AGENT_PROFILES].insert_one({
        "agent_id": "basic-agent",
        "name": "Basic Agent",
        "roles": ["reader"],
        "enabled": True,
    })

    roles = await role_resolver.resolve_roles("basic-agent")
    assert "reader" in roles


@pytest.mark.asyncio
async def test_role_resolver_walks_hierarchy(mock_mongodb):
    """RoleResolver should walk parent_roles and return all ancestors."""
    from app.db.mongodb import AGENT_PROFILES, AGENT_ROLES
    from app.services.role_resolver import role_resolver

    # Set up hierarchy: editor -> reader, writer -> base_user
    await mock_mongodb[AGENT_ROLES].insert_many([
        {"role_id": "base_user", "name": "Base", "parent_roles": [],
         "allowed_tools": [], "denied_tools": [], "max_risk_threshold": 1.0, "enabled": True},
        {"role_id": "reader", "name": "Reader", "parent_roles": ["base_user"],
         "allowed_tools": ["read_*"], "denied_tools": [], "max_risk_threshold": 1.0, "enabled": True},
        {"role_id": "writer", "name": "Writer", "parent_roles": ["base_user"],
         "allowed_tools": ["write_*"], "denied_tools": [], "max_risk_threshold": 0.8, "enabled": True},
        {"role_id": "editor", "name": "Editor", "parent_roles": ["reader", "writer"],
         "allowed_tools": ["edit_*"], "denied_tools": [], "max_risk_threshold": 0.7, "enabled": True},
    ])

    await mock_mongodb[AGENT_PROFILES].insert_one({
        "agent_id": "editor-agent",
        "name": "Editor Agent",
        "roles": ["editor"],
        "enabled": True,
    })

    roles = await role_resolver.resolve_roles("editor-agent")
    assert set(roles) == {"editor", "reader", "writer", "base_user"}


@pytest.mark.asyncio
async def test_role_resolver_handles_diamond_hierarchy(mock_mongodb):
    """Diamond inheritance should not cause duplicates."""
    from app.db.mongodb import AGENT_PROFILES, AGENT_ROLES
    from app.services.role_resolver import role_resolver

    # Diamond: admin -> reader, writer; reader -> base; writer -> base
    await mock_mongodb[AGENT_ROLES].insert_many([
        {"role_id": "base", "name": "Base", "parent_roles": [],
         "allowed_tools": [], "denied_tools": [], "max_risk_threshold": 1.0, "enabled": True},
        {"role_id": "reader", "name": "Reader", "parent_roles": ["base"],
         "allowed_tools": [], "denied_tools": [], "max_risk_threshold": 1.0, "enabled": True},
        {"role_id": "writer", "name": "Writer", "parent_roles": ["base"],
         "allowed_tools": [], "denied_tools": [], "max_risk_threshold": 1.0, "enabled": True},
        {"role_id": "admin", "name": "Admin", "parent_roles": ["reader", "writer"],
         "allowed_tools": [], "denied_tools": [], "max_risk_threshold": 1.0, "enabled": True},
    ])
    await mock_mongodb[AGENT_PROFILES].insert_one({
        "agent_id": "admin-agent", "name": "Admin", "roles": ["admin"], "enabled": True,
    })

    roles = await role_resolver.resolve_roles("admin-agent")
    # No duplicates
    assert len(roles) == len(set(roles))
    assert set(roles) == {"admin", "reader", "writer", "base"}


@pytest.mark.asyncio
async def test_role_resolver_effective_permissions(mock_mongodb):
    """Effective permissions merge allowed_tools and take most restrictive risk threshold."""
    from app.db.mongodb import AGENT_PROFILES, AGENT_ROLES
    from app.services.role_resolver import role_resolver

    await mock_mongodb[AGENT_ROLES].insert_many([
        {"role_id": "base", "name": "Base", "parent_roles": [],
         "allowed_tools": ["health_*"], "denied_tools": [], "max_risk_threshold": 1.0, "enabled": True},
        {"role_id": "analyst", "name": "Analyst", "parent_roles": ["base"],
         "allowed_tools": ["read_*", "query_*"], "denied_tools": ["delete_*"],
         "max_risk_threshold": 0.6, "enabled": True},
    ])
    await mock_mongodb[AGENT_PROFILES].insert_one({
        "agent_id": "analyst-agent", "name": "Analyst", "roles": ["analyst"], "enabled": True,
    })

    perms = await role_resolver.resolve_effective_permissions("analyst-agent")
    assert set(perms.roles) == {"analyst", "base"}
    assert "read_*" in perms.allowed_tools
    assert "query_*" in perms.allowed_tools
    assert "health_*" in perms.allowed_tools
    assert "delete_*" in perms.denied_tools
    assert perms.max_risk_threshold == 0.6


# ---------------------------------------------------------------------------
# APEP-022: RuleMatcher — glob + regex tool matching
# ---------------------------------------------------------------------------


class TestRuleMatcher:
    """Unit tests for RuleMatcher.tool_matches and RuleMatcher.role_matches."""

    def test_glob_exact_match(self):
        from app.services.rule_matcher import RuleMatcher

        assert RuleMatcher.tool_matches("read_file", "read_file") is True

    def test_glob_wildcard(self):
        from app.services.rule_matcher import RuleMatcher

        assert RuleMatcher.tool_matches("file_read", "file_*") is True
        assert RuleMatcher.tool_matches("file_write", "file_*") is True
        assert RuleMatcher.tool_matches("db_read", "file_*") is False

    def test_glob_question_mark(self):
        from app.services.rule_matcher import RuleMatcher

        assert RuleMatcher.tool_matches("log_a", "log_?") is True
        assert RuleMatcher.tool_matches("log_ab", "log_?") is False

    def test_regex_alternation(self):
        from app.services.rule_matcher import RuleMatcher

        assert RuleMatcher.tool_matches("db_read_users", r"db_(read|list)_.*") is True
        assert RuleMatcher.tool_matches("db_list_items", r"db_(read|list)_.*") is True
        assert RuleMatcher.tool_matches("db_delete_users", r"db_(read|list)_.*") is False

    def test_regex_character_class(self):
        from app.services.rule_matcher import RuleMatcher

        assert RuleMatcher.tool_matches("api_v2_get", r"api_v[0-9]+_get") is True
        assert RuleMatcher.tool_matches("api_vX_get", r"api_v[0-9]+_get") is False

    def test_invalid_regex_does_not_crash(self):
        from app.services.rule_matcher import RuleMatcher

        # Invalid regex should not raise, just return False
        assert RuleMatcher.tool_matches("test", "[invalid") is False

    def test_role_matches_wildcard(self):
        from app.services.rule_matcher import RuleMatcher

        assert RuleMatcher.role_matches(["reader"], ["*"]) is True

    def test_role_matches_specific(self):
        from app.services.rule_matcher import RuleMatcher

        assert RuleMatcher.role_matches(["reader"], ["reader", "writer"]) is True
        assert RuleMatcher.role_matches(["admin"], ["reader", "writer"]) is False

    def test_role_matches_multi_role_agent(self):
        from app.services.rule_matcher import RuleMatcher

        # Agent with multiple roles — any match suffices
        assert RuleMatcher.role_matches(["reader", "analyst"], ["analyst"]) is True


# ---------------------------------------------------------------------------
# APEP-023: Priority-ordered first-match with deny-by-default
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_first_match_with_role_hierarchy(client: AsyncClient, mock_mongodb):
    """Rules match against resolved role hierarchy, not just direct role."""
    from app.db.mongodb import AGENT_PROFILES, AGENT_ROLES, POLICY_RULES

    await mock_mongodb[AGENT_ROLES].insert_many([
        {"role_id": "base", "name": "Base", "parent_roles": [],
         "allowed_tools": [], "denied_tools": [], "max_risk_threshold": 1.0, "enabled": True},
        {"role_id": "analyst", "name": "Analyst", "parent_roles": ["base"],
         "allowed_tools": [], "denied_tools": [], "max_risk_threshold": 1.0, "enabled": True},
    ])
    await mock_mongodb[AGENT_PROFILES].insert_one({
        "agent_id": "analyst-agent", "name": "Analyst", "roles": ["analyst"], "enabled": True,
    })
    # Rule targets "base" role — should match analyst via inheritance
    await mock_mongodb[POLICY_RULES].insert_one({
        "rule_id": str(uuid.uuid4()),
        "name": "allow-base-read",
        "agent_role": ["base"],
        "tool_pattern": "read_*",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [],
    })

    resp = await client.post(
        "/v1/intercept",
        json=_make_request(agent_id="analyst-agent", tool_name="read_file"),
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "ALLOW"


@pytest.mark.asyncio
async def test_deny_by_default_no_rules(client: AsyncClient, mock_mongodb):
    """Without rules, deny by default."""
    resp = await client.post("/v1/intercept", json=_make_request())
    assert resp.json()["decision"] == "DENY"


# ---------------------------------------------------------------------------
# APEP-024: JSON schema argument validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_json_schema_valid_args(client: AsyncClient, mock_mongodb):
    """Tool args matching JSON schema should allow the rule to match."""
    from app.db.mongodb import POLICY_RULES

    await mock_mongodb[POLICY_RULES].insert_one({
        "rule_id": str(uuid.uuid4()),
        "name": "allow-with-schema",
        "agent_role": ["*"],
        "tool_pattern": "create_user",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [{
            "arg_name": "age",
            "json_schema": {"type": "integer", "minimum": 0, "maximum": 150},
        }],
    })

    resp = await client.post(
        "/v1/intercept",
        json=_make_request(tool_name="create_user", tool_args={"age": 25}),
    )
    assert resp.json()["decision"] == "ALLOW"


@pytest.mark.asyncio
async def test_json_schema_invalid_args(client: AsyncClient, mock_mongodb):
    """Tool args failing JSON schema should cause the rule to not match (deny by default)."""
    from app.db.mongodb import POLICY_RULES

    await mock_mongodb[POLICY_RULES].insert_one({
        "rule_id": str(uuid.uuid4()),
        "name": "allow-with-schema",
        "agent_role": ["*"],
        "tool_pattern": "create_user",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [{
            "arg_name": "age",
            "json_schema": {"type": "integer", "minimum": 0, "maximum": 150},
        }],
    })

    # age=-5 fails minimum:0
    resp = await client.post(
        "/v1/intercept",
        json=_make_request(tool_name="create_user", tool_args={"age": -5}),
    )
    assert resp.json()["decision"] == "DENY"


@pytest.mark.asyncio
async def test_json_schema_type_mismatch(client: AsyncClient, mock_mongodb):
    """String value where integer expected should fail schema validation."""
    from app.db.mongodb import POLICY_RULES

    await mock_mongodb[POLICY_RULES].insert_one({
        "rule_id": str(uuid.uuid4()),
        "name": "allow-with-schema",
        "agent_role": ["*"],
        "tool_pattern": "create_user",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [{
            "arg_name": "age",
            "json_schema": {"type": "integer"},
        }],
    })

    resp = await client.post(
        "/v1/intercept",
        json=_make_request(tool_name="create_user", tool_args={"age": "not_a_number"}),
    )
    assert resp.json()["decision"] == "DENY"


# ---------------------------------------------------------------------------
# APEP-025: Regex allowlist/blocklist argument validators
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_blocklist_rejects_arg(client: AsyncClient, mock_mongodb):
    """Blocklisted arg value should cause rule not to match."""
    from app.db.mongodb import POLICY_RULES

    await mock_mongodb[POLICY_RULES].insert_one({
        "rule_id": str(uuid.uuid4()),
        "name": "allow-with-blocklist",
        "agent_role": ["*"],
        "tool_pattern": "send_email",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [{
            "arg_name": "recipient",
            "blocklist": ["evil@attacker.com", "spam@test.com"],
        }],
    })

    resp = await client.post(
        "/v1/intercept",
        json=_make_request(tool_name="send_email", tool_args={"recipient": "evil@attacker.com"}),
    )
    assert resp.json()["decision"] == "DENY"


@pytest.mark.asyncio
async def test_allowlist_accepts_arg(client: AsyncClient, mock_mongodb):
    """Arg in allowlist should let rule match."""
    from app.db.mongodb import POLICY_RULES

    await mock_mongodb[POLICY_RULES].insert_one({
        "rule_id": str(uuid.uuid4()),
        "name": "allow-with-allowlist",
        "agent_role": ["*"],
        "tool_pattern": "send_email",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [{
            "arg_name": "recipient",
            "allowlist": ["user@company.com", "admin@company.com"],
        }],
    })

    resp = await client.post(
        "/v1/intercept",
        json=_make_request(tool_name="send_email", tool_args={"recipient": "user@company.com"}),
    )
    # ALLOW or MODIFY are both acceptable — MODIFY occurs when PII redaction
    # detects the email and the agent lacks PII clearance (Sprint 35).
    assert resp.json()["decision"] in ("ALLOW", "MODIFY")


@pytest.mark.asyncio
async def test_allowlist_rejects_unknown(client: AsyncClient, mock_mongodb):
    """Arg NOT in allowlist should cause rule not to match."""
    from app.db.mongodb import POLICY_RULES

    await mock_mongodb[POLICY_RULES].insert_one({
        "rule_id": str(uuid.uuid4()),
        "name": "allow-with-allowlist",
        "agent_role": ["*"],
        "tool_pattern": "send_email",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [{
            "arg_name": "recipient",
            "allowlist": ["user@company.com"],
        }],
    })

    resp = await client.post(
        "/v1/intercept",
        json=_make_request(tool_name="send_email", tool_args={"recipient": "hacker@evil.com"}),
    )
    assert resp.json()["decision"] == "DENY"


@pytest.mark.asyncio
async def test_regex_pattern_accepts_valid(client: AsyncClient, mock_mongodb):
    """Arg matching regex pattern should let rule match."""
    from app.db.mongodb import POLICY_RULES

    await mock_mongodb[POLICY_RULES].insert_one({
        "rule_id": str(uuid.uuid4()),
        "name": "allow-with-regex",
        "agent_role": ["*"],
        "tool_pattern": "read_file",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [{
            "arg_name": "path",
            "regex_pattern": r"/tmp/.*\.txt",
        }],
    })

    resp = await client.post(
        "/v1/intercept",
        json=_make_request(tool_name="read_file", tool_args={"path": "/tmp/data.txt"}),
    )
    assert resp.json()["decision"] == "ALLOW"


@pytest.mark.asyncio
async def test_regex_pattern_rejects_invalid(client: AsyncClient, mock_mongodb):
    """Arg not matching regex pattern should deny."""
    from app.db.mongodb import POLICY_RULES

    await mock_mongodb[POLICY_RULES].insert_one({
        "rule_id": str(uuid.uuid4()),
        "name": "allow-with-regex",
        "agent_role": ["*"],
        "tool_pattern": "read_file",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [{
            "arg_name": "path",
            "regex_pattern": r"/tmp/.*\.txt",
        }],
    })

    resp = await client.post(
        "/v1/intercept",
        json=_make_request(tool_name="read_file", tool_args={"path": "/etc/passwd"}),
    )
    assert resp.json()["decision"] == "DENY"


# ---------------------------------------------------------------------------
# APEP-026: Rule caching with TTL
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rule_cache_returns_cached_rules(mock_mongodb):
    """Second call should return cached rules without re-fetching."""
    from app.db.mongodb import POLICY_RULES
    from app.services.rule_cache import RuleCache

    cache = RuleCache(ttl_s=60.0)

    await mock_mongodb[POLICY_RULES].insert_one({
        "rule_id": str(uuid.uuid4()),
        "name": "test-rule",
        "agent_role": ["*"],
        "tool_pattern": "*",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [],
    })

    rules1 = await cache.get_rules()
    assert len(rules1) == 1

    # Delete from DB — cache should still return the rule
    await mock_mongodb[POLICY_RULES].delete_many({})
    rules2 = await cache.get_rules()
    assert len(rules2) == 1  # Still cached


@pytest.mark.asyncio
async def test_rule_cache_invalidation(mock_mongodb):
    """After invalidation, cache should re-fetch from MongoDB."""
    from app.db.mongodb import POLICY_RULES
    from app.services.rule_cache import RuleCache

    cache = RuleCache(ttl_s=60.0)

    await mock_mongodb[POLICY_RULES].insert_one({
        "rule_id": str(uuid.uuid4()),
        "name": "test-rule",
        "agent_role": ["*"],
        "tool_pattern": "*",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [],
    })

    await cache.get_rules()  # Populate cache
    await mock_mongodb[POLICY_RULES].delete_many({})

    cache.invalidate()
    rules = await cache.get_rules()
    assert len(rules) == 0  # Re-fetched, now empty


# ---------------------------------------------------------------------------
# APEP-028: Rule conflict detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_conflict_detection_finds_overlapping_rules(mock_mongodb):
    """Two rules with same pattern/roles but different actions should conflict."""
    from app.db.mongodb import POLICY_RULES
    from app.services.conflict_detector import conflict_detector

    await mock_mongodb[POLICY_RULES].insert_many([
        {
            "rule_id": str(uuid.uuid4()),
            "name": "allow-file-ops",
            "agent_role": ["*"],
            "tool_pattern": "file_*",
            "action": "ALLOW",
            "priority": 10,
            "enabled": True,
            "taint_check": False,
            "risk_threshold": 1.0,
            "arg_validators": [],
        },
        {
            "rule_id": str(uuid.uuid4()),
            "name": "deny-file-ops",
            "agent_role": ["*"],
            "tool_pattern": "file_*",
            "action": "DENY",
            "priority": 20,
            "enabled": True,
            "taint_check": False,
            "risk_threshold": 1.0,
            "arg_validators": [],
        },
    ])

    conflicts = await conflict_detector.detect_conflicts()
    assert len(conflicts) == 1
    assert conflicts[0].overlap_type == "action_conflict"


@pytest.mark.asyncio
async def test_conflict_detection_no_conflict_same_action(mock_mongodb):
    """Two rules with same action should not conflict."""
    from app.db.mongodb import POLICY_RULES
    from app.services.conflict_detector import conflict_detector

    await mock_mongodb[POLICY_RULES].insert_many([
        {
            "rule_id": str(uuid.uuid4()),
            "name": "allow-file-a",
            "agent_role": ["*"],
            "tool_pattern": "file_*",
            "action": "ALLOW",
            "priority": 10,
            "enabled": True,
            "taint_check": False,
            "risk_threshold": 1.0,
            "arg_validators": [],
        },
        {
            "rule_id": str(uuid.uuid4()),
            "name": "allow-file-b",
            "agent_role": ["*"],
            "tool_pattern": "file_*",
            "action": "ALLOW",
            "priority": 20,
            "enabled": True,
            "taint_check": False,
            "risk_threshold": 1.0,
            "arg_validators": [],
        },
    ])

    conflicts = await conflict_detector.detect_conflicts()
    assert len(conflicts) == 0


@pytest.mark.asyncio
async def test_conflict_detection_no_conflict_different_roles(mock_mongodb):
    """Rules targeting different roles should not conflict."""
    from app.db.mongodb import POLICY_RULES
    from app.services.conflict_detector import conflict_detector

    await mock_mongodb[POLICY_RULES].insert_many([
        {
            "rule_id": str(uuid.uuid4()),
            "name": "allow-reader",
            "agent_role": ["reader"],
            "tool_pattern": "file_*",
            "action": "ALLOW",
            "priority": 10,
            "enabled": True,
            "taint_check": False,
            "risk_threshold": 1.0,
            "arg_validators": [],
        },
        {
            "rule_id": str(uuid.uuid4()),
            "name": "deny-writer",
            "agent_role": ["writer"],
            "tool_pattern": "file_*",
            "action": "DENY",
            "priority": 20,
            "enabled": True,
            "taint_check": False,
            "risk_threshold": 1.0,
            "arg_validators": [],
        },
    ])

    conflicts = await conflict_detector.detect_conflicts()
    assert len(conflicts) == 0
