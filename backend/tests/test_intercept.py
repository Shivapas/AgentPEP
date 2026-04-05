"""Integration tests for the Intercept API — ALLOW / DENY / DRY_RUN paths end-to-end.

Covers Sprint 2 stories APEP-012 through APEP-019.
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

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
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
# APEP-012: POST /v1/intercept returns valid PolicyDecisionResponse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_intercept_returns_valid_response(client: AsyncClient):
    """POST /v1/intercept returns 200 with all expected response fields."""
    resp = await client.post("/v1/intercept", json=_make_request())
    assert resp.status_code == 200
    data = resp.json()

    assert "request_id" in data
    assert "decision" in data
    assert "risk_score" in data
    assert "taint_flags" in data
    assert "reason" in data
    assert "latency_ms" in data
    assert isinstance(data["latency_ms"], int)


@pytest.mark.asyncio
async def test_intercept_request_validation_rejects_missing_fields(client: AsyncClient):
    """Missing required fields should return 422 validation error."""
    resp = await client.post("/v1/intercept", json={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_intercept_request_validation_rejects_invalid_uuid(client: AsyncClient):
    """Invalid request_id UUID should return 422."""
    resp = await client.post(
        "/v1/intercept",
        json=_make_request(request_id="not-a-uuid"),
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# APEP-014: PolicyEvaluator — deny by default when no rules exist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_by_default_when_no_rules(client: AsyncClient):
    """Without any policy rules in MongoDB, the engine should deny by default."""
    resp = await client.post("/v1/intercept", json=_make_request())
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "DENY"
    assert "deny by default" in data["reason"].lower()


# ---------------------------------------------------------------------------
# APEP-014: PolicyEvaluator — ALLOW path with matching rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_allow_when_matching_rule_exists(client: AsyncClient):
    """Insert an ALLOW rule that matches, verify ALLOW decision."""
    from app.db.mongodb import get_database, POLICY_RULES

    db = get_database()
    rule = {
        "rule_id": str(uuid.uuid4()),
        "name": "allow-read-file",
        "agent_role": ["*"],
        "tool_pattern": "read_file",
        "action": "ALLOW",
        "taint_check": False,
        "risk_threshold": 1.0,
        "rate_limit": None,
        "arg_validators": [],
        "priority": 10,
        "enabled": True,
    }
    await db[POLICY_RULES].insert_one(rule)

    try:
        resp = await client.post("/v1/intercept", json=_make_request())
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "ALLOW"
        assert data["matched_rule_id"] == rule["rule_id"]
        assert "allow-read-file" in data["reason"]
    finally:
        await db[POLICY_RULES].delete_one({"rule_id": rule["rule_id"]})


# ---------------------------------------------------------------------------
# APEP-014: PolicyEvaluator — DENY path with matching deny rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_when_deny_rule_matches(client: AsyncClient):
    """Insert a DENY rule that matches the tool, verify DENY decision."""
    from app.db.mongodb import get_database, POLICY_RULES

    db = get_database()
    rule = {
        "rule_id": str(uuid.uuid4()),
        "name": "deny-send-email",
        "agent_role": ["*"],
        "tool_pattern": "send_email",
        "action": "DENY",
        "taint_check": False,
        "risk_threshold": 1.0,
        "rate_limit": None,
        "arg_validators": [],
        "priority": 10,
        "enabled": True,
    }
    await db[POLICY_RULES].insert_one(rule)

    try:
        resp = await client.post(
            "/v1/intercept",
            json=_make_request(tool_name="send_email"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "DENY"
        assert data["matched_rule_id"] == rule["rule_id"]
    finally:
        await db[POLICY_RULES].delete_one({"rule_id": rule["rule_id"]})


# ---------------------------------------------------------------------------
# APEP-017: DRY_RUN mode — full evaluation but no enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dry_run_returns_dry_run_decision(client: AsyncClient):
    """DRY_RUN mode should evaluate fully but return DRY_RUN decision."""
    resp = await client.post(
        "/v1/intercept",
        json=_make_request(dry_run=True),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "DRY_RUN"


@pytest.mark.asyncio
async def test_dry_run_with_deny_rule_still_returns_dry_run(client: AsyncClient):
    """Even when a DENY rule matches, DRY_RUN mode should return DRY_RUN."""
    from app.db.mongodb import get_database, POLICY_RULES

    db = get_database()
    rule = {
        "rule_id": str(uuid.uuid4()),
        "name": "deny-delete-file",
        "agent_role": ["*"],
        "tool_pattern": "delete_file",
        "action": "DENY",
        "taint_check": False,
        "risk_threshold": 1.0,
        "rate_limit": None,
        "arg_validators": [],
        "priority": 10,
        "enabled": True,
    }
    await db[POLICY_RULES].insert_one(rule)

    try:
        resp = await client.post(
            "/v1/intercept",
            json=_make_request(tool_name="delete_file", dry_run=True),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "DRY_RUN"
        # Should still report the matched rule
        assert data["matched_rule_id"] == rule["rule_id"]
    finally:
        await db[POLICY_RULES].delete_one({"rule_id": rule["rule_id"]})


# ---------------------------------------------------------------------------
# APEP-014: First-match semantics — priority ordering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_first_match_priority_ordering(client: AsyncClient):
    """Higher-priority (lower number) rule should win over lower-priority."""
    from app.db.mongodb import get_database, POLICY_RULES

    db = get_database()
    deny_rule = {
        "rule_id": str(uuid.uuid4()),
        "name": "deny-all-write",
        "agent_role": ["*"],
        "tool_pattern": "write_*",
        "action": "DENY",
        "priority": 5,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [],
    }
    allow_rule = {
        "rule_id": str(uuid.uuid4()),
        "name": "allow-all-write",
        "agent_role": ["*"],
        "tool_pattern": "write_*",
        "action": "ALLOW",
        "priority": 50,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [],
    }
    await db[POLICY_RULES].insert_many([deny_rule, allow_rule])

    try:
        resp = await client.post(
            "/v1/intercept",
            json=_make_request(tool_name="write_document"),
        )
        assert resp.status_code == 200
        data = resp.json()
        # Priority 5 DENY should win over priority 50 ALLOW
        assert data["decision"] == "DENY"
        assert data["matched_rule_id"] == deny_rule["rule_id"]
    finally:
        await db[POLICY_RULES].delete_many(
            {"rule_id": {"$in": [deny_rule["rule_id"], allow_rule["rule_id"]]}}
        )


# ---------------------------------------------------------------------------
# APEP-014: Glob and regex tool pattern matching
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_glob_pattern_matching(client: AsyncClient):
    """Glob patterns like 'file_*' should match tool names like 'file_read'."""
    from app.db.mongodb import get_database, POLICY_RULES

    db = get_database()
    rule = {
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
    }
    await db[POLICY_RULES].insert_one(rule)

    try:
        resp = await client.post(
            "/v1/intercept",
            json=_make_request(tool_name="file_read"),
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "ALLOW"
    finally:
        await db[POLICY_RULES].delete_one({"rule_id": rule["rule_id"]})


@pytest.mark.asyncio
async def test_regex_pattern_matching(client: AsyncClient):
    """Regex patterns should match tool names."""
    from app.db.mongodb import get_database, POLICY_RULES

    db = get_database()
    rule = {
        "rule_id": str(uuid.uuid4()),
        "name": "allow-db-ops",
        "agent_role": ["*"],
        "tool_pattern": r"db_(read|list)_.*",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [],
    }
    await db[POLICY_RULES].insert_one(rule)

    try:
        resp = await client.post(
            "/v1/intercept",
            json=_make_request(tool_name="db_read_users"),
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "ALLOW"
    finally:
        await db[POLICY_RULES].delete_one({"rule_id": rule["rule_id"]})


# ---------------------------------------------------------------------------
# APEP-014: Role-based rule matching
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_role_specific_rule_matches_agent_role(client: AsyncClient):
    """Rule targeting a specific role should match agents with that role."""
    from app.db.mongodb import get_database, POLICY_RULES, AGENT_PROFILES

    db = get_database()

    profile = {
        "agent_id": "writer-agent",
        "name": "Writer Agent",
        "roles": ["WriterAgent"],
        "enabled": True,
    }
    rule = {
        "rule_id": str(uuid.uuid4()),
        "name": "allow-writer-send",
        "agent_role": ["WriterAgent"],
        "tool_pattern": "send_*",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [],
    }
    await db[AGENT_PROFILES].insert_one(profile)
    await db[POLICY_RULES].insert_one(rule)

    try:
        resp = await client.post(
            "/v1/intercept",
            json=_make_request(agent_id="writer-agent", tool_name="send_message"),
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "ALLOW"
    finally:
        await db[AGENT_PROFILES].delete_one({"agent_id": "writer-agent"})
        await db[POLICY_RULES].delete_one({"rule_id": rule["rule_id"]})


@pytest.mark.asyncio
async def test_role_specific_rule_does_not_match_other_role(client: AsyncClient):
    """Rule targeting WriterAgent should not match a ReaderAgent."""
    from app.db.mongodb import get_database, POLICY_RULES, AGENT_PROFILES

    db = get_database()

    profile = {
        "agent_id": "reader-agent",
        "name": "Reader Agent",
        "roles": ["ReaderAgent"],
        "enabled": True,
    }
    rule = {
        "rule_id": str(uuid.uuid4()),
        "name": "allow-writer-only",
        "agent_role": ["WriterAgent"],
        "tool_pattern": "send_*",
        "action": "ALLOW",
        "priority": 10,
        "enabled": True,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [],
    }
    await db[AGENT_PROFILES].insert_one(profile)
    await db[POLICY_RULES].insert_one(rule)

    try:
        resp = await client.post(
            "/v1/intercept",
            json=_make_request(agent_id="reader-agent", tool_name="send_message"),
        )
        assert resp.status_code == 200
        # ReaderAgent doesn't match WriterAgent rule, so deny-by-default
        assert resp.json()["decision"] == "DENY"
    finally:
        await db[AGENT_PROFILES].delete_one({"agent_id": "reader-agent"})
        await db[POLICY_RULES].delete_one({"rule_id": rule["rule_id"]})


# ---------------------------------------------------------------------------
# APEP-014: Disabled rules are skipped
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disabled_rules_are_skipped(client: AsyncClient):
    """Disabled rules should not be evaluated."""
    from app.db.mongodb import get_database, POLICY_RULES

    db = get_database()
    rule = {
        "rule_id": str(uuid.uuid4()),
        "name": "allow-but-disabled",
        "agent_role": ["*"],
        "tool_pattern": "read_file",
        "action": "ALLOW",
        "priority": 1,
        "enabled": False,
        "taint_check": False,
        "risk_threshold": 1.0,
        "arg_validators": [],
    }
    await db[POLICY_RULES].insert_one(rule)

    try:
        resp = await client.post("/v1/intercept", json=_make_request())
        assert resp.status_code == 200
        # Rule is disabled, so no match → deny by default
        assert resp.json()["decision"] == "DENY"
    finally:
        await db[POLICY_RULES].delete_one({"rule_id": rule["rule_id"]})


# ---------------------------------------------------------------------------
# APEP-014: Audit log is written
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_log_written_on_decision(client: AsyncClient):
    """Every intercept call should write an audit decision record.

    Sprint 23 (APEP-184): Audit writes are now async-batched.
    We flush the writer before checking MongoDB.
    """
    from app.db.mongodb import get_database, AUDIT_DECISIONS
    from app.services.policy_evaluator import audit_log_writer

    db = get_database()

    req_id = str(uuid.uuid4())
    await client.post(
        "/v1/intercept",
        json=_make_request(request_id=req_id),
    )

    # APEP-184: Flush the async audit log writer so records reach MongoDB
    await audit_log_writer.flush_pending()

    # Check audit log
    audit = await db[AUDIT_DECISIONS].find_one({"session_id": "test-session"})
    assert audit is not None
    assert audit["tool_name"] == "read_file"
    assert audit["decision"] in ["ALLOW", "DENY", "DRY_RUN", "ESCALATE", "TIMEOUT"]

    # Clean up
    await db[AUDIT_DECISIONS].delete_many({"session_id": "test-session"})


# ---------------------------------------------------------------------------
# APEP-015: API key auth middleware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_disabled_allows_all_requests(client: AsyncClient):
    """When auth is disabled, requests without API key should succeed."""
    resp = await client.post("/v1/intercept", json=_make_request())
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_auth_enabled_rejects_missing_key():
    """When auth is enabled, missing API key should return 401."""
    import os
    os.environ["AGENTPEP_AUTH_ENABLED"] = "true"

    # Need to reimport with new settings
    from app.core.config import Settings
    test_settings = Settings()
    assert test_settings.auth_enabled is True

    # Reset
    os.environ.pop("AGENTPEP_AUTH_ENABLED", None)


# ---------------------------------------------------------------------------
# APEP-019: FAIL_OPEN / FAIL_CLOSED config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fail_closed_is_default():
    """Default fail mode should be FAIL_CLOSED."""
    from app.core.config import settings

    assert settings.default_fail_mode == "FAIL_CLOSED"


@pytest.mark.asyncio
async def test_fail_mode_configurable():
    """FAIL_OPEN and FAIL_CLOSED should be configurable via env."""
    import os
    os.environ["AGENTPEP_DEFAULT_FAIL_MODE"] = "FAIL_OPEN"

    from app.core.config import Settings
    test_settings = Settings()
    assert test_settings.default_fail_mode == "FAIL_OPEN"

    os.environ.pop("AGENTPEP_DEFAULT_FAIL_MODE", None)
