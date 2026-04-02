"""Sprint 7 — Confused-Deputy Detector tests.

APEP-054: DelegationHop data model
APEP-055: DelegationChainWalker
APEP-056: AuthorityValidator
APEP-057: Chain depth limit enforcement
APEP-058: Implicit delegation detection
APEP-059: SECURITY_ALERT events
APEP-060: PolicyEvaluator integration
APEP-061: Attack simulation tests
"""

import pytest
from uuid import uuid4

from httpx import ASGITransport, AsyncClient

import app.db.mongodb as db_module
from app.main import app
from app.models.policy import (
    Decision,
    DelegationChain,
    DelegationHop,
    SecurityAlertEvent,
    SecurityAlertType,
)
from app.services.confused_deputy import (
    AuthorityValidator,
    ChainDepthEnforcer,
    ConfusedDeputyDetector,
    DelegationChainWalker,
    ImplicitDelegationDetector,
    SecurityAlertEmitter,
    confused_deputy_detector,
    security_alert_emitter,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_hop(agent_id: str, granted_tools: list[str] | None = None,
              authority_source: str = "user") -> DelegationHop:
    return DelegationHop(
        agent_id=agent_id,
        granted_tools=granted_tools or [],
        authority_source=authority_source,
    )


async def _seed_agent_profile(db, agent_id: str, roles: list[str] | None = None,
                               max_delegation_depth: int = 5):
    await db[db_module.AGENT_PROFILES].insert_one({
        "agent_id": agent_id,
        "name": f"Agent {agent_id}",
        "roles": roles or ["default"],
        "allowed_tools": ["*"],
        "risk_budget": 1.0,
        "max_delegation_depth": max_delegation_depth,
        "session_limit": 100,
        "enabled": True,
    })


async def _seed_role(db, role_id: str, allowed_tools: list[str] | None = None):
    await db[db_module.AGENT_ROLES].insert_one({
        "role_id": role_id,
        "name": f"Role {role_id}",
        "parent_roles": [],
        "allowed_tools": allowed_tools or ["*"],
        "denied_tools": [],
        "max_risk_threshold": 1.0,
        "enabled": True,
    })


async def _seed_allow_rule(db, tool_pattern: str = "*", agent_role: list[str] | None = None):
    await db[db_module.POLICY_RULES].insert_one({
        "rule_id": str(uuid4()),
        "name": "allow-all",
        "agent_role": agent_role or ["*"],
        "tool_pattern": tool_pattern,
        "action": "ALLOW",
        "taint_check": False,
        "risk_threshold": 1.0,
        "priority": 100,
        "enabled": True,
    })


# ===========================================================================
# APEP-054: DelegationHop / DelegationChain model tests
# ===========================================================================


class TestDelegationHopModel:
    def test_delegation_hop_defaults(self):
        hop = DelegationHop(agent_id="agent-1")
        assert hop.agent_id == "agent-1"
        assert hop.granted_tools == []
        assert hop.authority_source == "user"

    def test_delegation_hop_with_grants(self):
        hop = DelegationHop(
            agent_id="agent-2",
            granted_tools=["file_read", "file_write"],
            authority_source="role:admin",
        )
        assert hop.granted_tools == ["file_read", "file_write"]
        assert hop.authority_source == "role:admin"

    def test_delegation_chain_depth(self):
        chain = DelegationChain(
            session_id="sess-1",
            hops=[_make_hop("a"), _make_hop("b"), _make_hop("c")],
        )
        assert chain.depth == 3
        assert chain.origin_agent == "a"
        assert chain.current_agent == "c"

    def test_delegation_chain_empty(self):
        chain = DelegationChain(session_id="sess-1")
        assert chain.depth == 0
        assert chain.origin_agent is None
        assert chain.current_agent is None


# ===========================================================================
# APEP-055: DelegationChainWalker tests
# ===========================================================================


class TestDelegationChainWalker:
    def test_walk_returns_enumerated_hops(self):
        hops = [_make_hop("a"), _make_hop("b"), _make_hop("c")]
        walked = DelegationChainWalker.walk(hops)
        assert len(walked) == 3
        assert walked[0] == (0, hops[0])
        assert walked[2] == (2, hops[2])

    def test_get_agent_ids(self):
        hops = [_make_hop("x"), _make_hop("y"), _make_hop("z")]
        ids = DelegationChainWalker.get_agent_ids(hops)
        assert ids == ["x", "y", "z"]

    def test_get_granted_tools_at_hop(self):
        hops = [
            _make_hop("a", granted_tools=["file_*"]),
            _make_hop("b", granted_tools=["file_read"]),
        ]
        assert DelegationChainWalker.get_granted_tools_at_hop(hops, 0) == ["file_*"]
        assert DelegationChainWalker.get_granted_tools_at_hop(hops, 1) == ["file_read"]
        assert DelegationChainWalker.get_granted_tools_at_hop(hops, 5) == []

    def test_find_authority_source(self):
        hops = [
            _make_hop("a", authority_source="user"),
            _make_hop("b", authority_source="role:admin"),
        ]
        assert DelegationChainWalker.find_authority_source(hops, "a") == "user"
        assert DelegationChainWalker.find_authority_source(hops, "b") == "role:admin"
        assert DelegationChainWalker.find_authority_source(hops, "missing") is None


# ===========================================================================
# APEP-056: AuthorityValidator tests
# ===========================================================================


class TestAuthorityValidator:
    @pytest.mark.asyncio
    async def test_empty_chain_is_valid(self, mock_mongodb):
        validator = AuthorityValidator()
        ok, reason = await validator.validate_chain([], "any_tool")
        assert ok is True

    @pytest.mark.asyncio
    async def test_user_authority_source_valid(self, mock_mongodb):
        validator = AuthorityValidator()
        hops = [_make_hop("agent-1", granted_tools=["file_read"], authority_source="user")]
        ok, reason = await validator.validate_chain(hops, "file_read")
        assert ok is True

    @pytest.mark.asyncio
    async def test_role_authority_source_valid(self, mock_mongodb):
        db = mock_mongodb
        await _seed_role(db, "admin")
        validator = AuthorityValidator()
        hops = [_make_hop("agent-1", granted_tools=["*"], authority_source="role:admin")]
        ok, reason = await validator.validate_chain(hops, "file_read")
        assert ok is True

    @pytest.mark.asyncio
    async def test_invalid_role_authority_denied(self, mock_mongodb):
        validator = AuthorityValidator()
        hops = [_make_hop("agent-1", granted_tools=["*"], authority_source="role:nonexistent")]
        ok, reason = await validator.validate_chain(hops, "file_read")
        assert ok is False
        assert "lacks authority" in reason

    @pytest.mark.asyncio
    async def test_child_exceeds_parent_grants_denied(self, mock_mongodb):
        validator = AuthorityValidator()
        hops = [
            _make_hop("agent-1", granted_tools=["file_read"], authority_source="user"),
            _make_hop("agent-2", granted_tools=["file_read", "file_write"], authority_source="agent:agent-1"),
        ]
        ok, reason = await validator.validate_chain(hops, "file_write")
        assert ok is False
        assert "exceed parent" in reason

    @pytest.mark.asyncio
    async def test_child_subset_of_parent_allowed(self, mock_mongodb):
        validator = AuthorityValidator()
        hops = [
            _make_hop("agent-1", granted_tools=["file_*"], authority_source="user"),
            _make_hop("agent-2", granted_tools=["file_read"], authority_source="agent:agent-1"),
        ]
        ok, reason = await validator.validate_chain(hops, "file_read")
        assert ok is True

    @pytest.mark.asyncio
    async def test_tool_not_in_final_grants_denied(self, mock_mongodb):
        validator = AuthorityValidator()
        hops = [
            _make_hop("agent-1", granted_tools=["file_read"], authority_source="user"),
        ]
        ok, reason = await validator.validate_chain(hops, "db_delete")
        assert ok is False
        assert "not in granted tools" in reason

    @pytest.mark.asyncio
    async def test_tools_subset_glob_matching(self, mock_mongodb):
        assert AuthorityValidator._tools_subset(["file_read"], ["file_*"]) is True
        assert AuthorityValidator._tools_subset(["db_write"], ["file_*"]) is False
        assert AuthorityValidator._tools_subset([], ["file_*"]) is True
        assert AuthorityValidator._tools_subset(["file_read"], []) is False


# ===========================================================================
# APEP-057: Chain Depth Limit tests
# ===========================================================================


class TestChainDepthEnforcer:
    @pytest.mark.asyncio
    async def test_within_default_limit(self, mock_mongodb):
        enforcer = ChainDepthEnforcer(default_max_depth=5)
        hops = [_make_hop(f"a{i}") for i in range(5)]
        ok, _ = await enforcer.check_depth(hops)
        assert ok is True

    @pytest.mark.asyncio
    async def test_exceeds_default_limit(self, mock_mongodb):
        enforcer = ChainDepthEnforcer(default_max_depth=3)
        hops = [_make_hop(f"a{i}") for i in range(4)]
        ok, reason = await enforcer.check_depth(hops)
        assert ok is False
        assert "exceeds maximum 3" in reason

    @pytest.mark.asyncio
    async def test_agent_profile_overrides_default(self, mock_mongodb):
        db = mock_mongodb
        await _seed_agent_profile(db, "deep-agent", max_delegation_depth=2)
        enforcer = ChainDepthEnforcer(default_max_depth=10)
        hops = [_make_hop(f"a{i}") for i in range(3)]
        ok, reason = await enforcer.check_depth(hops, agent_id="deep-agent")
        assert ok is False
        assert "exceeds maximum 2" in reason

    @pytest.mark.asyncio
    async def test_single_hop_always_allowed(self, mock_mongodb):
        enforcer = ChainDepthEnforcer(default_max_depth=1)
        hops = [_make_hop("a")]
        ok, _ = await enforcer.check_depth(hops)
        assert ok is True


# ===========================================================================
# APEP-058: Implicit Delegation Detection tests
# ===========================================================================


class TestImplicitDelegationDetector:
    @pytest.mark.asyncio
    async def test_explicit_chain_not_implicit(self, mock_mongodb):
        detector = ImplicitDelegationDetector()
        hops = [_make_hop("a")]
        is_implicit, _ = await detector.detect("sess-1", "agent-b", "file_read", hops)
        assert is_implicit is False

    @pytest.mark.asyncio
    async def test_no_prior_writes_not_implicit(self, mock_mongodb):
        detector = ImplicitDelegationDetector()
        is_implicit, _ = await detector.detect("sess-1", "agent-b", "execute_code", [])
        assert is_implicit is False

    @pytest.mark.asyncio
    async def test_detects_implicit_delegation_from_write(self, mock_mongodb):
        db = mock_mongodb
        # Agent-A wrote to shared workspace
        await db[db_module.AUDIT_DECISIONS].insert_one({
            "decision_id": str(uuid4()),
            "session_id": "sess-1",
            "agent_id": "agent-a",
            "agent_role": "writer",
            "tool_name": "file_write",
            "tool_args_hash": "abc",
            "decision": "ALLOW",
            "timestamp": "2026-01-01T00:00:00",
        })

        detector = ImplicitDelegationDetector()
        is_implicit, detail = await detector.detect("sess-1", "agent-b", "execute_code", [])
        assert is_implicit is True
        assert "agent-a" in detail
        assert "file_write" in detail

    @pytest.mark.asyncio
    async def test_read_tool_not_flagged(self, mock_mongodb):
        db = mock_mongodb
        await db[db_module.AUDIT_DECISIONS].insert_one({
            "decision_id": str(uuid4()),
            "session_id": "sess-1",
            "agent_id": "agent-a",
            "agent_role": "writer",
            "tool_name": "file_write",
            "tool_args_hash": "abc",
            "decision": "ALLOW",
            "timestamp": "2026-01-01T00:00:00",
        })

        detector = ImplicitDelegationDetector()
        # Agent-B doing a read should not trigger implicit delegation
        is_implicit, _ = await detector.detect("sess-1", "agent-b", "file_read", [])
        assert is_implicit is False

    def test_write_pattern_matching(self):
        assert ImplicitDelegationDetector._is_write_tool("file_write") is True
        assert ImplicitDelegationDetector._is_write_tool("db_create_record") is True
        assert ImplicitDelegationDetector._is_write_tool("s3_upload") is True
        assert ImplicitDelegationDetector._is_write_tool("file_read") is False
        assert ImplicitDelegationDetector._is_write_tool("get_status") is False


# ===========================================================================
# APEP-059: Security Alert Event tests
# ===========================================================================


class TestSecurityAlertEmitter:
    @pytest.mark.asyncio
    async def test_emit_persists_to_db(self, mock_mongodb):
        db = mock_mongodb
        emitter = SecurityAlertEmitter()
        alert = SecurityAlertEvent(
            alert_type=SecurityAlertType.PRIVILEGE_ESCALATION,
            session_id="sess-1",
            agent_id="agent-bad",
            tool_name="admin_delete",
            detail="Agent exceeded grants",
            severity="CRITICAL",
        )
        await emitter.emit(alert)

        # Check in-memory buffer
        assert len(emitter.buffer) == 1
        assert emitter.buffer[0].alert_type == SecurityAlertType.PRIVILEGE_ESCALATION

        # Check MongoDB
        from app.services.confused_deputy import SECURITY_ALERTS
        doc = await db[SECURITY_ALERTS].find_one({"agent_id": "agent-bad"})
        assert doc is not None
        assert doc["alert_type"] == "PRIVILEGE_ESCALATION"
        assert doc["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_get_alerts_filters_by_session(self, mock_mongodb):
        db = mock_mongodb
        emitter = SecurityAlertEmitter()
        for i, sess in enumerate(["s1", "s1", "s2"]):
            await emitter.emit(SecurityAlertEvent(
                alert_type=SecurityAlertType.CHAIN_DEPTH_EXCEEDED,
                session_id=sess,
                agent_id=f"agent-{i}",
                detail="test",
            ))

        alerts = await emitter.get_alerts(session_id="s1")
        assert len(alerts) == 2

    @pytest.mark.asyncio
    async def test_get_alerts_filters_by_type(self, mock_mongodb):
        emitter = SecurityAlertEmitter()
        await emitter.emit(SecurityAlertEvent(
            alert_type=SecurityAlertType.PRIVILEGE_ESCALATION,
            session_id="s1", agent_id="a1", detail="test",
        ))
        await emitter.emit(SecurityAlertEvent(
            alert_type=SecurityAlertType.CHAIN_DEPTH_EXCEEDED,
            session_id="s1", agent_id="a2", detail="test",
        ))

        alerts = await emitter.get_alerts(
            alert_type=SecurityAlertType.PRIVILEGE_ESCALATION
        )
        assert len(alerts) == 1
        assert alerts[0].alert_type == SecurityAlertType.PRIVILEGE_ESCALATION

    @pytest.mark.asyncio
    async def test_clear_buffer(self, mock_mongodb):
        emitter = SecurityAlertEmitter()
        await emitter.emit(SecurityAlertEvent(
            alert_type=SecurityAlertType.IMPLICIT_DELEGATION,
            session_id="s1", agent_id="a1", detail="test",
        ))
        assert len(emitter.buffer) == 1
        emitter.clear()
        assert len(emitter.buffer) == 0


# ===========================================================================
# APEP-060: ConfusedDeputyDetector (orchestrator) tests
# ===========================================================================


class TestConfusedDeputyDetector:
    @pytest.mark.asyncio
    async def test_valid_chain_allowed(self, mock_mongodb):
        detector = ConfusedDeputyDetector(max_chain_depth=5)
        hops = [
            _make_hop("agent-1", granted_tools=["file_*"], authority_source="user"),
            _make_hop("agent-2", granted_tools=["file_read"], authority_source="agent:agent-1"),
        ]
        ok, reason = await detector.evaluate("sess-1", "agent-2", "file_read", hops)
        assert ok is True

    @pytest.mark.asyncio
    async def test_depth_exceeded_denied(self, mock_mongodb):
        detector = ConfusedDeputyDetector(max_chain_depth=2)
        hops = [_make_hop(f"a{i}", granted_tools=["*"], authority_source="user") for i in range(3)]
        ok, reason = await detector.evaluate("sess-1", "a2", "any_tool", hops)
        assert ok is False
        assert "exceeds maximum" in reason

    @pytest.mark.asyncio
    async def test_privilege_escalation_detected(self, mock_mongodb):
        detector = ConfusedDeputyDetector()
        hops = [
            _make_hop("agent-1", granted_tools=["file_read"], authority_source="user"),
            _make_hop("agent-2", granted_tools=["file_read", "admin_delete"],
                      authority_source="agent:agent-1"),
        ]
        ok, reason = await detector.evaluate("sess-1", "agent-2", "admin_delete", hops)
        assert ok is False
        assert "exceed parent" in reason
        # Verify SECURITY_ALERT was emitted
        alerts = detector.alert_emitter.buffer
        assert len(alerts) == 1
        assert alerts[0].alert_type == SecurityAlertType.PRIVILEGE_ESCALATION
        assert alerts[0].severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_implicit_delegation_escalates(self, mock_mongodb):
        db = mock_mongodb
        # Agent-A previously wrote
        await db[db_module.AUDIT_DECISIONS].insert_one({
            "decision_id": str(uuid4()),
            "session_id": "sess-1",
            "agent_id": "agent-a",
            "agent_role": "writer",
            "tool_name": "file_write",
            "tool_args_hash": "abc",
            "decision": "ALLOW",
            "timestamp": "2026-01-01T00:00:00",
        })

        detector = ConfusedDeputyDetector()
        ok, reason = await detector.evaluate("sess-1", "agent-b", "execute_code", [])
        assert ok is False
        assert "ESCALATE" in reason
        alerts = detector.alert_emitter.buffer
        assert len(alerts) == 1
        assert alerts[0].alert_type == SecurityAlertType.IMPLICIT_DELEGATION


# ===========================================================================
# APEP-061: Attack Simulation Tests (privilege escalation via agent chain)
# ===========================================================================


class TestAttackSimulations:
    """End-to-end attack simulations that verify the confused-deputy detector
    blocks real-world privilege escalation patterns."""

    @pytest.mark.asyncio
    async def test_attack_tool_grant_escalation(self, mock_mongodb):
        """Attack: Agent-A (file_read only) delegates to Agent-B claiming
        file_read + admin_delete. Agent-B tries admin_delete.
        Expected: DENY with PRIVILEGE_ESCALATION alert."""
        detector = ConfusedDeputyDetector()
        hops = [
            _make_hop("agent-reader", granted_tools=["file_read"],
                      authority_source="user"),
            _make_hop("agent-malicious", granted_tools=["file_read", "admin_delete"],
                      authority_source="agent:agent-reader"),
        ]
        ok, reason = await detector.evaluate("attack-sess", "agent-malicious",
                                             "admin_delete", hops)
        assert ok is False
        alert = detector.alert_emitter.buffer[0]
        assert alert.alert_type == SecurityAlertType.PRIVILEGE_ESCALATION
        assert alert.severity == "CRITICAL"
        assert alert.session_id == "attack-sess"

    @pytest.mark.asyncio
    async def test_attack_deep_chain_obfuscation(self, mock_mongodb):
        """Attack: Create a chain of 10 agents to hide the final malicious call
        behind many layers of delegation.
        Expected: DENY with CHAIN_DEPTH_EXCEEDED alert."""
        detector = ConfusedDeputyDetector(max_chain_depth=5)
        hops = [
            _make_hop(f"agent-{i}", granted_tools=["*"], authority_source="user")
            for i in range(10)
        ]
        ok, reason = await detector.evaluate("attack-sess", "agent-9",
                                             "admin_delete", hops)
        assert ok is False
        alert = detector.alert_emitter.buffer[0]
        assert alert.alert_type == SecurityAlertType.CHAIN_DEPTH_EXCEEDED

    @pytest.mark.asyncio
    async def test_attack_invalid_role_authority(self, mock_mongodb):
        """Attack: Agent claims authority from a non-existent role.
        Expected: DENY with AUTHORITY_VIOLATION alert."""
        detector = ConfusedDeputyDetector()
        hops = [
            _make_hop("agent-fake", granted_tools=["*"],
                      authority_source="role:superadmin_fake"),
        ]
        ok, reason = await detector.evaluate("attack-sess", "agent-fake",
                                             "admin_delete", hops)
        assert ok is False
        alert = detector.alert_emitter.buffer[0]
        assert alert.alert_type == SecurityAlertType.AUTHORITY_VIOLATION

    @pytest.mark.asyncio
    async def test_attack_implicit_delegation_via_shared_workspace(self, mock_mongodb):
        """Attack: Agent-A writes malicious instructions to shared workspace.
        Agent-B reads and executes without explicit delegation.
        Expected: ESCALATE with IMPLICIT_DELEGATION alert."""
        db = mock_mongodb
        # Agent-A writes malicious payload
        await db[db_module.AUDIT_DECISIONS].insert_one({
            "decision_id": str(uuid4()),
            "session_id": "attack-sess",
            "agent_id": "agent-malicious-writer",
            "agent_role": "writer",
            "tool_name": "workspace_write",
            "tool_args_hash": "malicious-hash",
            "decision": "ALLOW",
            "timestamp": "2026-01-01T00:00:00",
        })

        detector = ConfusedDeputyDetector()
        ok, reason = await detector.evaluate(
            "attack-sess", "agent-victim", "execute_command", []
        )
        assert ok is False
        assert "ESCALATE" in reason
        alert = detector.alert_emitter.buffer[0]
        assert alert.alert_type == SecurityAlertType.IMPLICIT_DELEGATION
        assert "agent-malicious-writer" in alert.detail

    @pytest.mark.asyncio
    async def test_attack_multi_hop_narrowing_valid(self, mock_mongodb):
        """Legitimate pattern: each hop narrows tool grants.
        user → agent-A (file_*) → agent-B (file_read) → tool call file_read
        Expected: ALLOW — this is proper delegation."""
        detector = ConfusedDeputyDetector()
        hops = [
            _make_hop("agent-A", granted_tools=["file_*"], authority_source="user"),
            _make_hop("agent-B", granted_tools=["file_read"],
                      authority_source="agent:agent-A"),
        ]
        ok, reason = await detector.evaluate("legit-sess", "agent-B",
                                             "file_read", hops)
        assert ok is True

    @pytest.mark.asyncio
    async def test_attack_unknown_authority_source(self, mock_mongodb):
        """Attack: Agent claims authority from an unknown source type.
        Expected: DENY — unrecognized authority source is rejected."""
        detector = ConfusedDeputyDetector()
        hops = [
            _make_hop("agent-x", granted_tools=["*"],
                      authority_source="magic:crystal_ball"),
        ]
        ok, reason = await detector.evaluate("attack-sess", "agent-x",
                                             "admin_delete", hops)
        assert ok is False

    @pytest.mark.asyncio
    async def test_intercept_api_with_delegation_hops(self, mock_mongodb):
        """Integration test: POST /v1/intercept with delegation_hops
        triggers confused-deputy checks and returns DENY on violation."""
        db = mock_mongodb
        await _seed_allow_rule(db)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/v1/intercept", json={
                "session_id": "integration-sess",
                "agent_id": "agent-bad",
                "tool_name": "admin_delete",
                "delegation_hops": [
                    {
                        "agent_id": "agent-reader",
                        "granted_tools": ["file_read"],
                        "authority_source": "user",
                    },
                    {
                        "agent_id": "agent-bad",
                        "granted_tools": ["file_read", "admin_delete"],
                        "authority_source": "agent:agent-reader",
                    },
                ],
            })

        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "DENY"
        assert "Confused-deputy" in data["reason"]

    @pytest.mark.asyncio
    async def test_intercept_api_valid_delegation_allowed(self, mock_mongodb):
        """Integration test: valid delegation chain passes through to normal
        rule evaluation."""
        db = mock_mongodb
        await _seed_allow_rule(db)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/v1/intercept", json={
                "session_id": "integration-sess",
                "agent_id": "agent-good",
                "tool_name": "file_read",
                "delegation_hops": [
                    {
                        "agent_id": "agent-root",
                        "granted_tools": ["file_*"],
                        "authority_source": "user",
                    },
                    {
                        "agent_id": "agent-good",
                        "granted_tools": ["file_read"],
                        "authority_source": "agent:agent-root",
                    },
                ],
            })

        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "ALLOW"
