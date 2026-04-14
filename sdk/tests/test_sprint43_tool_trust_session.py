"""Tests for Sprint 43 -- ToolTrustSession SDK class.

APEP-344: ToolTrustSession unit tests.
APEP-345: SDK delegate() method tests.
"""

import pytest

from agentpep.tool_trust_session import (
    AuditTree,
    DelegationResult,
    PlanInfo,
    ToolTrustSession,
)


# ===========================================================================
# PlanInfo Tests
# ===========================================================================


class TestPlanInfo:
    """Tests for the PlanInfo helper class."""

    def test_from_dict(self):
        info = PlanInfo({
            "plan_id": "550e8400-e29b-41d4-a716-446655440000",
            "action": "Analyze reports",
            "issuer": "alice@corp.com",
            "status": "ACTIVE",
            "signature": "sig123",
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-02T00:00:00Z",
        })
        assert info.plan_id == "550e8400-e29b-41d4-a716-446655440000"
        assert info.action == "Analyze reports"
        assert info.issuer == "alice@corp.com"
        assert info.status == "ACTIVE"
        assert info.expires_at == "2026-01-02T00:00:00Z"

    def test_from_dict_missing_optional(self):
        info = PlanInfo({"plan_id": "abc"})
        assert info.plan_id == "abc"
        assert info.action == ""
        assert info.expires_at is None

    def test_repr(self):
        info = PlanInfo({"plan_id": "abc", "action": "test", "status": "ACTIVE"})
        r = repr(info)
        assert "abc" in r
        assert "test" in r
        assert "ACTIVE" in r


# ===========================================================================
# AuditTree Tests
# ===========================================================================


class TestAuditTree:
    """Tests for the AuditTree helper class."""

    def test_from_dict(self):
        tree = AuditTree({
            "plan_id": "abc",
            "receipts": [{"id": "r1"}, {"id": "r2"}],
            "chain_valid": True,
        })
        assert tree.plan_id == "abc"
        assert tree.total == 2
        assert tree.chain_valid is True
        assert len(tree.receipts) == 2

    def test_from_dict_empty(self):
        tree = AuditTree({})
        assert tree.plan_id == ""
        assert tree.total == 0
        assert tree.chain_valid is True

    def test_repr(self):
        tree = AuditTree({"plan_id": "xyz", "receipts": [{"id": "r1"}]})
        assert "xyz" in repr(tree)
        assert "1" in repr(tree)


# ===========================================================================
# DelegationResult Tests
# ===========================================================================


class TestDelegationResult:
    """Tests for the DelegationResult helper class."""

    def test_allowed(self):
        dr = DelegationResult(
            allowed=True,
            child_agent_id="child-bot",
            decision="ALLOW",
            reason="Within scope",
        )
        assert dr.allowed is True
        assert dr.child_agent_id == "child-bot"
        assert dr.decision == "ALLOW"

    def test_denied(self):
        dr = DelegationResult(
            allowed=False,
            child_agent_id="rogue-bot",
            decision="DENY",
            reason="Not in whitelist",
        )
        assert dr.allowed is False
        assert dr.decision == "DENY"

    def test_repr(self):
        dr = DelegationResult(allowed=True, child_agent_id="bot")
        r = repr(dr)
        assert "bot" in r
        assert "True" in r


# ===========================================================================
# ToolTrustSession Tests
# ===========================================================================


class TestToolTrustSession:
    """Unit tests for the ToolTrustSession class."""

    def test_init_defaults(self):
        session = ToolTrustSession()
        assert session.session_id == "default"
        assert session.agent_id == "default-agent"
        assert session.plan is None

    def test_init_custom(self):
        session = ToolTrustSession(
            base_url="http://example.com:9000",
            api_key="test-key",
            timeout=10.0,
            fail_open=True,
            session_id="my-session",
            agent_id="my-agent",
        )
        assert session.session_id == "my-session"
        assert session.agent_id == "my-agent"
        assert session._base_url == "http://example.com:9000"
        assert session._api_key == "test-key"

    def test_plan_initially_none(self):
        session = ToolTrustSession()
        assert session.plan is None

    @pytest.mark.asyncio
    async def test_audit_without_plan_raises(self):
        session = ToolTrustSession()
        with pytest.raises(RuntimeError, match="No plan bound"):
            await session.audit()

    @pytest.mark.asyncio
    async def test_revoke_without_plan_raises(self):
        session = ToolTrustSession()
        with pytest.raises(RuntimeError, match="No plan bound"):
            await session.revoke_plan()

    @pytest.mark.asyncio
    async def test_get_plan_detail_without_plan_raises(self):
        session = ToolTrustSession()
        with pytest.raises(RuntimeError, match="No plan bound"):
            await session.get_plan_detail()

    @pytest.mark.asyncio
    async def test_delegate_without_plan_raises(self):
        session = ToolTrustSession()
        with pytest.raises(RuntimeError, match="No plan bound"):
            await session.delegate(
                child_agent_id="child", tool_name="test.tool"
            )

    @pytest.mark.asyncio
    async def test_budget_status_without_plan_raises(self):
        session = ToolTrustSession()
        with pytest.raises(RuntimeError, match="No plan bound"):
            await session.budget_status()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        async with ToolTrustSession() as session:
            assert session.plan is None
        # After exiting, resources should be closed


# ===========================================================================
# Import / Export Tests
# ===========================================================================


class TestToolTrustSessionExports:
    """Verify ToolTrustSession is properly exported from the SDK."""

    def test_import_from_agentpep(self):
        from agentpep import ToolTrustSession
        assert ToolTrustSession is not None

    def test_import_from_module(self):
        from agentpep.tool_trust_session import ToolTrustSession
        assert ToolTrustSession is not None
