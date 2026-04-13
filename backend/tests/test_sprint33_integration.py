"""Integration tests for Sprint 33 features (APEP-266).

End-to-end tests spanning MemoryAccessGate, ContextAuthorityTracker,
and DEFER/MODIFY decision types.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.db import mongodb as db_module
from app.models.policy import (
    Decision,
    PolicyDecisionResponse,
    TaintSource,
)
from app.services.context_authority import (
    ContextAuthority,
    context_authority_tracker,
)
from app.services.memory_access_gate import (
    MemoryAccessGate,
    MemoryAccessPolicy,
    MemoryAccessRequest,
    MemoryOperation,
    memory_access_gate,
)
from app.services.risk_scoring import RiskScoringEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _insert_memory_policy(db, **overrides) -> MemoryAccessPolicy:
    defaults = {
        "policy_id": str(uuid4()),
        "store_pattern": "test_store",
        "allowed_writers": ["agent-*"],
        "allowed_readers": ["agent-*"],
        "prohibited_content_patterns": [],
        "max_entries_per_session": 100,
        "max_entry_size_bytes": 65536,
        "max_age_seconds": None,
        "enabled": True,
        "created_at": datetime.now(UTC).isoformat(),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    defaults.update(overrides)
    await db[db_module.MEMORY_ACCESS_POLICIES].insert_one(defaults)
    return MemoryAccessPolicy(**defaults)


# ---------------------------------------------------------------------------
# Memory gate CRUD lifecycle
# ---------------------------------------------------------------------------


class TestMemoryGateLifecycle:
    """End-to-end: create policy -> write -> read -> delete."""

    async def test_full_write_read_delete_lifecycle(self, mock_mongodb) -> None:
        await _insert_memory_policy(mock_mongodb, store_pattern="lifecycle_store")

        # Write
        write_req = MemoryAccessRequest(
            session_id="e2e-sess",
            agent_id="agent-e2e",
            store_name="lifecycle_store",
            operation=MemoryOperation.WRITE,
            key="test-key",
            value="test-value",
        )
        write_result = await memory_access_gate.evaluate(write_req)
        assert write_result.allowed is True
        assert write_result.entry_count == 1

        # Read
        read_req = MemoryAccessRequest(
            session_id="e2e-sess",
            agent_id="agent-e2e",
            store_name="lifecycle_store",
            operation=MemoryOperation.READ,
        )
        read_result = await memory_access_gate.evaluate(read_req)
        assert read_result.allowed is True
        assert read_result.entry_count == 1

        # Delete
        delete_req = MemoryAccessRequest(
            session_id="e2e-sess",
            agent_id="agent-e2e",
            store_name="lifecycle_store",
            operation=MemoryOperation.DELETE,
            key="test-key",
        )
        delete_result = await memory_access_gate.evaluate(delete_req)
        assert delete_result.allowed is True

    async def test_write_prohibited_content_then_clean(self, mock_mongodb) -> None:
        await _insert_memory_policy(
            mock_mongodb,
            store_pattern="secure_store",
            prohibited_content_patterns=[r"password\s*[:=]"],
        )

        # Prohibited write → denied
        bad_req = MemoryAccessRequest(
            session_id="e2e-sec",
            agent_id="agent-e2e",
            store_name="secure_store",
            operation=MemoryOperation.WRITE,
            key="creds",
            value="password: secret123",
        )
        bad_result = await memory_access_gate.evaluate(bad_req)
        assert bad_result.allowed is False
        assert "prohibited pattern" in bad_result.reason

        # Clean write → allowed
        good_req = MemoryAccessRequest(
            session_id="e2e-sec",
            agent_id="agent-e2e",
            store_name="secure_store",
            operation=MemoryOperation.WRITE,
            key="data",
            value="regular data",
        )
        good_result = await memory_access_gate.evaluate(good_req)
        assert good_result.allowed is True

    async def test_write_at_limit_then_denied(self, mock_mongodb) -> None:
        await _insert_memory_policy(
            mock_mongodb,
            store_pattern="limited_store",
            max_entries_per_session=2,
        )

        for i in range(2):
            req = MemoryAccessRequest(
                session_id="e2e-limit",
                agent_id="agent-e2e",
                store_name="limited_store",
                operation=MemoryOperation.WRITE,
                key=f"key-{i}",
                value=f"value-{i}",
            )
            result = await memory_access_gate.evaluate(req)
            assert result.allowed is True

        # 3rd write → denied
        overflow_req = MemoryAccessRequest(
            session_id="e2e-limit",
            agent_id="agent-e2e",
            store_name="limited_store",
            operation=MemoryOperation.WRITE,
            key="overflow",
            value="overflow",
        )
        overflow_result = await memory_access_gate.evaluate(overflow_req)
        assert overflow_result.allowed is False
        assert "reached the limit" in overflow_result.reason

    async def test_read_with_expired_entries_purged(self, mock_mongodb) -> None:
        await _insert_memory_policy(
            mock_mongodb,
            store_pattern="ttl_store",
            max_age_seconds=30,
        )

        old_time = datetime.now(UTC) - timedelta(seconds=60)
        for i in range(2):
            await mock_mongodb[db_module.MEMORY_ENTRIES].insert_one(
                {
                    "entry_id": str(uuid4()),
                    "session_id": "e2e-ttl",
                    "agent_id": "agent-e2e",
                    "store_name": "ttl_store",
                    "key": f"old-{i}",
                    "created_at": old_time,
                }
            )

        await mock_mongodb[db_module.MEMORY_ENTRIES].insert_one(
            {
                "entry_id": str(uuid4()),
                "session_id": "e2e-ttl",
                "agent_id": "agent-e2e",
                "store_name": "ttl_store",
                "key": "fresh",
                "created_at": datetime.now(UTC),
            }
        )

        read_req = MemoryAccessRequest(
            session_id="e2e-ttl",
            agent_id="agent-e2e",
            store_name="ttl_store",
            operation=MemoryOperation.READ,
        )
        result = await memory_access_gate.evaluate(read_req)
        assert result.allowed is True
        assert len(result.purged_keys) == 2
        assert result.entry_count == 1


# ---------------------------------------------------------------------------
# Context authority scoring end-to-end
# ---------------------------------------------------------------------------


class TestContextAuthorityE2E:
    """End-to-end: context authority → risk scoring."""

    async def test_untrusted_context_elevates_risk(self, mock_mongodb) -> None:
        await context_authority_tracker.track_entry(
            "risk-e2e", TaintSource.WEB
        )
        await context_authority_tracker.track_entry(
            "risk-e2e", TaintSource.EMAIL
        )

        engine = RiskScoringEngine()
        score, factors = await engine.compute(
            tool_name="read_data",
            tool_args={},
            session_id="risk-e2e",
        )

        ctx_factor = next(f for f in factors if f.factor_name == "context_authority")
        assert ctx_factor.score == 0.9  # All untrusted → majority
        # Overall score should reflect elevated context authority
        assert score > 0.0

    async def test_authoritative_only_low_risk(self, mock_mongodb) -> None:
        await context_authority_tracker.track_entry(
            "auth-e2e", TaintSource.USER_PROMPT
        )
        await context_authority_tracker.track_entry(
            "auth-e2e", TaintSource.SYSTEM_PROMPT
        )

        engine = RiskScoringEngine()
        score, factors = await engine.compute(
            tool_name="read_data",
            tool_args={},
            session_id="auth-e2e",
        )

        ctx_factor = next(f for f in factors if f.factor_name == "context_authority")
        assert ctx_factor.score == 0.0

    async def test_mixed_session_authority_distribution(self, mock_mongodb) -> None:
        await context_authority_tracker.track_entry("mixed-e2e", TaintSource.USER_PROMPT)
        await context_authority_tracker.track_entry("mixed-e2e", TaintSource.TOOL_OUTPUT)
        await context_authority_tracker.track_entry("mixed-e2e", TaintSource.WEB)

        counts = await context_authority_tracker.get_session_authorities("mixed-e2e")
        assert counts[ContextAuthority.AUTHORITATIVE] == 1
        assert counts[ContextAuthority.DERIVED] == 1
        assert counts[ContextAuthority.UNTRUSTED] == 1

        score = await context_authority_tracker.get_authority_score("mixed-e2e")
        # 1 untrusted out of 3 (33%) → 0.7 (any untrusted present)
        assert score == 0.7


# ---------------------------------------------------------------------------
# DEFER/MODIFY decision types
# ---------------------------------------------------------------------------


class TestDeferModifyDecisions:
    """End-to-end: DEFER and MODIFY decision type serialisation."""

    def test_defer_decision_serialisation(self) -> None:
        resp = PolicyDecisionResponse(
            request_id=uuid4(),
            decision=Decision.DEFER,
            reason="Awaiting human approval",
            defer_timeout_s=45,
        )
        data = resp.model_dump(mode="json")
        assert data["decision"] == "DEFER"
        assert data["defer_timeout_s"] == 45
        # No execution token for DEFER
        assert data.get("execution_token") is None

    def test_modify_decision_serialisation(self) -> None:
        resp = PolicyDecisionResponse(
            request_id=uuid4(),
            decision=Decision.MODIFY,
            reason="Args sanitized",
            modified_args={"path": "/safe/file.txt"},
        )
        data = resp.model_dump(mode="json")
        assert data["decision"] == "MODIFY"
        assert data["modified_args"] == {"path": "/safe/file.txt"}
        # No execution token for MODIFY
        assert data.get("execution_token") is None

    def test_defer_roundtrip(self) -> None:
        original = PolicyDecisionResponse(
            request_id=uuid4(),
            decision=Decision.DEFER,
            reason="Pending review",
            defer_timeout_s=120,
        )
        data = original.model_dump(mode="json")
        restored = PolicyDecisionResponse(**data)
        assert restored.decision == Decision.DEFER
        assert restored.defer_timeout_s == 120

    def test_modify_roundtrip(self) -> None:
        original = PolicyDecisionResponse(
            request_id=uuid4(),
            decision=Decision.MODIFY,
            reason="Rewritten",
            modified_args={"cmd": "ls", "dir": "/tmp"},
        )
        data = original.model_dump(mode="json")
        restored = PolicyDecisionResponse(**data)
        assert restored.decision == Decision.MODIFY
        assert restored.modified_args == {"cmd": "ls", "dir": "/tmp"}


# ---------------------------------------------------------------------------
# Cross-feature: memory gate + context authority
# ---------------------------------------------------------------------------


class TestCrossFeature:
    """Cross-feature interactions between memory gate and context authority."""

    async def test_memory_write_and_context_tracking(self, mock_mongodb) -> None:
        """Memory write + context tracking in same session don't interfere."""
        await _insert_memory_policy(mock_mongodb, store_pattern="cross_store")

        # Track context
        await context_authority_tracker.track_entry("cross-sess", TaintSource.USER_PROMPT)
        await context_authority_tracker.track_entry("cross-sess", TaintSource.TOOL_OUTPUT)

        # Write to memory store
        write_req = MemoryAccessRequest(
            session_id="cross-sess",
            agent_id="agent-cross",
            store_name="cross_store",
            operation=MemoryOperation.WRITE,
            key="data",
            value="some data",
        )
        write_result = await memory_access_gate.evaluate(write_req)
        assert write_result.allowed is True

        # Context authority still accurate
        counts = await context_authority_tracker.get_session_authorities("cross-sess")
        assert counts[ContextAuthority.AUTHORITATIVE] == 1
        assert counts[ContextAuthority.DERIVED] == 1

        # Memory entry count is separate
        assert write_result.entry_count == 1

    async def test_deny_by_default_all_stores(self, mock_mongodb) -> None:
        """No policy for any store → denied."""
        req = MemoryAccessRequest(
            session_id="no-policy",
            agent_id="agent-any",
            store_name="nonexistent_store",
            operation=MemoryOperation.WRITE,
            key="key",
            value="val",
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is False
        assert "No memory access policy" in result.reason
