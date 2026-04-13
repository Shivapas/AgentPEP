"""Tests for Sprint 33 MemoryAccessGate (APEP-261, APEP-262, APEP-263).

Tests memory access control: write/read/delete authorisation, content pattern
blocking, entry count limits, and lazy retention enforcement.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.db import mongodb as db_module
from app.services.memory_access_gate import (
    MemoryAccessGate,
    MemoryAccessPolicy,
    MemoryAccessRequest,
    MemoryOperation,
    memory_access_gate,
)


async def _insert_policy(db, **overrides) -> MemoryAccessPolicy:
    """Helper to insert a memory access policy into the mock DB."""
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
# APEP-261: MemoryAccessGate core
# ---------------------------------------------------------------------------


class TestMemoryAccessGateCore:
    """Core gate behaviour: deny-by-default, policy lookup."""

    async def test_no_policy_denies_by_default(self, mock_mongodb) -> None:
        req = MemoryAccessRequest(
            session_id="sess-1",
            agent_id="agent-alpha",
            store_name="unknown_store",
            operation=MemoryOperation.WRITE,
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is False
        assert "No memory access policy" in result.reason

    async def test_disabled_policy_denies(self, mock_mongodb) -> None:
        await _insert_policy(mock_mongodb, store_pattern="disabled_store", enabled=False)
        req = MemoryAccessRequest(
            session_id="sess-1",
            agent_id="agent-alpha",
            store_name="disabled_store",
            operation=MemoryOperation.READ,
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is False
        assert "disabled" in result.reason


# ---------------------------------------------------------------------------
# APEP-261: Write authorisation
# ---------------------------------------------------------------------------


class TestWriteAuthorisation:
    """APEP-261/262: Write access control."""

    async def test_write_allowed_writer(self, mock_mongodb) -> None:
        await _insert_policy(mock_mongodb, store_pattern="test_store")
        req = MemoryAccessRequest(
            session_id="sess-1",
            agent_id="agent-writer",
            store_name="test_store",
            operation=MemoryOperation.WRITE,
            key="key1",
            value="hello world",
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is True
        assert result.entry_count == 1

    async def test_write_disallowed_writer(self, mock_mongodb) -> None:
        await _insert_policy(
            mock_mongodb,
            store_pattern="test_store",
            allowed_writers=["admin-*"],
        )
        req = MemoryAccessRequest(
            session_id="sess-1",
            agent_id="agent-reader",
            store_name="test_store",
            operation=MemoryOperation.WRITE,
            key="key1",
            value="data",
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is False
        assert "not an allowed writer" in result.reason

    async def test_write_glob_pattern_matching(self, mock_mongodb) -> None:
        await _insert_policy(
            mock_mongodb,
            store_pattern="project_*",
            allowed_writers=["team-*", "admin"],
        )
        req = MemoryAccessRequest(
            session_id="sess-1",
            agent_id="team-alpha",
            store_name="project_data",
            operation=MemoryOperation.WRITE,
            key="key1",
            value="data",
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is True


# ---------------------------------------------------------------------------
# APEP-262: Write content patterns and limits
# ---------------------------------------------------------------------------


class TestWriteContentPatterns:
    """APEP-262: Prohibited content patterns and entry limits."""

    async def test_prohibited_content_blocked(self, mock_mongodb) -> None:
        await _insert_policy(
            mock_mongodb,
            store_pattern="test_store",
            prohibited_content_patterns=[r"password\s*[:=]", r"\bsecret\b"],
        )
        req = MemoryAccessRequest(
            session_id="sess-1",
            agent_id="agent-writer",
            store_name="test_store",
            operation=MemoryOperation.WRITE,
            key="creds",
            value="password: hunter2",
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is False
        assert "prohibited pattern" in result.reason

    async def test_clean_content_allowed(self, mock_mongodb) -> None:
        await _insert_policy(
            mock_mongodb,
            store_pattern="test_store",
            prohibited_content_patterns=[r"password\s*[:=]"],
        )
        req = MemoryAccessRequest(
            session_id="sess-1",
            agent_id="agent-writer",
            store_name="test_store",
            operation=MemoryOperation.WRITE,
            key="data",
            value="regular data without secrets",
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is True

    async def test_entry_count_limit_enforced(self, mock_mongodb) -> None:
        await _insert_policy(
            mock_mongodb,
            store_pattern="test_store",
            max_entries_per_session=3,
        )

        # Write 3 entries
        for i in range(3):
            req = MemoryAccessRequest(
                session_id="sess-limit",
                agent_id="agent-writer",
                store_name="test_store",
                operation=MemoryOperation.WRITE,
                key=f"key-{i}",
                value=f"value-{i}",
            )
            result = await memory_access_gate.evaluate(req)
            assert result.allowed is True

        # 4th write should be denied
        req = MemoryAccessRequest(
            session_id="sess-limit",
            agent_id="agent-writer",
            store_name="test_store",
            operation=MemoryOperation.WRITE,
            key="key-overflow",
            value="overflow",
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is False
        assert "reached the limit" in result.reason

    async def test_entry_size_limit(self, mock_mongodb) -> None:
        await _insert_policy(
            mock_mongodb,
            store_pattern="test_store",
            max_entry_size_bytes=10,
        )
        req = MemoryAccessRequest(
            session_id="sess-1",
            agent_id="agent-writer",
            store_name="test_store",
            operation=MemoryOperation.WRITE,
            key="big",
            value="this is way too large for the limit",
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is False
        assert "exceeds limit" in result.reason


# ---------------------------------------------------------------------------
# APEP-261: Read authorisation
# ---------------------------------------------------------------------------


class TestReadAuthorisation:
    """APEP-261: Read access control."""

    async def test_read_allowed_reader(self, mock_mongodb) -> None:
        await _insert_policy(mock_mongodb, store_pattern="test_store")
        req = MemoryAccessRequest(
            session_id="sess-1",
            agent_id="agent-reader",
            store_name="test_store",
            operation=MemoryOperation.READ,
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is True

    async def test_read_disallowed_reader(self, mock_mongodb) -> None:
        await _insert_policy(
            mock_mongodb,
            store_pattern="test_store",
            allowed_readers=["admin-*"],
        )
        req = MemoryAccessRequest(
            session_id="sess-1",
            agent_id="agent-reader",
            store_name="test_store",
            operation=MemoryOperation.READ,
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is False
        assert "not an allowed reader" in result.reason


# ---------------------------------------------------------------------------
# APEP-263: Read with max_age retention
# ---------------------------------------------------------------------------


class TestReadRetention:
    """APEP-263: Lazy retention enforcement at read time."""

    async def test_read_purges_expired_entries(self, mock_mongodb) -> None:
        await _insert_policy(
            mock_mongodb,
            store_pattern="test_store",
            max_age_seconds=60,
        )

        # Insert old entries directly
        old_time = datetime.now(UTC) - timedelta(seconds=120)
        for i in range(3):
            await mock_mongodb[db_module.MEMORY_ENTRIES].insert_one(
                {
                    "entry_id": str(uuid4()),
                    "session_id": "sess-purge",
                    "agent_id": "agent-writer",
                    "store_name": "test_store",
                    "key": f"old-key-{i}",
                    "created_at": old_time,
                }
            )

        # Insert a fresh entry
        await mock_mongodb[db_module.MEMORY_ENTRIES].insert_one(
            {
                "entry_id": str(uuid4()),
                "session_id": "sess-purge",
                "agent_id": "agent-writer",
                "store_name": "test_store",
                "key": "fresh-key",
                "created_at": datetime.now(UTC),
            }
        )

        req = MemoryAccessRequest(
            session_id="sess-purge",
            agent_id="agent-reader",
            store_name="test_store",
            operation=MemoryOperation.READ,
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is True
        assert len(result.purged_keys) == 3
        assert "old-key-0" in result.purged_keys
        # Only the fresh entry should remain
        assert result.entry_count == 1

    async def test_read_no_purge_when_no_max_age(self, mock_mongodb) -> None:
        await _insert_policy(
            mock_mongodb,
            store_pattern="test_store",
            max_age_seconds=None,
        )

        old_time = datetime.now(UTC) - timedelta(seconds=9999)
        await mock_mongodb[db_module.MEMORY_ENTRIES].insert_one(
            {
                "entry_id": str(uuid4()),
                "session_id": "sess-no-purge",
                "agent_id": "agent-writer",
                "store_name": "test_store",
                "key": "ancient-key",
                "created_at": old_time,
            }
        )

        req = MemoryAccessRequest(
            session_id="sess-no-purge",
            agent_id="agent-reader",
            store_name="test_store",
            operation=MemoryOperation.READ,
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is True
        assert len(result.purged_keys) == 0
        assert result.entry_count == 1


# ---------------------------------------------------------------------------
# APEP-261: Delete authorisation
# ---------------------------------------------------------------------------


class TestDeleteAuthorisation:
    """APEP-261: Delete requires writer permissions."""

    async def test_delete_requires_writer(self, mock_mongodb) -> None:
        await _insert_policy(
            mock_mongodb,
            store_pattern="test_store",
            allowed_writers=["admin-*"],
            allowed_readers=["agent-*"],
        )
        req = MemoryAccessRequest(
            session_id="sess-1",
            agent_id="agent-reader",
            store_name="test_store",
            operation=MemoryOperation.DELETE,
            key="some-key",
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is False
        assert "not an allowed writer" in result.reason

    async def test_delete_allowed_for_writer(self, mock_mongodb) -> None:
        await _insert_policy(
            mock_mongodb,
            store_pattern="test_store",
            allowed_writers=["admin-*"],
        )
        req = MemoryAccessRequest(
            session_id="sess-1",
            agent_id="admin-user",
            store_name="test_store",
            operation=MemoryOperation.DELETE,
            key="some-key",
        )
        result = await memory_access_gate.evaluate(req)
        assert result.allowed is True
