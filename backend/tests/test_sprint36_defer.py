"""Unit tests for DEFER decision handler (Sprint 36 — APEP-287)."""

from uuid import uuid4

import pytest

from app.models.sprint36 import DeferCondition
from app.services.defer_handler import defer_handler


@pytest.mark.asyncio
async def test_create_deferral(mock_mongodb):
    """Creating a deferral should return a record with correct fields."""
    request_id = uuid4()
    record = await defer_handler.create_deferral(
        request_id=request_id,
        session_id="session-1",
        agent_id="agent-1",
        tool_name="file.write",
        condition=DeferCondition.PENDING_REVIEW,
        reason="Trust degraded",
        timeout_s=120,
    )
    assert record.request_id == request_id
    assert record.session_id == "session-1"
    assert record.tool_name == "file.write"
    assert record.condition == DeferCondition.PENDING_REVIEW
    assert record.timeout_s == 120
    assert record.resolved is False
    assert record.resolution is None


@pytest.mark.asyncio
async def test_resolve_deferral(mock_mongodb):
    """Resolving a deferral should set resolved=True and record the resolution."""
    request_id = uuid4()
    record = await defer_handler.create_deferral(
        request_id=request_id,
        session_id="session-2",
        agent_id="agent-1",
        tool_name="file.write",
    )
    resolved = await defer_handler.resolve(record.defer_id, "ALLOW")
    assert resolved is not None
    assert resolved.resolved is True
    assert resolved.resolution == "ALLOW"


@pytest.mark.asyncio
async def test_resolve_nonexistent(mock_mongodb):
    """Resolving a nonexistent deferral should return None."""
    result = await defer_handler.resolve(uuid4(), "DENY")
    assert result is None


@pytest.mark.asyncio
async def test_get_pending(mock_mongodb):
    """get_pending should return only unresolved deferrals."""
    for i in range(3):
        await defer_handler.create_deferral(
            request_id=uuid4(),
            session_id="session-3",
            agent_id="agent-1",
            tool_name=f"tool-{i}",
        )

    # Resolve one
    pending = await defer_handler.get_pending(session_id="session-3")
    assert len(pending) == 3

    await defer_handler.resolve(pending[0].defer_id, "DENY")
    pending_after = await defer_handler.get_pending(session_id="session-3")
    assert len(pending_after) == 2


@pytest.mark.asyncio
async def test_get_by_id(mock_mongodb):
    """get_by_id should retrieve a specific defer record."""
    record = await defer_handler.create_deferral(
        request_id=uuid4(),
        session_id="session-4",
        agent_id="agent-1",
        tool_name="file.read",
    )
    found = await defer_handler.get_by_id(record.defer_id)
    assert found is not None
    assert found.defer_id == record.defer_id


@pytest.mark.asyncio
async def test_get_by_id_nonexistent(mock_mongodb):
    """get_by_id should return None for nonexistent ID."""
    result = await defer_handler.get_by_id(uuid4())
    assert result is None


@pytest.mark.asyncio
async def test_different_conditions(mock_mongodb):
    """Deferrals can be created with different conditions."""
    for condition in DeferCondition:
        record = await defer_handler.create_deferral(
            request_id=uuid4(),
            session_id=f"session-cond-{condition.value}",
            agent_id="agent-1",
            tool_name="test.tool",
            condition=condition,
        )
        assert record.condition == condition


@pytest.mark.asyncio
async def test_tenant_isolation_in_pending(mock_mongodb):
    """get_pending should filter by tenant_id."""
    await defer_handler.create_deferral(
        request_id=uuid4(),
        session_id="session-5",
        agent_id="agent-1",
        tool_name="tool-a",
        tenant_id="tenant-a",
    )
    await defer_handler.create_deferral(
        request_id=uuid4(),
        session_id="session-6",
        agent_id="agent-1",
        tool_name="tool-b",
        tenant_id="tenant-b",
    )

    pending_a = await defer_handler.get_pending(tenant_id="tenant-a")
    pending_b = await defer_handler.get_pending(tenant_id="tenant-b")
    assert len(pending_a) == 1
    assert len(pending_b) == 1
