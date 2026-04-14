"""Unit tests for HashChainedContext (Sprint 36 — APEP-285)."""

import pytest

from app.services.hash_chained_context import (
    GENESIS_HASH,
    HashChainedContextManager,
    hash_chained_context,
)


@pytest.mark.asyncio
async def test_append_first_entry(mock_mongodb):
    """First entry in a chain uses GENESIS_HASH as previous_hash."""
    entry = await hash_chained_context.append(
        session_id="test-session-1",
        content="Hello, world!",
        source="user_prompt",
        agent_id="agent-1",
    )
    assert entry.session_id == "test-session-1"
    assert entry.sequence_number == 0
    assert entry.previous_hash == GENESIS_HASH
    assert entry.chain_hash != ""
    assert entry.content_hash != ""
    assert entry.source == "user_prompt"
    assert entry.agent_id == "agent-1"


@pytest.mark.asyncio
async def test_append_second_entry_links_to_first(mock_mongodb):
    """Second entry's previous_hash should be the first entry's chain_hash."""
    entry1 = await hash_chained_context.append(
        session_id="test-session-2",
        content="First entry",
    )
    entry2 = await hash_chained_context.append(
        session_id="test-session-2",
        content="Second entry",
    )
    assert entry2.sequence_number == 1
    assert entry2.previous_hash == entry1.chain_hash


@pytest.mark.asyncio
async def test_chain_hash_computation(mock_mongodb):
    """chain_hash should be SHA-256 of (previous_hash || content_hash)."""
    mgr = HashChainedContextManager()

    content = "Test content"
    content_hash = mgr.compute_content_hash(content)
    expected_chain_hash = mgr.compute_chain_hash(GENESIS_HASH, content_hash)

    entry = await hash_chained_context.append(
        session_id="test-session-3",
        content=content,
    )
    assert entry.chain_hash == expected_chain_hash


@pytest.mark.asyncio
async def test_verify_chain_valid(mock_mongodb):
    """Verify a valid chain returns valid=True."""
    for i in range(5):
        await hash_chained_context.append(
            session_id="test-session-4",
            content=f"Entry {i}",
        )

    result = await hash_chained_context.verify_chain("test-session-4")
    assert result.valid is True
    assert result.total_entries == 5
    assert result.verified_entries == 5


@pytest.mark.asyncio
async def test_verify_chain_detects_tampering(mock_mongodb):
    """Verify chain detects tampered chain_hash."""
    for i in range(3):
        await hash_chained_context.append(
            session_id="test-session-5",
            content=f"Entry {i}",
        )

    # Tamper with the second entry's chain_hash
    from app.db import mongodb as db_module

    db = db_module.get_database()
    await db[db_module.HASH_CHAINED_CONTEXT].update_one(
        {"session_id": "test-session-5", "sequence_number": 1},
        {"$set": {"chain_hash": "tampered_hash"}},
    )

    result = await hash_chained_context.verify_chain("test-session-5")
    assert result.valid is False
    assert result.first_tampered_sequence == 1


@pytest.mark.asyncio
async def test_verify_chain_empty_session(mock_mongodb):
    """Verifying an empty session returns valid with 0 entries."""
    result = await hash_chained_context.verify_chain("nonexistent-session")
    assert result.valid is True
    assert result.total_entries == 0


@pytest.mark.asyncio
async def test_get_chain(mock_mongodb):
    """get_chain returns entries ordered by sequence_number."""
    for i in range(3):
        await hash_chained_context.append(
            session_id="test-session-6",
            content=f"Entry {i}",
        )

    chain = await hash_chained_context.get_chain("test-session-6")
    assert len(chain) == 3
    assert chain[0].sequence_number == 0
    assert chain[1].sequence_number == 1
    assert chain[2].sequence_number == 2


@pytest.mark.asyncio
async def test_get_latest(mock_mongodb):
    """get_latest returns the most recent entry."""
    for i in range(3):
        await hash_chained_context.append(
            session_id="test-session-7",
            content=f"Entry {i}",
        )

    latest = await hash_chained_context.get_latest("test-session-7")
    assert latest is not None
    assert latest.sequence_number == 2


@pytest.mark.asyncio
async def test_get_latest_empty(mock_mongodb):
    """get_latest returns None for empty session."""
    latest = await hash_chained_context.get_latest("nonexistent")
    assert latest is None


@pytest.mark.asyncio
async def test_multi_tenant_isolation(mock_mongodb):
    """Entries are isolated by tenant_id when filtering."""
    await hash_chained_context.append(
        session_id="shared-session",
        content="Tenant A data",
        tenant_id="tenant-a",
    )
    await hash_chained_context.append(
        session_id="shared-session",
        content="Tenant B data",
        tenant_id="tenant-b",
    )

    chain_a = await hash_chained_context.get_chain(
        "shared-session", tenant_id="tenant-a"
    )
    chain_b = await hash_chained_context.get_chain(
        "shared-session", tenant_id="tenant-b"
    )
    assert len(chain_a) == 1
    assert len(chain_b) == 1


@pytest.mark.asyncio
async def test_content_hash_deterministic():
    """Same content should produce the same hash."""
    mgr = HashChainedContextManager()
    hash1 = mgr.compute_content_hash("test content")
    hash2 = mgr.compute_content_hash("test content")
    assert hash1 == hash2

    hash3 = mgr.compute_content_hash("different content")
    assert hash1 != hash3
