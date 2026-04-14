"""Adversarial and integration tests for Sprint 36 — APEP-285.g.

Tests hash-chained context against:
- Reordering attacks (swapping sequence numbers)
- Insertion attacks (injecting entries mid-chain)
- Deletion attacks (removing entries from chain)
- Content modification (changing content_hash after insertion)
- Previous hash manipulation (breaking chain links)
"""

import pytest

from app.db import mongodb as db_module
from app.services.hash_chained_context import GENESIS_HASH, hash_chained_context


@pytest.mark.asyncio
async def test_adversarial_content_modification(mock_mongodb):
    """Modifying content_hash of an entry should break verification."""
    for i in range(5):
        await hash_chained_context.append(
            session_id="adv-1",
            content=f"Entry {i}",
        )

    # Tamper with entry 2's content_hash
    db = db_module.get_database()
    await db[db_module.HASH_CHAINED_CONTEXT].update_one(
        {"session_id": "adv-1", "sequence_number": 2},
        {"$set": {"content_hash": "0" * 64}},
    )

    result = await hash_chained_context.verify_chain("adv-1")
    assert result.valid is False
    assert result.first_tampered_sequence == 2


@pytest.mark.asyncio
async def test_adversarial_previous_hash_manipulation(mock_mongodb):
    """Changing previous_hash should break chain verification."""
    for i in range(3):
        await hash_chained_context.append(
            session_id="adv-2",
            content=f"Entry {i}",
        )

    db = db_module.get_database()
    await db[db_module.HASH_CHAINED_CONTEXT].update_one(
        {"session_id": "adv-2", "sequence_number": 1},
        {"$set": {"previous_hash": "deadbeef" * 8}},
    )

    result = await hash_chained_context.verify_chain("adv-2")
    assert result.valid is False
    assert result.first_tampered_sequence == 1


@pytest.mark.asyncio
async def test_adversarial_deletion_attack(mock_mongodb):
    """Deleting an entry mid-chain should break verification."""
    for i in range(5):
        await hash_chained_context.append(
            session_id="adv-3",
            content=f"Entry {i}",
        )

    # Delete entry at sequence 2
    db = db_module.get_database()
    await db[db_module.HASH_CHAINED_CONTEXT].delete_one(
        {"session_id": "adv-3", "sequence_number": 2}
    )

    result = await hash_chained_context.verify_chain("adv-3")
    # After deletion, sequence 3 will have previous_hash pointing to
    # sequence 2's chain_hash, but sequence 2 no longer exists.
    # The chain walker will see a gap: 0,1,3,4 — sequence 3's
    # previous_hash won't match sequence 1's chain_hash.
    assert result.valid is False


@pytest.mark.asyncio
async def test_adversarial_insertion_attack(mock_mongodb):
    """Inserting an entry mid-chain should break verification."""
    for i in range(3):
        await hash_chained_context.append(
            session_id="adv-4",
            content=f"Entry {i}",
        )

    # Insert a forged entry between sequence 0 and 1
    from app.services.hash_chained_context import HashChainedContextManager
    from uuid import uuid4

    mgr = HashChainedContextManager()
    db = db_module.get_database()

    # Get entry 0 to forge the link
    entry0 = await db[db_module.HASH_CHAINED_CONTEXT].find_one(
        {"session_id": "adv-4", "sequence_number": 0}
    )
    forged_content_hash = mgr.compute_content_hash("Forged entry")
    forged_chain_hash = mgr.compute_chain_hash(entry0["chain_hash"], forged_content_hash)

    # Update sequence numbers to make room
    await db[db_module.HASH_CHAINED_CONTEXT].update_many(
        {"session_id": "adv-4", "sequence_number": {"$gte": 1}},
        {"$inc": {"sequence_number": 1}},
    )

    # Insert forged entry
    await db[db_module.HASH_CHAINED_CONTEXT].insert_one({
        "entry_id": str(uuid4()),
        "session_id": "adv-4",
        "sequence_number": 1,
        "content_hash": forged_content_hash,
        "previous_hash": entry0["chain_hash"],
        "chain_hash": forged_chain_hash,
        "source": "forged",
        "tenant_id": "default",
    })

    result = await hash_chained_context.verify_chain("adv-4")
    # The forged entry itself may verify, but the next entry's
    # previous_hash won't match the forged entry's chain_hash
    assert result.valid is False


@pytest.mark.asyncio
async def test_adversarial_genesis_tampering(mock_mongodb):
    """Modifying the genesis entry's previous_hash should fail."""
    await hash_chained_context.append(
        session_id="adv-5",
        content="Genesis entry",
    )

    db = db_module.get_database()
    await db[db_module.HASH_CHAINED_CONTEXT].update_one(
        {"session_id": "adv-5", "sequence_number": 0},
        {"$set": {"previous_hash": "not_genesis"}},
    )

    result = await hash_chained_context.verify_chain("adv-5")
    assert result.valid is False
    assert result.first_tampered_sequence == 0


@pytest.mark.asyncio
async def test_adversarial_chain_hash_swap(mock_mongodb):
    """Swapping chain_hash between entries should fail verification."""
    for i in range(3):
        await hash_chained_context.append(
            session_id="adv-6",
            content=f"Entry {i}",
        )

    db = db_module.get_database()
    entry1 = await db[db_module.HASH_CHAINED_CONTEXT].find_one(
        {"session_id": "adv-6", "sequence_number": 1}
    )
    entry2 = await db[db_module.HASH_CHAINED_CONTEXT].find_one(
        {"session_id": "adv-6", "sequence_number": 2}
    )

    # Swap their chain_hashes
    await db[db_module.HASH_CHAINED_CONTEXT].update_one(
        {"session_id": "adv-6", "sequence_number": 1},
        {"$set": {"chain_hash": entry2["chain_hash"]}},
    )
    await db[db_module.HASH_CHAINED_CONTEXT].update_one(
        {"session_id": "adv-6", "sequence_number": 2},
        {"$set": {"chain_hash": entry1["chain_hash"]}},
    )

    result = await hash_chained_context.verify_chain("adv-6")
    assert result.valid is False


@pytest.mark.asyncio
async def test_valid_long_chain(mock_mongodb):
    """A long valid chain should pass verification."""
    for i in range(50):
        await hash_chained_context.append(
            session_id="adv-7",
            content=f"Long chain entry {i}",
        )

    result = await hash_chained_context.verify_chain("adv-7")
    assert result.valid is True
    assert result.total_entries == 50
    assert result.verified_entries == 50


@pytest.mark.asyncio
async def test_adversarial_replay_entire_chain(mock_mongodb):
    """Replaying a valid chain under a different session should not affect the original."""
    for i in range(3):
        await hash_chained_context.append(
            session_id="adv-8-original",
            content=f"Entry {i}",
        )

    # Verify original is valid
    result_orig = await hash_chained_context.verify_chain("adv-8-original")
    assert result_orig.valid is True

    # Copy entries to a different session (replay attack)
    db = db_module.get_database()
    cursor = db[db_module.HASH_CHAINED_CONTEXT].find(
        {"session_id": "adv-8-original"}
    )
    async for doc in cursor:
        doc["session_id"] = "adv-8-replay"
        doc["_id"] = None  # let mongo generate new _id
        del doc["_id"]
        from uuid import uuid4
        doc["entry_id"] = str(uuid4())
        await db[db_module.HASH_CHAINED_CONTEXT].insert_one(doc)

    # Both chains should still be independently valid
    result_replay = await hash_chained_context.verify_chain("adv-8-replay")
    assert result_replay.valid is True

    # Original should still be valid
    result_orig2 = await hash_chained_context.verify_chain("adv-8-original")
    assert result_orig2.valid is True
