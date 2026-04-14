"""Unit tests for TrustDegradationEngine (Sprint 36 — APEP-286)."""

import pytest

from app.services.trust_degradation_engine import TrustDegradationEngine


@pytest.mark.asyncio
async def test_get_or_create_new_record(mock_mongodb):
    """Creating a new record should start with ceiling=1.0."""
    engine = TrustDegradationEngine()
    record = await engine.get_or_create_record("session-1")
    assert record.session_id == "session-1"
    assert record.current_ceiling == 1.0
    assert record.total_degradation == 0.0
    assert record.locked is False


@pytest.mark.asyncio
async def test_get_or_create_returns_existing(mock_mongodb):
    """Second call should return the same record."""
    engine = TrustDegradationEngine()
    record1 = await engine.get_or_create_record("session-2")
    record2 = await engine.get_or_create_record("session-2")
    assert record1.session_id == record2.session_id
    assert record1.current_ceiling == record2.current_ceiling


@pytest.mark.asyncio
async def test_record_untrusted_tool_call_degrades(mock_mongodb):
    """An UNTRUSTED tool call should degrade the trust ceiling."""
    engine = TrustDegradationEngine()
    record = await engine.record_event(
        session_id="session-3",
        interaction_type="TOOL_CALL",
        taint_level="UNTRUSTED",
        tool_name="file.read",
    )
    assert record.current_ceiling < 1.0
    assert record.degradation_count == 1
    assert record.last_degradation_reason != ""


@pytest.mark.asyncio
async def test_trusted_tool_call_no_degradation(mock_mongodb):
    """A TRUSTED tool call should not degrade the trust ceiling."""
    engine = TrustDegradationEngine()
    record = await engine.record_event(
        session_id="session-4",
        interaction_type="TOOL_CALL",
        taint_level="TRUSTED",
        tool_name="file.read",
    )
    assert record.current_ceiling == 1.0
    assert record.degradation_count == 0


@pytest.mark.asyncio
async def test_injection_detection_heavy_degradation(mock_mongodb):
    """Injection detection should cause heavy degradation."""
    engine = TrustDegradationEngine()
    record = await engine.record_event(
        session_id="session-5",
        interaction_type="INJECTION_DETECTED",
    )
    assert record.current_ceiling <= 0.5
    assert record.degradation_count == 1


@pytest.mark.asyncio
async def test_session_locks_at_threshold(mock_mongodb):
    """Session should lock when ceiling drops below lock threshold."""
    engine = TrustDegradationEngine(lock_threshold=0.3)
    # Apply multiple heavy penalties
    await engine.record_event(
        session_id="session-6",
        interaction_type="INJECTION_DETECTED",
    )
    record = await engine.record_event(
        session_id="session-6",
        interaction_type="INJECTION_DETECTED",
    )
    assert record.locked is True


@pytest.mark.asyncio
async def test_locked_session_no_further_degradation(mock_mongodb):
    """Locked session should not degrade further."""
    engine = TrustDegradationEngine(lock_threshold=0.3)
    # Lock the session
    await engine.record_event(
        session_id="session-7",
        interaction_type="INJECTION_DETECTED",
    )
    await engine.record_event(
        session_id="session-7",
        interaction_type="INJECTION_DETECTED",
    )
    locked_record = await engine.get_or_create_record("session-7")
    assert locked_record.locked is True

    # Try another event — should be ignored
    record = await engine.record_event(
        session_id="session-7",
        interaction_type="INJECTION_DETECTED",
    )
    assert record.current_ceiling == locked_record.current_ceiling


@pytest.mark.asyncio
async def test_admin_reset(mock_mongodb):
    """Admin reset should restore trust ceiling."""
    engine = TrustDegradationEngine()
    await engine.record_event(
        session_id="session-8",
        interaction_type="INJECTION_DETECTED",
    )
    degraded = await engine.get_or_create_record("session-8")
    assert degraded.current_ceiling < 1.0

    reset = await engine.admin_reset("session-8")
    assert reset.current_ceiling == 1.0
    assert reset.locked is False


@pytest.mark.asyncio
async def test_get_ceiling(mock_mongodb):
    """get_ceiling should return the current trust ceiling."""
    engine = TrustDegradationEngine()
    ceiling = await engine.get_ceiling("session-9")
    assert ceiling == 1.0

    await engine.record_event(
        session_id="session-9",
        interaction_type="CONTEXT_INJECTION",
        taint_level="UNTRUSTED",
    )
    ceiling = await engine.get_ceiling("session-9")
    assert ceiling < 1.0


@pytest.mark.asyncio
async def test_is_locked(mock_mongodb):
    """is_locked should return lock status."""
    engine = TrustDegradationEngine(lock_threshold=0.3)
    assert await engine.is_locked("session-10") is False

    await engine.record_event(
        session_id="session-10",
        interaction_type="INJECTION_DETECTED",
    )
    await engine.record_event(
        session_id="session-10",
        interaction_type="INJECTION_DETECTED",
    )
    assert await engine.is_locked("session-10") is True


@pytest.mark.asyncio
async def test_cumulative_degradation(mock_mongodb):
    """Multiple events should cumulatively degrade the ceiling."""
    engine = TrustDegradationEngine()
    await engine.record_event(
        session_id="session-11",
        interaction_type="TOOL_CALL",
        taint_level="UNTRUSTED",
    )
    after_first = await engine.get_ceiling("session-11")

    await engine.record_event(
        session_id="session-11",
        interaction_type="DELEGATION_HOP",
    )
    after_second = await engine.get_ceiling("session-11")

    assert after_second < after_first < 1.0


@pytest.mark.asyncio
async def test_tenant_id_stored(mock_mongodb):
    """Record should store the tenant_id."""
    engine = TrustDegradationEngine()
    record = await engine.get_or_create_record("session-12", "my-tenant")
    assert record.tenant_id == "my-tenant"
