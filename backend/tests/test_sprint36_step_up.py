"""Unit tests for STEP_UP challenge handler (Sprint 36 — APEP-288)."""

from uuid import uuid4

import pytest

from app.models.sprint36 import StepUpChallengeStatus
from app.services.step_up_handler import StepUpHandler


@pytest.mark.asyncio
async def test_create_challenge(mock_mongodb):
    """Creating a challenge should return a challenge with correct fields."""
    handler = StepUpHandler()
    challenge = await handler.create_challenge(
        request_id=uuid4(),
        session_id="session-1",
        agent_id="agent-1",
        required_factors=["mfa", "manager_approval"],
    )
    assert challenge.session_id == "session-1"
    assert challenge.required_factors == ["mfa", "manager_approval"]
    assert challenge.verified_factors == []
    assert challenge.status == StepUpChallengeStatus.PENDING


@pytest.mark.asyncio
async def test_verify_single_factor(mock_mongodb):
    """Verifying one factor should add it to verified_factors."""
    handler = StepUpHandler()
    challenge = await handler.create_challenge(
        request_id=uuid4(),
        session_id="session-2",
        agent_id="agent-1",
        required_factors=["mfa", "biometric"],
    )
    updated = await handler.verify_factor(challenge.challenge_id, "mfa")
    assert updated is not None
    assert "mfa" in updated.verified_factors
    assert updated.status == StepUpChallengeStatus.PENDING


@pytest.mark.asyncio
async def test_verify_all_factors_completes(mock_mongodb):
    """Verifying all required factors should set status to VERIFIED."""
    handler = StepUpHandler()
    challenge = await handler.create_challenge(
        request_id=uuid4(),
        session_id="session-3",
        agent_id="agent-1",
        required_factors=["mfa"],
    )
    updated = await handler.verify_factor(challenge.challenge_id, "mfa")
    assert updated is not None
    assert updated.status == StepUpChallengeStatus.VERIFIED


@pytest.mark.asyncio
async def test_verify_multi_factor_completion(mock_mongodb):
    """Multi-factor challenge requires all factors verified."""
    handler = StepUpHandler()
    challenge = await handler.create_challenge(
        request_id=uuid4(),
        session_id="session-4",
        agent_id="agent-1",
        required_factors=["mfa", "biometric"],
    )
    # Verify first factor
    after_first = await handler.verify_factor(challenge.challenge_id, "mfa")
    assert after_first.status == StepUpChallengeStatus.PENDING

    # Verify second factor
    after_second = await handler.verify_factor(challenge.challenge_id, "biometric")
    assert after_second.status == StepUpChallengeStatus.VERIFIED


@pytest.mark.asyncio
async def test_verify_invalid_factor(mock_mongodb):
    """Verifying a factor not in required_factors should not change state."""
    handler = StepUpHandler()
    challenge = await handler.create_challenge(
        request_id=uuid4(),
        session_id="session-5",
        agent_id="agent-1",
        required_factors=["mfa"],
    )
    updated = await handler.verify_factor(challenge.challenge_id, "biometric")
    assert updated is not None
    assert "biometric" not in updated.verified_factors
    assert updated.status == StepUpChallengeStatus.PENDING


@pytest.mark.asyncio
async def test_verify_nonexistent_challenge(mock_mongodb):
    """Verifying a nonexistent challenge should return None."""
    handler = StepUpHandler()
    result = await handler.verify_factor(uuid4(), "mfa")
    assert result is None


@pytest.mark.asyncio
async def test_get_challenge(mock_mongodb):
    """get_challenge should retrieve a challenge by ID."""
    handler = StepUpHandler()
    challenge = await handler.create_challenge(
        request_id=uuid4(),
        session_id="session-6",
        agent_id="agent-1",
        required_factors=["mfa"],
    )
    found = await handler.get_challenge(challenge.challenge_id)
    assert found is not None
    assert found.challenge_id == challenge.challenge_id


@pytest.mark.asyncio
async def test_is_verified(mock_mongodb):
    """is_verified should return True only when all factors are verified."""
    handler = StepUpHandler()
    challenge = await handler.create_challenge(
        request_id=uuid4(),
        session_id="session-7",
        agent_id="agent-1",
        required_factors=["mfa"],
    )
    assert await handler.is_verified(challenge.challenge_id) is False

    await handler.verify_factor(challenge.challenge_id, "mfa")
    assert await handler.is_verified(challenge.challenge_id) is True


@pytest.mark.asyncio
async def test_fail_challenge(mock_mongodb):
    """fail_challenge should set status to FAILED."""
    handler = StepUpHandler()
    challenge = await handler.create_challenge(
        request_id=uuid4(),
        session_id="session-8",
        agent_id="agent-1",
        required_factors=["mfa"],
    )
    failed = await handler.fail_challenge(challenge.challenge_id)
    assert failed is not None
    assert failed.status == StepUpChallengeStatus.FAILED


@pytest.mark.asyncio
async def test_duplicate_factor_verification(mock_mongodb):
    """Verifying the same factor twice should be idempotent."""
    handler = StepUpHandler()
    challenge = await handler.create_challenge(
        request_id=uuid4(),
        session_id="session-9",
        agent_id="agent-1",
        required_factors=["mfa", "biometric"],
    )
    await handler.verify_factor(challenge.challenge_id, "mfa")
    updated = await handler.verify_factor(challenge.challenge_id, "mfa")
    assert updated is not None
    assert updated.verified_factors.count("mfa") == 1
    assert updated.status == StepUpChallengeStatus.PENDING
