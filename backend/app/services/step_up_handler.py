"""StepUpHandler — manages STEP_UP authentication challenges.

Sprint 36 — APEP-288: When a policy rule requires additional authentication
factors (e.g., MFA, biometric, manager approval), the policy evaluator
returns a STEP_UP decision with a challenge. The caller must satisfy
all required factors before the tool call is authorized.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.db import mongodb as db_module
from app.models.sprint36 import StepUpChallenge, StepUpChallengeStatus

logger = logging.getLogger(__name__)

# Default challenge TTL
DEFAULT_CHALLENGE_TTL_S = 300


class StepUpHandler:
    """Manage STEP_UP authentication challenges."""

    def __init__(self, challenge_ttl_s: int = DEFAULT_CHALLENGE_TTL_S) -> None:
        self._challenge_ttl_s = challenge_ttl_s

    async def create_challenge(
        self,
        request_id: UUID,
        session_id: str,
        agent_id: str,
        required_factors: list[str],
        tenant_id: str = "default",
    ) -> StepUpChallenge:
        """Create a new STEP_UP authentication challenge.

        Args:
            request_id: Original tool call request ID.
            session_id: Session identifier.
            agent_id: Agent requesting the tool call.
            required_factors: Auth factors that must be verified.
            tenant_id: Tenant identifier.

        Returns:
            The created StepUpChallenge.
        """
        now = datetime.now(UTC)
        challenge = StepUpChallenge(
            request_id=request_id,
            session_id=session_id,
            agent_id=agent_id,
            required_factors=required_factors,
            status=StepUpChallengeStatus.PENDING,
            expires_at=now + timedelta(seconds=self._challenge_ttl_s),
            tenant_id=tenant_id,
            created_at=now,
        )

        db = db_module.get_database()
        await db[db_module.STEP_UP_CHALLENGES].insert_one(
            challenge.model_dump(mode="json")
        )

        logger.info(
            "step_up_challenge_created challenge_id=%s session_id=%s factors=%s",
            challenge.challenge_id,
            session_id,
            required_factors,
        )
        return challenge

    async def verify_factor(
        self,
        challenge_id: UUID,
        factor: str,
    ) -> StepUpChallenge | None:
        """Verify a single authentication factor on a challenge.

        Args:
            challenge_id: Challenge to verify against.
            factor: The factor being verified (e.g., 'mfa').

        Returns:
            Updated challenge, or None if not found.
        """
        db = db_module.get_database()
        collection = db[db_module.STEP_UP_CHALLENGES]

        doc = await collection.find_one({"challenge_id": str(challenge_id)})
        if not doc:
            logger.warning("step_up_challenge_not_found challenge_id=%s", challenge_id)
            return None

        challenge = StepUpChallenge(**doc)

        # Check expiry
        now = datetime.now(UTC)
        expires_at = challenge.expires_at
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)

        if now > expires_at:
            await collection.update_one(
                {"challenge_id": str(challenge_id)},
                {"$set": {"status": StepUpChallengeStatus.EXPIRED.value}},
            )
            challenge.status = StepUpChallengeStatus.EXPIRED
            return challenge

        if challenge.status != StepUpChallengeStatus.PENDING:
            return challenge

        # Verify the factor
        if factor not in challenge.required_factors:
            logger.warning(
                "step_up_invalid_factor challenge_id=%s factor=%s",
                challenge_id,
                factor,
            )
            return challenge

        if factor in challenge.verified_factors:
            return challenge

        verified = list(challenge.verified_factors) + [factor]

        # Check if all factors are now verified
        all_verified = set(verified) >= set(challenge.required_factors)
        new_status = (
            StepUpChallengeStatus.VERIFIED if all_verified
            else StepUpChallengeStatus.PENDING
        )

        await collection.update_one(
            {"challenge_id": str(challenge_id)},
            {
                "$set": {
                    "verified_factors": verified,
                    "status": new_status.value,
                }
            },
        )

        challenge.verified_factors = verified
        challenge.status = new_status

        logger.info(
            "step_up_factor_verified challenge_id=%s factor=%s all_verified=%s",
            challenge_id,
            factor,
            all_verified,
        )
        return challenge

    async def get_challenge(
        self,
        challenge_id: UUID,
    ) -> StepUpChallenge | None:
        """Get a challenge by ID."""
        db = db_module.get_database()
        doc = await db[db_module.STEP_UP_CHALLENGES].find_one(
            {"challenge_id": str(challenge_id)}
        )
        if doc:
            return StepUpChallenge(**doc)
        return None

    async def is_verified(self, challenge_id: UUID) -> bool:
        """Check if a challenge has been fully verified."""
        challenge = await self.get_challenge(challenge_id)
        if not challenge:
            return False
        return challenge.status == StepUpChallengeStatus.VERIFIED

    async def fail_challenge(self, challenge_id: UUID) -> StepUpChallenge | None:
        """Mark a challenge as failed."""
        db = db_module.get_database()
        collection = db[db_module.STEP_UP_CHALLENGES]

        result = await collection.find_one_and_update(
            {"challenge_id": str(challenge_id)},
            {"$set": {"status": StepUpChallengeStatus.FAILED.value}},
            return_document=True,
        )
        if result:
            return StepUpChallenge(**result)
        return None


# Module-level singleton
step_up_handler = StepUpHandler()
