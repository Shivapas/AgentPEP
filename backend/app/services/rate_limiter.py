"""Rate Limiter — sliding window, fixed window, and global per-tenant rate limits.

APEP-090: Sliding window rate limiter per agent_role per tool per time window in MongoDB.
APEP-091: Fixed window rate limiter as alternative; configurable per rule.
APEP-092: Global rate limit — per-tenant total decisions/second ceiling.
"""

import logging
import time
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.db import mongodb as db_module
from app.models.policy import RateLimit, RateLimitType

logger = logging.getLogger(__name__)


class RateLimitResult:
    """Result of a rate limit check."""

    __slots__ = ("allowed", "reason", "current_count", "limit")

    def __init__(
        self,
        allowed: bool,
        reason: str = "",
        current_count: int = 0,
        limit: int = 0,
    ):
        self.allowed = allowed
        self.reason = reason
        self.current_count = current_count
        self.limit = limit


class RateLimiter:
    """Enforces per-role per-tool and global rate limits using MongoDB counters.

    Two algorithms are supported:
    - SLIDING_WINDOW (APEP-090): counts invocations within a rolling time window.
      Uses per-invocation timestamp documents and counts within [now - window, now].
    - FIXED_WINDOW (APEP-091): counts invocations within discrete time buckets.
      Uses a single counter document per (key, bucket) pair.
    """

    # --- Sliding Window (APEP-090) ---

    async def check_sliding_window(
        self,
        agent_role: str,
        tool_name: str,
        rate_limit: RateLimit,
    ) -> RateLimitResult:
        """Check and increment the sliding window rate limit counter.

        Each invocation inserts a timestamp document. The count of documents
        within [now - window_s, now] determines whether the limit is exceeded.
        """
        db = db_module.get_database()
        collection = db[db_module.RATE_LIMIT_COUNTERS]

        key = f"sliding:{agent_role}:{tool_name}"
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=rate_limit.window_s)

        # Count existing invocations within the window
        count = await collection.count_documents(
            {"key": key, "window_start": {"$gte": window_start}},
        )

        if count >= rate_limit.count:
            return RateLimitResult(
                allowed=False,
                reason=(
                    f"Sliding window rate limit exceeded for role={agent_role} "
                    f"tool={tool_name}: {count}/{rate_limit.count} in {rate_limit.window_s}s"
                ),
                current_count=count,
                limit=rate_limit.count,
            )

        # Record this invocation
        await collection.insert_one(
            {
                "key": key,
                "window_start": now,
                "expires_at": now + timedelta(seconds=rate_limit.window_s),
            }
        )

        return RateLimitResult(
            allowed=True,
            current_count=count + 1,
            limit=rate_limit.count,
        )

    # --- Fixed Window (APEP-091) ---

    async def check_fixed_window(
        self,
        agent_role: str,
        tool_name: str,
        rate_limit: RateLimit,
    ) -> RateLimitResult:
        """Check and increment the fixed window rate limit counter.

        Uses a single counter document per discrete time bucket. The bucket
        is determined by floor(now / window_s) * window_s.
        """
        db = db_module.get_database()
        collection = db[db_module.RATE_LIMIT_COUNTERS]

        now = datetime.now(timezone.utc)
        epoch_s = int(now.timestamp())
        bucket_start_s = (epoch_s // rate_limit.window_s) * rate_limit.window_s
        bucket_start = datetime.fromtimestamp(bucket_start_s, tz=timezone.utc)
        bucket_expires = bucket_start + timedelta(seconds=rate_limit.window_s)

        key = f"fixed:{agent_role}:{tool_name}"

        # Atomic upsert + increment
        result = await collection.find_one_and_update(
            {"key": key, "window_start": bucket_start},
            {
                "$inc": {"count": 1},
                "$setOnInsert": {"expires_at": bucket_expires},
            },
            upsert=True,
            return_document=True,
        )

        current_count = result.get("count", 1) if result else 1

        if current_count > rate_limit.count:
            return RateLimitResult(
                allowed=False,
                reason=(
                    f"Fixed window rate limit exceeded for role={agent_role} "
                    f"tool={tool_name}: {current_count}/{rate_limit.count} "
                    f"in {rate_limit.window_s}s window"
                ),
                current_count=current_count,
                limit=rate_limit.count,
            )

        return RateLimitResult(
            allowed=True,
            current_count=current_count,
            limit=rate_limit.count,
        )

    # --- Global Per-Tenant Rate Limit (APEP-092) ---

    async def check_global_rate_limit(
        self,
        tenant_id: str,
    ) -> RateLimitResult:
        """Check the global per-tenant decisions/second ceiling.

        Uses a fixed 1-second window keyed by tenant_id.
        """
        if not settings.global_rate_limit_enabled:
            return RateLimitResult(allowed=True)

        db = db_module.get_database()
        collection = db[db_module.RATE_LIMIT_COUNTERS]

        now = datetime.now(timezone.utc)
        epoch_s = int(now.timestamp())
        bucket_start = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
        bucket_expires = bucket_start + timedelta(seconds=2)  # expire after 2s for safety

        key = f"global:{tenant_id}"
        ceiling = settings.global_rate_limit_per_second

        result = await collection.find_one_and_update(
            {"key": key, "window_start": bucket_start},
            {
                "$inc": {"count": 1},
                "$setOnInsert": {"expires_at": bucket_expires},
            },
            upsert=True,
            return_document=True,
        )

        current_count = result.get("count", 1) if result else 1

        if current_count > ceiling:
            return RateLimitResult(
                allowed=False,
                reason=(
                    f"Global rate limit exceeded for tenant={tenant_id}: "
                    f"{current_count}/{ceiling} decisions/second"
                ),
                current_count=current_count,
                limit=ceiling,
            )

        return RateLimitResult(
            allowed=True,
            current_count=current_count,
            limit=ceiling,
        )

    # --- Unified Check ---

    async def check(
        self,
        agent_role: str,
        tool_name: str,
        rate_limit: RateLimit,
    ) -> RateLimitResult:
        """Check rate limit using the algorithm configured on the rule."""
        if rate_limit.limiter_type == RateLimitType.SLIDING_WINDOW:
            return await self.check_sliding_window(agent_role, tool_name, rate_limit)
        elif rate_limit.limiter_type == RateLimitType.FIXED_WINDOW:
            return await self.check_fixed_window(agent_role, tool_name, rate_limit)
        else:
            logger.warning("Unknown rate limit type: %s", rate_limit.limiter_type)
            return RateLimitResult(allowed=True)


# Module-level singleton
rate_limiter = RateLimiter()
