"""RedisRateLimiter — Redis-backed sliding window rate limiter.

Sprint 31 — APEP-245: Replaces MongoDB-based rate limiting with Redis
sorted sets for lower latency and atomic operations via Lua scripts.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from app.core.config import settings
from app.models.policy import RateLimit, RateLimitType
from app.services.rate_limiter import RateLimitResult

logger = logging.getLogger(__name__)

# Lua script for atomic sliding window rate limiting.
# Keys[1] = sorted set key
# ARGV[1] = window start timestamp (prune before this)
# ARGV[2] = current timestamp (score for new member)
# ARGV[3] = unique member ID
# ARGV[4] = TTL in seconds for the key
# Returns: current count after add
_SLIDING_WINDOW_LUA = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[3])
local count = redis.call('ZCARD', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[4])
return count
"""

# Lua script for atomic fixed window rate limiting.
# Keys[1] = counter key (includes bucket)
# ARGV[1] = TTL in seconds
# Returns: current count after increment
_FIXED_WINDOW_LUA = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""


class RedisRateLimiter:
    """Redis-backed rate limiter using sorted sets (sliding) and counters (fixed).

    Sliding Window Algorithm:
      Uses a Redis sorted set per (agent_role, tool_name) pair.
      Each invocation adds a member with score = current timestamp.
      Expired entries are pruned atomically via ``ZREMRANGEBYSCORE``.
      The count is obtained via ``ZCARD`` after pruning.
      All operations are atomic via a Lua script.

    Fixed Window Algorithm:
      Uses a Redis string counter per (agent_role, tool_name, bucket) triplet.
      ``INCR`` atomically increments; ``EXPIRE`` sets TTL on first use.
    """

    def __init__(self) -> None:
        self._redis: Any = None
        self._sliding_script: Any = None
        self._fixed_script: Any = None

    async def initialize(self) -> None:
        """Connect to Redis and register Lua scripts."""
        try:
            import redis.asyncio as aioredis

            url = settings.redis_storage_url or settings.redis_url
            self._redis = aioredis.from_url(
                url,
                decode_responses=False,  # Lua scripts work with bytes
                socket_connect_timeout=5,
            )
            await self._redis.ping()

            # Register Lua scripts for atomic execution
            self._sliding_script = self._redis.register_script(_SLIDING_WINDOW_LUA)
            self._fixed_script = self._redis.register_script(_FIXED_WINDOW_LUA)

            logger.info("RedisRateLimiter connected and Lua scripts registered")
        except Exception:
            logger.warning("RedisRateLimiter failed to connect — rate limiting unavailable")
            self._redis = None

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    @property
    def available(self) -> bool:
        """Return True if Redis is connected."""
        return self._redis is not None

    # --- Sliding Window (APEP-245) ---

    async def check_sliding_window(
        self,
        agent_role: str,
        tool_name: str,
        rate_limit: RateLimit,
    ) -> RateLimitResult:
        """Check and increment the sliding window rate limit via Redis sorted set."""
        if self._redis is None:
            return RateLimitResult(allowed=True)

        key = f"agentpep:rl:sliding:{agent_role}:{tool_name}"
        now = time.time()
        window_start = now - rate_limit.window_s
        member_id = uuid.uuid4().hex
        ttl = rate_limit.window_s + 1  # Extra second for safety

        try:
            count = await self._sliding_script(
                keys=[key],
                args=[str(window_start), str(now), member_id, str(ttl)],
            )
            current_count = int(count)
        except Exception:
            logger.warning("Redis sliding window check failed — allowing request")
            return RateLimitResult(allowed=True)

        if current_count > rate_limit.count:
            return RateLimitResult(
                allowed=False,
                reason=(
                    f"Sliding window rate limit exceeded for role={agent_role} "
                    f"tool={tool_name}: "
                    f"{current_count}/{rate_limit.count} in {rate_limit.window_s}s"
                ),
                current_count=current_count,
                limit=rate_limit.count,
            )

        return RateLimitResult(
            allowed=True,
            current_count=current_count,
            limit=rate_limit.count,
        )

    # --- Fixed Window (APEP-245) ---

    async def check_fixed_window(
        self,
        agent_role: str,
        tool_name: str,
        rate_limit: RateLimit,
    ) -> RateLimitResult:
        """Check and increment the fixed window rate limit via Redis counter."""
        if self._redis is None:
            return RateLimitResult(allowed=True)

        now = time.time()
        bucket_start = int(now // rate_limit.window_s) * rate_limit.window_s
        key = f"agentpep:rl:fixed:{agent_role}:{tool_name}:{bucket_start}"
        ttl = rate_limit.window_s + 1

        try:
            count = await self._fixed_script(
                keys=[key],
                args=[str(ttl)],
            )
            current_count = int(count)
        except Exception:
            logger.warning("Redis fixed window check failed — allowing request")
            return RateLimitResult(allowed=True)

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

    # --- Global Per-Tenant Rate Limit ---

    async def check_global_rate_limit(
        self,
        tenant_id: str,
    ) -> RateLimitResult:
        """Check the global per-tenant decisions/second ceiling."""
        if not settings.global_rate_limit_enabled:
            return RateLimitResult(allowed=True)

        if self._redis is None:
            return RateLimitResult(allowed=True)

        now = time.time()
        bucket_start = int(now)
        key = f"agentpep:rl:global:{tenant_id}:{bucket_start}"
        ceiling = settings.global_rate_limit_per_second

        try:
            count = await self._fixed_script(
                keys=[key],
                args=["2"],  # 2-second TTL for safety
            )
            current_count = int(count)
        except Exception:
            logger.warning("Redis global rate limit check failed — allowing request")
            return RateLimitResult(allowed=True)

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
redis_rate_limiter = RedisRateLimiter()
