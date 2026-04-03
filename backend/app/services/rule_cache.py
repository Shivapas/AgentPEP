"""RuleCache — LRU in-memory cache with optional Redis backing for policy rules.

APEP-026: Caches fetched rules to reduce MongoDB reads during high-throughput evaluation.
APEP-181 (Sprint 23): Redis-backed policy cache for sub-millisecond rule retrieval.
APEP-186 (Sprint 23): Exposes ``is_warm`` property for adaptive timeout selection.
"""

import json
import logging
import time
from collections import OrderedDict

from app.core.config import settings
from app.db import mongodb as db_module
from app.models.policy import PolicyRule

logger = logging.getLogger(__name__)

_DEFAULT_MAX_SIZE = 256
_DEFAULT_TTL_S = 30.0

_REDIS_POLICY_KEY = "agentpep:policy_rules:enabled"


class RuleCache:
    """LRU cache for policy rules with TTL-based invalidation.

    Two-tier caching:
    1. L1 — in-process LRU OrderedDict (sub-microsecond).
    2. L2 — Redis (sub-millisecond), enabled via ``AGENTPEP_REDIS_ENABLED``.

    Falls back to MongoDB when both caches miss.
    """

    def __init__(
        self,
        max_size: int = _DEFAULT_MAX_SIZE,
        ttl_s: float = _DEFAULT_TTL_S,
    ):
        self._max_size = max_size
        self._ttl_s = ttl_s
        self._cache: OrderedDict[str, tuple[float, list[PolicyRule]]] = OrderedDict()
        self._redis = None  # type: ignore[assignment]
        self._redis_ttl_s = settings.redis_policy_cache_ttl_s
        self._warm = False

    # --- Redis lifecycle ---

    async def init_redis(self) -> None:
        """Initialise the Redis connection if enabled. Safe to call multiple times."""
        if not settings.redis_enabled:
            return
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
            )
            # Test connectivity
            await self._redis.ping()
            logger.info("Redis policy cache connected: %s", settings.redis_url)
        except Exception:
            logger.warning("Redis unavailable — falling back to in-memory only")
            self._redis = None

    async def close_redis(self) -> None:
        """Close the Redis connection."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    # --- Public API ---

    async def get_rules(self) -> list[PolicyRule]:
        """Return enabled rules sorted by priority, using cache if valid."""
        cache_key = "enabled_rules"
        now = time.monotonic()

        # L1: in-memory LRU
        if cache_key in self._cache:
            cached_at, rules = self._cache[cache_key]
            if now - cached_at < self._ttl_s:
                self._cache.move_to_end(cache_key)
                logger.debug("Rule cache L1 HIT (age %.1fs)", now - cached_at)
                return rules
            del self._cache[cache_key]

        # L2: Redis
        rules = await self._get_from_redis()
        if rules is not None:
            self._put(cache_key, rules, now)
            logger.debug("Rule cache L2 HIT (Redis) — %d rules", len(rules))
            return rules

        # L3: MongoDB
        rules = await self._fetch_rules()
        self._put(cache_key, rules, now)
        self._warm = True
        logger.debug("Rule cache MISS — fetched %d rules from MongoDB", len(rules))

        # Populate Redis asynchronously
        await self._put_to_redis(rules)

        return rules

    def invalidate(self) -> None:
        """Clear all cached rules. Call after rule CRUD operations."""
        self._cache.clear()
        self._warm = False
        logger.debug("Rule cache invalidated")

    async def invalidate_all(self) -> None:
        """Invalidate both in-memory and Redis caches."""
        self.invalidate()
        if self._redis is not None:
            try:
                await self._redis.delete(_REDIS_POLICY_KEY)
            except Exception:
                logger.warning("Failed to invalidate Redis policy cache")

    @property
    def is_warm(self) -> bool:
        """True if the cache has been populated at least once since last invalidation."""
        cache_key = "enabled_rules"
        if cache_key in self._cache:
            cached_at, _ = self._cache[cache_key]
            if time.monotonic() - cached_at < self._ttl_s:
                return True
        return False

    # --- Internal helpers ---

    def _put(self, key: str, rules: list[PolicyRule], now: float) -> None:
        """Insert into L1 cache, evicting LRU entries if at capacity."""
        if len(self._cache) >= self._max_size:
            self._cache.popitem(last=False)
        self._cache[key] = (now, rules)

    @staticmethod
    async def _fetch_rules() -> list[PolicyRule]:
        """Fetch all enabled rules from MongoDB, sorted by priority ascending."""
        db = db_module.get_database()
        cursor = db[db_module.POLICY_RULES].find({"enabled": True}).sort("priority", 1)
        docs = await cursor.to_list(length=1000)
        return [PolicyRule(**doc) for doc in docs]

    async def _get_from_redis(self) -> list[PolicyRule] | None:
        """Try to read rules from Redis L2 cache."""
        if self._redis is None:
            return None
        try:
            data = await self._redis.get(_REDIS_POLICY_KEY)
            if data is None:
                return None
            raw_list = json.loads(data)
            return [PolicyRule(**doc) for doc in raw_list]
        except Exception:
            logger.warning("Redis L2 read failed — falling back to MongoDB")
            return None

    async def _put_to_redis(self, rules: list[PolicyRule]) -> None:
        """Store rules in Redis L2 cache."""
        if self._redis is None:
            return
        try:
            data = json.dumps(
                [r.model_dump(mode="json") for r in rules],
                separators=(",", ":"),
            )
            await self._redis.set(
                _REDIS_POLICY_KEY, data, ex=int(self._redis_ttl_s)
            )
        except Exception:
            logger.warning("Redis L2 write failed")

    @property
    def size(self) -> int:
        return len(self._cache)


# Module-level singleton
rule_cache = RuleCache()
