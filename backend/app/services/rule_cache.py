"""RuleCache — LRU in-memory cache with TTL invalidation for policy rules.

APEP-026: Caches fetched rules to reduce MongoDB reads during high-throughput evaluation.
"""

import logging
import time
from collections import OrderedDict

from app.db import mongodb as db_module
from app.models.policy import PolicyRule

logger = logging.getLogger(__name__)

_DEFAULT_MAX_SIZE = 256
_DEFAULT_TTL_S = 30.0


class RuleCache:
    """LRU cache for policy rules with TTL-based invalidation.

    Cache key is a composite of (enabled,) — currently caches the full
    sorted rule list since all evaluations need the same ordered set.
    """

    def __init__(self, max_size: int = _DEFAULT_MAX_SIZE, ttl_s: float = _DEFAULT_TTL_S):
        self._max_size = max_size
        self._ttl_s = ttl_s
        self._cache: OrderedDict[str, tuple[float, list[PolicyRule]]] = OrderedDict()

    async def get_rules(self) -> list[PolicyRule]:
        """Return enabled rules sorted by priority, using cache if valid."""
        cache_key = "enabled_rules"
        now = time.monotonic()

        if cache_key in self._cache:
            cached_at, rules = self._cache[cache_key]
            if now - cached_at < self._ttl_s:
                # Move to end (most recently used)
                self._cache.move_to_end(cache_key)
                logger.debug("Rule cache HIT (age %.1fs)", now - cached_at)
                return rules

            # TTL expired — remove stale entry
            del self._cache[cache_key]

        # Cache miss — fetch from MongoDB
        rules = await self._fetch_rules()
        self._put(cache_key, rules, now)
        logger.debug("Rule cache MISS — fetched %d rules from MongoDB", len(rules))
        return rules

    def invalidate(self) -> None:
        """Clear all cached rules. Call after rule CRUD operations."""
        self._cache.clear()
        logger.debug("Rule cache invalidated")

    def _put(self, key: str, rules: list[PolicyRule], now: float) -> None:
        """Insert into cache, evicting LRU entries if at capacity."""
        if len(self._cache) >= self._max_size:
            self._cache.popitem(last=False)  # Evict oldest (LRU)
        self._cache[key] = (now, rules)

    @staticmethod
    async def _fetch_rules() -> list[PolicyRule]:
        """Fetch all enabled rules from MongoDB, sorted by priority ascending."""
        db = db_module.get_database()
        cursor = db[db_module.POLICY_RULES].find({"enabled": True}).sort("priority", 1)
        docs = await cursor.to_list(length=1000)
        return [PolicyRule(**doc) for doc in docs]

    @property
    def size(self) -> int:
        return len(self._cache)


# Module-level singleton
rule_cache = RuleCache()
