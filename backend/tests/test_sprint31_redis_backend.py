"""Sprint 31 tests — Redis Storage Backend & Rate Limiter.

APEP-244: RedisStorageBackend — Redis-backed policy cache, session store,
          and taint graph persistence.
APEP-245: Redis-backed sliding window rate limiter replacing MongoDB-based
          implementation.
"""


import pytest

from app.backends.redis_storage import RedisStorageBackend
from app.models.policy import RateLimit, RateLimitType
from app.services.rate_limiter import RateLimitResult
from app.services.redis_rate_limiter import RedisRateLimiter


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---------------------------------------------------------------------------
# APEP-244: RedisStorageBackend — Unit Tests (no Redis required)
# ---------------------------------------------------------------------------


class TestRedisStorageBackendUnit:
    """Unit tests for RedisStorageBackend that don't require a live Redis."""

    def test_collection_key(self):
        """Collection key format is correct."""
        backend = RedisStorageBackend(key_prefix="test")
        assert backend._collection_key("policy_rules") == "test:policy_rules"

    def test_filter_hash_deterministic(self):
        """Filter hash is stable and deterministic."""
        h1 = RedisStorageBackend._filter_hash({"key": "value", "a": 1})
        h2 = RedisStorageBackend._filter_hash({"a": 1, "key": "value"})
        # Same keys in different order should produce the same hash
        assert h1 == h2

    def test_filter_hash_different(self):
        """Different filters produce different hashes."""
        h1 = RedisStorageBackend._filter_hash({"key": "value1"})
        h2 = RedisStorageBackend._filter_hash({"key": "value2"})
        assert h1 != h2

    def test_doc_matches_filter_exact(self):
        """Exact match filter works."""
        doc = {"name": "test", "enabled": True, "count": 5}
        assert RedisStorageBackend._doc_matches_filter(doc, {"name": "test"})
        assert RedisStorageBackend._doc_matches_filter(doc, {"name": "test", "enabled": True})
        assert not RedisStorageBackend._doc_matches_filter(doc, {"name": "other"})

    def test_doc_matches_filter_operators(self):
        """MongoDB-style operators work."""
        doc = {"name": "test", "count": 5, "status": "active"}
        f = RedisStorageBackend._doc_matches_filter
        assert f(doc, {"status": {"$in": ["active", "pending"]}})
        assert not f(doc, {"status": {"$in": ["inactive"]}})
        assert f(doc, {"count": {"$gte": 3}})
        assert not f(doc, {"count": {"$gte": 10}})
        assert f(doc, {"count": {"$lte": 10}})
        assert not f(doc, {"count": {"$lte": 2}})
        assert not RedisStorageBackend._doc_matches_filter(doc, {"count": {"$lte": 2}})

    @pytest.mark.asyncio
    async def test_get_returns_none_when_disconnected(self):
        """get() returns None when Redis is not connected."""
        backend = RedisStorageBackend()
        # _redis is None by default (not initialized)
        result = await backend.get("collection", {"key": "value"})
        assert result is None

    @pytest.mark.asyncio
    async def test_put_returns_empty_when_disconnected(self):
        """put() returns empty string when Redis is not connected."""
        backend = RedisStorageBackend()
        result = await backend.put("collection", {"key": "value"})
        assert result == ""

    @pytest.mark.asyncio
    async def test_delete_returns_false_when_disconnected(self):
        """delete() returns False when Redis is not connected."""
        backend = RedisStorageBackend()
        result = await backend.delete("collection", {"key": "value"})
        assert result is False

    @pytest.mark.asyncio
    async def test_query_returns_empty_when_disconnected(self):
        """query() returns empty list when Redis is not connected."""
        backend = RedisStorageBackend()
        result = await backend.query("collection", {})
        assert result == []

    @pytest.mark.asyncio
    async def test_health_check_false_when_disconnected(self):
        """health_check() returns False when Redis is not connected."""
        backend = RedisStorageBackend()
        result = await backend.health_check()
        assert result is False

    @pytest.mark.asyncio
    async def test_close_safe_when_disconnected(self):
        """close() is safe to call when not connected."""
        backend = RedisStorageBackend()
        await backend.close()  # Should not raise


# ---------------------------------------------------------------------------
# APEP-245: RedisRateLimiter — Unit Tests (no Redis required)
# ---------------------------------------------------------------------------


class TestRedisRateLimiterUnit:
    """Unit tests for RedisRateLimiter that don't require a live Redis."""

    @pytest.mark.asyncio
    async def test_available_false_when_disconnected(self):
        """available returns False when not initialized."""
        limiter = RedisRateLimiter()
        assert limiter.available is False

    @pytest.mark.asyncio
    async def test_sliding_window_allows_when_disconnected(self):
        """Sliding window allows requests when Redis is unavailable."""
        limiter = RedisRateLimiter()
        rl = RateLimit(count=10, window_s=60)
        result = await limiter.check_sliding_window("role", "tool", rl)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_fixed_window_allows_when_disconnected(self):
        """Fixed window allows requests when Redis is unavailable."""
        limiter = RedisRateLimiter()
        rl = RateLimit(count=10, window_s=60, limiter_type=RateLimitType.FIXED_WINDOW)
        result = await limiter.check_fixed_window("role", "tool", rl)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_global_allows_when_disconnected(self):
        """Global rate limit allows when Redis is unavailable."""
        limiter = RedisRateLimiter()
        result = await limiter.check_global_rate_limit("tenant")
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_check_dispatches_sliding(self):
        """check() dispatches to sliding window for SLIDING_WINDOW type."""
        limiter = RedisRateLimiter()
        rl = RateLimit(count=10, window_s=60, limiter_type=RateLimitType.SLIDING_WINDOW)
        result = await limiter.check("role", "tool", rl)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_check_dispatches_fixed(self):
        """check() dispatches to fixed window for FIXED_WINDOW type."""
        limiter = RedisRateLimiter()
        rl = RateLimit(count=10, window_s=60, limiter_type=RateLimitType.FIXED_WINDOW)
        result = await limiter.check("role", "tool", rl)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_close_safe_when_disconnected(self):
        """close() is safe to call when not connected."""
        limiter = RedisRateLimiter()
        await limiter.close()  # Should not raise


# ---------------------------------------------------------------------------
# APEP-244/245: Integration with existing rate limiter
# ---------------------------------------------------------------------------


class TestRateLimiterFallback:
    """Test that the MongoDB rate limiter falls back correctly."""

    @pytest.mark.asyncio
    async def test_mongodb_rate_limiter_still_works(self, mock_mongodb):
        """Existing MongoDB rate limiter works when Redis is disabled."""
        from app.core.config import settings
        from app.services.rate_limiter import rate_limiter

        settings.redis_rate_limiter_enabled = False
        rl = RateLimit(count=5, window_s=60)

        # First call should be allowed
        result = await rate_limiter.check("test-role", "test-tool", rl)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_rate_limit_result_structure(self):
        """RateLimitResult has the expected fields."""
        result = RateLimitResult(allowed=True, current_count=3, limit=10)
        assert result.allowed is True
        assert result.current_count == 3
        assert result.limit == 10
        assert result.reason == ""

    @pytest.mark.asyncio
    async def test_rate_limit_denied_has_reason(self):
        """Denied RateLimitResult includes a descriptive reason."""
        result = RateLimitResult(
            allowed=False,
            reason="Rate limit exceeded",
            current_count=11,
            limit=10,
        )
        assert result.allowed is False
        assert "exceeded" in result.reason
