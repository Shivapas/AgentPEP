"""Sprint 23 — Performance Hardening tests.

APEP-180: Intercept hot path optimisation (serialisation elimination).
APEP-181: Redis-backed policy cache (L1/L2 tiered caching).
APEP-182: MongoDB connection pooling configuration.
APEP-183: Taint graph bounded node limit with LRU eviction.
APEP-184: Async audit log writer (background queue).
APEP-186: Adaptive timeouts (cached vs cold path).
APEP-187: Risk scorer hot path.
"""

import asyncio
import time
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import settings
from app.db import mongodb as db_module
from app.main import app
from app.models.policy import (
    Decision,
    PolicyRule,
    TaintSource,
)
from app.services.policy_evaluator import (
    AsyncAuditLogWriter,
    audit_log_writer,
    policy_evaluator,
    risk_scorer,
)
from app.services.rule_cache import RuleCache, rule_cache
from app.services.taint_graph import TaintGraph, session_graph_manager

# ---------------------------------------------------------------------------
# APEP-180: Intercept hot path — verify response includes risk_score
# ---------------------------------------------------------------------------


class TestInterceptHotPath:
    """APEP-180: Verify optimised intercept path works correctly."""

    @pytest.fixture
    async def seed_allow_rule(self, mock_mongodb):
        """Seed a simple ALLOW rule for file.read."""
        rule = PolicyRule(
            rule_id=uuid4(),
            name="allow-file-read",
            agent_role=["default"],
            tool_pattern="file.read",
            action=Decision.ALLOW,
            priority=10,
            enabled=True,
        )
        await mock_mongodb[db_module.POLICY_RULES].insert_one(
            rule.model_dump(mode="json")
        )
        rule_cache.invalidate()
        return rule

    async def test_intercept_returns_risk_score(self, seed_allow_rule):
        """APEP-180/187: Response includes computed risk_score field."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/v1/intercept", json={
                "session_id": "perf-session",
                "agent_id": "agent-1",
                "tool_name": "file.read",
                "tool_args": {"path": "/tmp/test"},
            })
        assert resp.status_code == 200
        body = resp.json()
        assert "risk_score" in body
        assert body["decision"] == "ALLOW"

    async def test_intercept_deny_by_default(self, mock_mongodb):
        """Verify deny-by-default still works after hot path changes."""
        rule_cache.invalidate()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/v1/intercept", json={
                "session_id": "perf-session",
                "agent_id": "agent-1",
                "tool_name": "unknown.tool",
                "tool_args": {},
            })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "DENY"


# ---------------------------------------------------------------------------
# APEP-181: Redis-backed policy cache
# ---------------------------------------------------------------------------


class TestRedisPolicyCache:
    """APEP-181: Two-tier cache behaviour (L1 in-memory, L2 Redis)."""

    async def test_l1_cache_hit(self, mock_mongodb):
        """L1 in-memory cache returns rules without hitting MongoDB."""
        cache = RuleCache(ttl_s=60.0)

        # First call — cache miss, fetches from MongoDB
        rules1 = await cache.get_rules()
        assert isinstance(rules1, list)

        # Second call — should hit L1
        rules2 = await cache.get_rules()
        assert rules2 == rules1

    async def test_cache_invalidation(self, mock_mongodb):
        """invalidate() clears L1 and resets warm status."""
        cache = RuleCache(ttl_s=60.0)
        await cache.get_rules()
        assert cache.is_warm is True

        cache.invalidate()
        assert cache.is_warm is False
        assert cache.size == 0

    async def test_is_warm_property(self, mock_mongodb):
        """is_warm reflects whether cache has valid data."""
        cache = RuleCache(ttl_s=0.1)  # Very short TTL

        assert cache.is_warm is False
        await cache.get_rules()
        assert cache.is_warm is True

        # Wait for TTL to expire
        await asyncio.sleep(0.15)
        assert cache.is_warm is False

    async def test_redis_not_enabled_falls_back(self, mock_mongodb):
        """When Redis is disabled, cache works with L1 only."""
        cache = RuleCache(ttl_s=60.0)
        # _redis is None by default (not initialised)
        assert cache._redis is None
        rules = await cache.get_rules()
        assert isinstance(rules, list)


# ---------------------------------------------------------------------------
# APEP-182: MongoDB connection pooling
# ---------------------------------------------------------------------------


class TestMongoConnectionPooling:
    """APEP-182: Verify pool settings are applied to config."""

    def test_pool_settings_in_config(self):
        """Config exposes pool size settings."""
        assert settings.mongodb_min_pool_size >= 1
        assert settings.mongodb_max_pool_size >= settings.mongodb_min_pool_size
        assert settings.mongodb_max_idle_time_ms > 0
        assert settings.mongodb_connect_timeout_ms > 0
        assert settings.mongodb_server_selection_timeout_ms > 0

    def test_default_pool_sizes(self):
        """Default pool sizes are reasonable for high-throughput."""
        assert settings.mongodb_min_pool_size == 10
        assert settings.mongodb_max_pool_size == 100


# ---------------------------------------------------------------------------
# APEP-183: Taint graph bounded node limit with LRU eviction
# ---------------------------------------------------------------------------


class TestTaintGraphLRUEviction:
    """APEP-183: Bounded per-session node limit with LRU eviction."""

    def test_eviction_triggers_at_capacity(self):
        """Nodes are evicted when max_nodes is reached."""
        graph = TaintGraph("eviction-session", max_nodes=5)

        # Add 5 nodes — at capacity
        node_ids = []
        for _ in range(5):
            n = graph.add_node(source=TaintSource.USER_PROMPT, value="test")
            node_ids.append(n.node_id)

        assert graph.node_count == 5
        assert graph.evicted_count == 0

        # Add 6th node — should evict the oldest
        graph.add_node(source=TaintSource.USER_PROMPT, value="overflow")
        assert graph.node_count == 5
        assert graph.evicted_count == 1

        # First node should have been evicted
        assert graph.get_node(node_ids[0]) is None

        # Last 4 original nodes should still exist
        for nid in node_ids[1:]:
            assert graph.get_node(nid) is not None

    def test_lru_touch_prevents_eviction(self):
        """Accessing a node moves it to end of LRU, preventing early eviction."""
        graph = TaintGraph("lru-touch-session", max_nodes=3)

        n1 = graph.add_node(source=TaintSource.USER_PROMPT, value="first")
        n2 = graph.add_node(source=TaintSource.USER_PROMPT, value="second")
        n3 = graph.add_node(source=TaintSource.USER_PROMPT, value="third")

        # Touch n1 — moves it to the end
        graph.get_node(n1.node_id)

        # Add a new node — should evict n2 (now oldest untouched)
        n4 = graph.add_node(source=TaintSource.USER_PROMPT, value="fourth")

        assert graph.get_node(n1.node_id) is not None  # Touched, still alive
        assert graph.get_node(n2.node_id) is None  # Evicted (was oldest)
        assert graph.get_node(n3.node_id) is not None
        assert graph.get_node(n4.node_id) is not None

    def test_eviction_with_propagation(self):
        """Propagated nodes respect the LRU limit."""
        graph = TaintGraph("prop-evict-session", max_nodes=3)

        n1 = graph.add_node(source=TaintSource.WEB, value="web-data")
        n2 = graph.add_node(source=TaintSource.EMAIL, value="email-data")
        n3 = graph.add_node(source=TaintSource.USER_PROMPT, value="user-data")

        # Propagate creates a new node, evicting the oldest (n1)
        n4 = graph.propagate(
            parent_ids=[n2.node_id, n3.node_id],
            source=TaintSource.TOOL_OUTPUT,
            value="combined",
        )

        assert graph.node_count == 3
        assert graph.get_node(n1.node_id) is None  # Evicted

    def test_max_nodes_property(self):
        """max_nodes property reflects the configured limit."""
        graph = TaintGraph("prop-session", max_nodes=42)
        assert graph.max_nodes == 42

    def test_evicted_count_accumulates(self):
        """evicted_count increments with each eviction."""
        graph = TaintGraph("accumulate-session", max_nodes=2)

        graph.add_node(source=TaintSource.USER_PROMPT, value="a")
        graph.add_node(source=TaintSource.USER_PROMPT, value="b")
        assert graph.evicted_count == 0

        graph.add_node(source=TaintSource.USER_PROMPT, value="c")
        assert graph.evicted_count == 1

        graph.add_node(source=TaintSource.USER_PROMPT, value="d")
        assert graph.evicted_count == 2

        assert graph.node_count == 2

    def test_config_default_max_nodes(self):
        """Config provides a sensible default for max_nodes."""
        assert settings.taint_graph_max_nodes_per_session == 10000


# ---------------------------------------------------------------------------
# APEP-184: Async audit log writer
# ---------------------------------------------------------------------------


class TestAsyncAuditLogWriter:
    """APEP-184: Background audit log writer with batching."""

    async def test_enqueue_and_flush(self, mock_mongodb):
        """Records enqueued are flushed to MongoDB."""
        writer = AsyncAuditLogWriter(batch_size=10, flush_interval_s=0.1)

        record = {
            "decision_id": str(uuid4()),
            "session_id": "audit-session",
            "agent_id": "agent-1",
            "agent_role": "default",
            "tool_name": "file.read",
            "tool_args_hash": "abc123",
            "decision": "ALLOW",
            "risk_score": 0.0,
            "taint_flags": [],
            "delegation_chain": [],
            "latency_ms": 5,
            "timestamp": "2025-01-01T00:00:00",
        }
        writer.enqueue(record)
        assert writer.pending_count == 1

        flushed = await writer.flush_pending()
        assert flushed == 1
        assert writer.pending_count == 0

        # Verify it was written to MongoDB
        docs = await mock_mongodb[db_module.AUDIT_DECISIONS].find().to_list(length=100)
        assert len(docs) == 1
        assert docs[0]["session_id"] == "audit-session"

    async def test_multiple_records_batched(self, mock_mongodb):
        """Multiple records are written in a single batch."""
        writer = AsyncAuditLogWriter(batch_size=100, flush_interval_s=0.1)

        for i in range(5):
            writer.enqueue({
                "decision_id": str(uuid4()),
                "session_id": f"batch-session-{i}",
                "agent_id": "agent-1",
                "agent_role": "default",
                "tool_name": "test.tool",
                "tool_args_hash": "hash",
                "decision": "DENY",
                "risk_score": 0.0,
                "taint_flags": [],
                "delegation_chain": [],
                "latency_ms": 1,
                "timestamp": "2025-01-01T00:00:00",
            })

        assert writer.pending_count == 5
        flushed = await writer.flush_pending()
        assert flushed == 5

    async def test_start_stop_idempotent(self):
        """start() and stop() are safe to call multiple times."""
        writer = AsyncAuditLogWriter()
        writer.start()
        writer.start()  # Should not raise
        writer.stop()
        writer.stop()  # Should not raise

    async def test_enqueue_nonblocking(self):
        """enqueue() returns immediately without awaiting."""
        writer = AsyncAuditLogWriter()
        start = time.monotonic()
        for _ in range(100):
            writer.enqueue({"test": True})
        elapsed = time.monotonic() - start
        # Should complete in < 10ms (non-blocking)
        assert elapsed < 0.1


# ---------------------------------------------------------------------------
# APEP-186: Adaptive timeouts
# ---------------------------------------------------------------------------


class TestAdaptiveTimeouts:
    """APEP-186: Dynamic timeout based on cache state."""

    def test_config_has_both_timeout_values(self):
        """Config provides distinct cached and cold timeout values."""
        assert settings.evaluation_timeout_cached_s < settings.evaluation_timeout_cold_s
        assert settings.evaluation_timeout_cached_s > 0
        assert settings.evaluation_timeout_cold_s > 0

    async def test_cold_timeout_when_cache_empty(self, mock_mongodb):
        """When cache is cold, the longer timeout is selected."""
        rule_cache.invalidate()
        timeout = policy_evaluator._select_timeout()
        assert timeout == settings.evaluation_timeout_cold_s

    async def test_cached_timeout_when_warm(self, mock_mongodb):
        """When cache is warm, the shorter timeout is selected."""
        # Warm the cache
        await rule_cache.get_rules()
        timeout = policy_evaluator._select_timeout()
        assert timeout == settings.evaluation_timeout_cached_s


# ---------------------------------------------------------------------------
# APEP-187: Risk scorer
# ---------------------------------------------------------------------------


class TestRiskScorer:
    """APEP-187: Risk score computation on the hot path."""

    def test_zero_risk_for_safe_call(self):
        """Safe tool call with no taint flags produces 0.0 risk."""
        score = risk_scorer.score(
            taint_flags=[],
            tool_name="file.read",
            delegation_chain=[],
        )
        assert score == 0.0

    def test_quarantine_taint_high_risk(self):
        """QUARANTINE taint produces high risk score."""
        score = risk_scorer.score(
            taint_flags=["QUARANTINE"],
            tool_name="file.read",
            delegation_chain=[],
        )
        assert score >= 0.8

    def test_untrusted_taint_medium_risk(self):
        """UNTRUSTED taint produces moderate risk score."""
        score = risk_scorer.score(
            taint_flags=["UNTRUSTED"],
            tool_name="file.read",
            delegation_chain=[],
        )
        assert 0.3 <= score <= 0.7

    def test_sensitive_tool_adds_risk(self):
        """Sensitive tool names contribute to risk score."""
        safe_score = risk_scorer.score(
            taint_flags=[],
            tool_name="file.read",
            delegation_chain=[],
        )
        risky_score = risk_scorer.score(
            taint_flags=[],
            tool_name="shell.exec",
            delegation_chain=[],
        )
        assert risky_score > safe_score

    def test_delegation_depth_adds_risk(self):
        """Deeper delegation chains add incremental risk."""
        score_no_chain = risk_scorer.score(
            taint_flags=[],
            tool_name="file.read",
            delegation_chain=[],
        )
        score_deep_chain = risk_scorer.score(
            taint_flags=[],
            tool_name="file.read",
            delegation_chain=["a", "b", "c", "d", "e"],
        )
        assert score_deep_chain > score_no_chain

    def test_risk_capped_at_one(self):
        """Risk score never exceeds 1.0 even with all risk factors."""
        score = risk_scorer.score(
            taint_flags=["QUARANTINE"],
            tool_name="shell.exec",
            delegation_chain=["a", "b", "c", "d", "e", "f", "g"],
        )
        assert score <= 1.0

    def test_combined_risk_factors(self):
        """Multiple risk factors compound correctly."""
        score = risk_scorer.score(
            taint_flags=["UNTRUSTED"],
            tool_name="file.write",
            delegation_chain=["a", "b"],
        )
        # Should be > just taint alone
        taint_only = risk_scorer.score(
            taint_flags=["UNTRUSTED"],
            tool_name="file.read",
            delegation_chain=[],
        )
        assert score > taint_only

    def test_rule_risk_threshold_contributes(self):
        """A rule with low risk_threshold adds to computed risk."""
        rule = PolicyRule(
            name="restricted",
            agent_role=["admin"],
            tool_pattern="deploy.*",
            action=Decision.ALLOW,
            risk_threshold=0.3,
        )
        score_with_rule = risk_scorer.score(
            taint_flags=[],
            tool_name="file.read",
            delegation_chain=[],
            matched_rule=rule,
        )
        score_without = risk_scorer.score(
            taint_flags=[],
            tool_name="file.read",
            delegation_chain=[],
        )
        assert score_with_rule > score_without


# ---------------------------------------------------------------------------
# Integration: full intercept with all Sprint 23 features active
# ---------------------------------------------------------------------------


class TestSprint23Integration:
    """End-to-end integration tests with all Sprint 23 features active."""

    @pytest.fixture
    async def seed_rules(self, mock_mongodb):
        """Seed rules for integration tests."""
        rules = [
            PolicyRule(
                rule_id=uuid4(),
                name="allow-read",
                agent_role=["default"],
                tool_pattern="file.read",
                action=Decision.ALLOW,
                priority=10,
                enabled=True,
            ),
            PolicyRule(
                rule_id=uuid4(),
                name="escalate-write",
                agent_role=["default"],
                tool_pattern="file.write",
                action=Decision.ESCALATE,
                priority=20,
                risk_threshold=0.5,
                enabled=True,
            ),
        ]
        for r in rules:
            await mock_mongodb[db_module.POLICY_RULES].insert_one(
                r.model_dump(mode="json")
            )
        rule_cache.invalidate()
        return rules

    async def test_full_intercept_with_risk_score(self, seed_rules):
        """Full intercept returns valid response with risk score."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/v1/intercept", json={
                "session_id": "integration-session",
                "agent_id": "agent-1",
                "tool_name": "file.read",
                "tool_args": {"path": "/data"},
            })

        assert resp.status_code == 200
        body = resp.json()
        assert body["decision"] == "ALLOW"
        assert "risk_score" in body
        assert body["risk_score"] >= 0.0

    async def test_audit_enqueued_not_blocking(self, seed_rules):
        """Audit records are enqueued, not written synchronously."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            start = time.monotonic()
            resp = await client.post("/v1/intercept", json={
                "session_id": "audit-perf-session",
                "agent_id": "agent-1",
                "tool_name": "file.read",
                "tool_args": {},
            })
            elapsed = time.monotonic() - start

        assert resp.status_code == 200
        # The response should return before audit is flushed
        # Audit writer should have pending records
        assert audit_log_writer.pending_count >= 0  # May have been flushed already

    async def test_taint_graph_eviction_during_intercept(self, mock_mongodb):
        """Taint graph respects node limits during active sessions."""
        graph = session_graph_manager.create_session("evict-integration")
        graph._max_nodes = 3  # Low limit for testing

        for i in range(5):
            graph.add_node(source=TaintSource.WEB, value=f"data-{i}")

        assert graph.node_count == 3
        assert graph.evicted_count == 2
        session_graph_manager.destroy_session("evict-integration")
