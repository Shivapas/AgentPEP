"""Sprint 56 — Unit tests for per-session scan mode configuration (APEP-444.c).

Tests cover:
  - Setting scan mode for a session
  - Mode resolution (session override vs requested)
  - Locked sessions preventing downgrade
  - Risk multiplier retrieval
  - Config listing and removal
  - Cache behaviour
"""

from __future__ import annotations

import pytest

from app.services.session_scan_config import SessionScanConfigService


@pytest.fixture
def svc():
    """Create a fresh SessionScanConfigService for each test."""
    s = SessionScanConfigService()
    yield s
    s.clear_cache()


class TestSetMode:
    """APEP-444.b: Core logic — setting per-session scan mode."""

    @pytest.mark.asyncio
    async def test_set_mode_standard(self, svc, mock_mongodb):
        config = await svc.set_mode("sess-1", "STANDARD")
        assert config.session_id == "sess-1"
        assert config.scan_mode == "STANDARD"
        assert config.risk_multiplier == 1.0
        assert config.locked is False

    @pytest.mark.asyncio
    async def test_set_mode_strict(self, svc, mock_mongodb):
        config = await svc.set_mode("sess-2", "STRICT", reason="test", lock=True)
        assert config.scan_mode == "STRICT"
        assert config.locked is True
        assert config.reason == "test"

    @pytest.mark.asyncio
    async def test_set_mode_with_multiplier(self, svc, mock_mongodb):
        config = await svc.set_mode(
            "sess-3", "STRICT", risk_multiplier=1.5, set_by="yolo_detector"
        )
        assert config.risk_multiplier == 1.5
        assert config.set_by == "yolo_detector"

    @pytest.mark.asyncio
    async def test_set_mode_invalid_defaults_to_strict(self, svc, mock_mongodb):
        config = await svc.set_mode("sess-4", "INVALID_MODE")
        assert config.scan_mode == "STRICT"


class TestLockedMode:
    """APEP-444.b: Locked sessions prevent scan mode downgrade."""

    @pytest.mark.asyncio
    async def test_locked_prevents_downgrade(self, svc, mock_mongodb):
        await svc.set_mode("sess-lock", "STRICT", lock=True)
        config = await svc.set_mode("sess-lock", "LENIENT")
        # Should stay STRICT because locked
        assert config.scan_mode == "STRICT"
        assert config.locked is True

    @pytest.mark.asyncio
    async def test_locked_allows_same_level(self, svc, mock_mongodb):
        await svc.set_mode("sess-lock2", "STRICT", lock=True)
        config = await svc.set_mode("sess-lock2", "STRICT", reason="updated")
        assert config.scan_mode == "STRICT"

    @pytest.mark.asyncio
    async def test_unlocked_allows_downgrade(self, svc, mock_mongodb):
        await svc.set_mode("sess-unlock", "STRICT", lock=False)
        config = await svc.set_mode("sess-unlock", "LENIENT")
        assert config.scan_mode == "LENIENT"


class TestResolveMode:
    """APEP-444.b: Mode resolution — most restrictive wins."""

    @pytest.mark.asyncio
    async def test_resolve_no_config(self, svc, mock_mongodb):
        mode = await svc.resolve_mode("no-session", requested="STANDARD")
        assert mode == "STANDARD"

    @pytest.mark.asyncio
    async def test_resolve_with_higher_override(self, svc, mock_mongodb):
        await svc.set_mode("sess-r1", "STRICT")
        mode = await svc.resolve_mode("sess-r1", requested="LENIENT")
        assert mode == "STRICT"

    @pytest.mark.asyncio
    async def test_resolve_requested_higher_wins(self, svc, mock_mongodb):
        await svc.set_mode("sess-r2", "LENIENT")
        mode = await svc.resolve_mode("sess-r2", requested="STRICT")
        assert mode == "STRICT"

    @pytest.mark.asyncio
    async def test_resolve_none_session(self, svc, mock_mongodb):
        mode = await svc.resolve_mode(None, requested="STANDARD")
        assert mode == "STANDARD"


class TestRiskMultiplier:
    """APEP-444.b: Risk multiplier retrieval."""

    @pytest.mark.asyncio
    async def test_default_multiplier(self, svc, mock_mongodb):
        m = await svc.get_risk_multiplier("no-session")
        assert m == 1.0

    @pytest.mark.asyncio
    async def test_custom_multiplier(self, svc, mock_mongodb):
        await svc.set_mode("sess-m1", "STRICT", risk_multiplier=2.0)
        m = await svc.get_risk_multiplier("sess-m1")
        assert m == 2.0

    @pytest.mark.asyncio
    async def test_none_session(self, svc, mock_mongodb):
        m = await svc.get_risk_multiplier(None)
        assert m == 1.0


class TestListAndRemove:
    """APEP-444.b: Listing and removing configs."""

    @pytest.mark.asyncio
    async def test_list_configs(self, svc, mock_mongodb):
        await svc.set_mode("sess-l1", "STRICT")
        await svc.set_mode("sess-l2", "STANDARD")
        result = await svc.list_configs()
        assert result.total == 2

    @pytest.mark.asyncio
    async def test_list_locked_only(self, svc, mock_mongodb):
        await svc.set_mode("sess-lo1", "STRICT", lock=True)
        await svc.set_mode("sess-lo2", "STANDARD", lock=False)
        result = await svc.list_configs(locked_only=True)
        assert result.total == 1
        assert result.configs[0].session_id == "sess-lo1"

    @pytest.mark.asyncio
    async def test_remove_config(self, svc, mock_mongodb):
        await svc.set_mode("sess-rm", "STRICT")
        deleted = await svc.remove_config("sess-rm")
        assert deleted is True
        config = await svc.get_config("sess-rm")
        assert config is None


class TestCacheBehaviour:
    """APEP-444.b: In-memory cache for fast lookups."""

    @pytest.mark.asyncio
    async def test_cache_hit(self, svc, mock_mongodb):
        await svc.set_mode("sess-c1", "STRICT")
        # Second call should hit cache
        config = await svc.get_config("sess-c1")
        assert config is not None
        assert config.scan_mode == "STRICT"

    @pytest.mark.asyncio
    async def test_clear_cache(self, svc, mock_mongodb):
        await svc.set_mode("sess-c2", "STRICT")
        svc.clear_cache()
        # Should still load from DB
        config = await svc.get_config("sess-c2")
        assert config is not None
