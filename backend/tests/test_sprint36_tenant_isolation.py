"""Unit tests for TenantIsolationGuard (Sprint 36 — APEP-290)."""

import pytest

from app.models.sprint36 import TenantIsolationConfig
from app.services.tenant_isolation import TenantIsolationGuard


@pytest.fixture
def guard():
    """Create a fresh TenantIsolationGuard with cleared cache."""
    g = TenantIsolationGuard()
    g.invalidate_cache()
    return g


@pytest.mark.asyncio
async def test_same_tenant_always_allowed(mock_mongodb, guard):
    """Same tenant should always be able to access its own data."""
    allowed, reason = await guard.check_access("tenant-a", "tenant-a")
    assert allowed is True


@pytest.mark.asyncio
async def test_default_tenant_bypass(mock_mongodb, guard):
    """Default tenant should bypass isolation checks."""
    allowed, reason = await guard.check_access("default", "tenant-a")
    assert allowed is True

    allowed2, reason2 = await guard.check_access("tenant-a", "default")
    assert allowed2 is True


@pytest.mark.asyncio
async def test_strict_isolation_blocks_cross_tenant(mock_mongodb, guard):
    """STRICT isolation should block cross-tenant access."""
    await guard.set_config(TenantIsolationConfig(
        tenant_id="tenant-a",
        data_boundary="STRICT",
    ))
    await guard.set_config(TenantIsolationConfig(
        tenant_id="tenant-b",
        data_boundary="STRICT",
    ))

    allowed, reason = await guard.check_access("tenant-a", "tenant-b")
    assert allowed is False
    assert "STRICT" in reason


@pytest.mark.asyncio
async def test_shared_with_peer_allowed(mock_mongodb, guard):
    """SHARED isolation should allow access to peer tenants."""
    await guard.set_config(TenantIsolationConfig(
        tenant_id="tenant-a",
        data_boundary="SHARED",
        allowed_peer_tenants=["tenant-b"],
    ))
    await guard.set_config(TenantIsolationConfig(
        tenant_id="tenant-b",
        data_boundary="SHARED",
    ))

    allowed, reason = await guard.check_access("tenant-a", "tenant-b")
    assert allowed is True


@pytest.mark.asyncio
async def test_shared_without_peer_blocked(mock_mongodb, guard):
    """SHARED isolation should block access to non-peer tenants."""
    await guard.set_config(TenantIsolationConfig(
        tenant_id="tenant-a",
        data_boundary="SHARED",
        allowed_peer_tenants=["tenant-c"],
    ))
    await guard.set_config(TenantIsolationConfig(
        tenant_id="tenant-b",
        data_boundary="SHARED",
    ))

    allowed, reason = await guard.check_access("tenant-a", "tenant-b")
    assert allowed is False
    assert "not in allowed peers" in reason


@pytest.mark.asyncio
async def test_no_config_defaults_to_deny(mock_mongodb, guard):
    """Without config, cross-tenant access should be denied."""
    allowed, reason = await guard.check_access("unknown-a", "unknown-b")
    assert allowed is False


@pytest.mark.asyncio
async def test_violation_logged(mock_mongodb, guard):
    """Violations should be persisted to the database."""
    await guard.set_config(TenantIsolationConfig(
        tenant_id="tenant-x",
        data_boundary="STRICT",
    ))
    await guard.set_config(TenantIsolationConfig(
        tenant_id="tenant-y",
        data_boundary="STRICT",
    ))

    await guard.check_access("tenant-x", "tenant-y", "session", "sess-123")

    violations = await guard.get_violations("tenant-x")
    assert len(violations) >= 1
    assert violations[0].source_tenant_id == "tenant-x"
    assert violations[0].target_tenant_id == "tenant-y"
    assert violations[0].blocked is True


@pytest.mark.asyncio
async def test_cache_invalidation(mock_mongodb, guard):
    """Cache invalidation should force re-read from DB."""
    await guard.set_config(TenantIsolationConfig(
        tenant_id="tenant-cache",
        data_boundary="STRICT",
    ))
    # First read populates cache
    config = await guard.get_config("tenant-cache")
    assert config is not None
    assert config.data_boundary == "STRICT"

    # Invalidate and verify cache is cleared
    guard.invalidate_cache("tenant-cache")
    assert "tenant-cache" not in guard._config_cache


@pytest.mark.asyncio
async def test_get_violations_filtered(mock_mongodb, guard):
    """get_violations should filter by tenant_id."""
    await guard.set_config(TenantIsolationConfig(
        tenant_id="t1", data_boundary="STRICT",
    ))
    await guard.set_config(TenantIsolationConfig(
        tenant_id="t2", data_boundary="STRICT",
    ))
    await guard.set_config(TenantIsolationConfig(
        tenant_id="t3", data_boundary="STRICT",
    ))

    await guard.check_access("t1", "t2")
    await guard.check_access("t3", "t2")

    v1 = await guard.get_violations("t1")
    v3 = await guard.get_violations("t3")
    assert len(v1) >= 1
    assert len(v3) >= 1
    # Each set should only include violations involving that tenant
    for v in v1:
        assert "t1" in (v.source_tenant_id, v.target_tenant_id)
