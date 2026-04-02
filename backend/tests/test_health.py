"""Tests for health and intercept endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    # Lazy import to avoid module-level side effects
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


@pytest.mark.asyncio
async def test_intercept_allow(client: AsyncClient):
    payload = {
        "session_id": "test-session",
        "agent_id": "test-agent",
        "tool_name": "read_file",
        "tool_args": {"path": "/tmp/test.txt"},
    }
    resp = await client.post("/v1/intercept", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "ALLOW"


@pytest.mark.asyncio
async def test_intercept_dry_run(client: AsyncClient):
    payload = {
        "session_id": "test-session",
        "agent_id": "test-agent",
        "tool_name": "send_email",
        "tool_args": {"to": "user@example.com"},
        "dry_run": True,
    }
    resp = await client.post("/v1/intercept", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "DRY_RUN"
