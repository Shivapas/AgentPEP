"""Tests for Console API endpoints (APEP-214, APEP-215)."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from tests.conftest import make_auth_headers


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def auth_headers():
    return make_auth_headers()


async def test_get_stats(client: AsyncClient, auth_headers):
    resp = await client.get("/v1/stats", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "policy_rules" in data
    assert "decisions_today" in data
    assert "active_agents" in data
    assert "deny_rate" in data
    assert "avg_latency_ms" in data
    assert "escalations_pending" in data


async def test_list_audit(client: AsyncClient, auth_headers):
    resp = await client.get("/v1/audit", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data


async def test_list_audit_with_filter(client: AsyncClient, auth_headers):
    resp = await client.get("/v1/audit?decision=DENY&limit=10", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data


async def test_list_rules(client: AsyncClient, auth_headers):
    resp = await client.get("/v1/rules", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data


async def test_list_agents(client: AsyncClient):
    resp = await client.get("/v1/console/agents")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data


async def test_submit_ux_survey(client: AsyncClient):
    resp = await client.post(
        "/v1/ux-survey",
        json={
            "responses": [4, 2, 5, 1, 4, 2, 5, 1, 4, 2],
            "score": 82.5,
            "additional_feedback": "Great product!",
            "timestamp": "2026-04-01T12:00:00Z",
        },
    )
    assert resp.status_code == 201
    assert resp.json()["status"] == "recorded"


async def test_submit_ux_survey_validation(client: AsyncClient):
    resp = await client.post(
        "/v1/ux-survey",
        json={
            "responses": [1, 2, 3],  # Too few responses
            "score": 50.0,
        },
    )
    assert resp.status_code == 422


async def test_stats_requires_auth(client: AsyncClient):
    """Stats endpoint should reject unauthenticated requests."""
    resp = await client.get("/v1/stats")
    assert resp.status_code == 422
