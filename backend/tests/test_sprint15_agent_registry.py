"""APEP-127 — E2E tests for agent registration and key rotation flows."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app

transport = ASGITransport(app=app)
BASE = "http://test"


@pytest.fixture
async def client():
    async with AsyncClient(transport=transport, base_url=BASE) as c:
        yield c


# ---------------------------------------------------------------------------
# Agent CRUD
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_agent(client: AsyncClient):
    payload = {
        "agent_id": "test-agent-1",
        "name": "Test Agent",
        "roles": ["reader"],
        "allowed_tools": ["read_*"],
        "risk_budget": 0.8,
        "session_limit": 50,
        "max_delegation_depth": 3,
    }
    res = await client.post("/v1/agents", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["agent_id"] == "test-agent-1"
    assert data["name"] == "Test Agent"
    assert data["roles"] == ["reader"]
    assert data["risk_budget"] == 0.8
    assert data["enabled"] is True


@pytest.mark.asyncio
async def test_create_duplicate_agent(client: AsyncClient):
    payload = {"agent_id": "dup-agent", "name": "Dup"}
    await client.post("/v1/agents", json=payload)
    res = await client.post("/v1/agents", json=payload)
    assert res.status_code == 409


@pytest.mark.asyncio
async def test_get_agent(client: AsyncClient):
    await client.post("/v1/agents", json={"agent_id": "get-me", "name": "GetMe"})
    res = await client.get("/v1/agents/get-me")
    assert res.status_code == 200
    assert res.json()["agent_id"] == "get-me"


@pytest.mark.asyncio
async def test_get_agent_not_found(client: AsyncClient):
    res = await client.get("/v1/agents/nonexistent")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_list_agents(client: AsyncClient):
    await client.post("/v1/agents", json={"agent_id": "a1", "name": "A1"})
    await client.post("/v1/agents", json={"agent_id": "a2", "name": "A2"})
    res = await client.get("/v1/agents")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 2
    ids = [a["agent_id"] for a in data["agents"]]
    assert "a1" in ids
    assert "a2" in ids


@pytest.mark.asyncio
async def test_list_agents_sorted(client: AsyncClient):
    await client.post("/v1/agents", json={"agent_id": "z-agent", "name": "Z"})
    await client.post("/v1/agents", json={"agent_id": "a-agent", "name": "A"})
    res = await client.get("/v1/agents?sort_by=agent_id&sort_dir=asc")
    data = res.json()
    ids = [a["agent_id"] for a in data["agents"]]
    assert ids == sorted(ids)


@pytest.mark.asyncio
async def test_update_agent(client: AsyncClient):
    await client.post("/v1/agents", json={"agent_id": "upd", "name": "Before"})
    res = await client.patch("/v1/agents/upd", json={"name": "After", "risk_budget": 0.5})
    assert res.status_code == 200
    assert res.json()["name"] == "After"
    assert res.json()["risk_budget"] == 0.5


@pytest.mark.asyncio
async def test_update_agent_not_found(client: AsyncClient):
    res = await client.patch("/v1/agents/nope", json={"name": "X"})
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_delete_agent(client: AsyncClient):
    await client.post("/v1/agents", json={"agent_id": "del-me", "name": "Del"})
    res = await client.delete("/v1/agents/del-me")
    assert res.status_code == 204
    res = await client.get("/v1/agents/del-me")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_delete_agent_not_found(client: AsyncClient):
    res = await client.delete("/v1/agents/nope")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# API Key Management (APEP-123)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_api_key(client: AsyncClient):
    await client.post("/v1/agents", json={"agent_id": "key-agent", "name": "Keys"})
    res = await client.post("/v1/agents/key-agent/keys?name=test-key")
    assert res.status_code == 201
    data = res.json()
    assert data["agent_id"] == "key-agent"
    assert data["name"] == "test-key"
    assert data["enabled"] is True
    assert data["plain_key"] is not None
    assert data["plain_key"].startswith("apk_")


@pytest.mark.asyncio
async def test_list_keys(client: AsyncClient):
    await client.post("/v1/agents", json={"agent_id": "list-key-agent", "name": "LK"})
    await client.post("/v1/agents/list-key-agent/keys?name=k1")
    await client.post("/v1/agents/list-key-agent/keys?name=k2")
    res = await client.get("/v1/agents/list-key-agent/keys")
    assert res.status_code == 200
    keys = res.json()["keys"]
    assert len(keys) >= 2
    # plain_key should NOT be in list response
    for k in keys:
        assert k.get("plain_key") is None


@pytest.mark.asyncio
async def test_rotate_key(client: AsyncClient):
    await client.post("/v1/agents", json={"agent_id": "rot-agent", "name": "Rot"})
    gen = await client.post("/v1/agents/rot-agent/keys?name=rotate-me")
    key_id = gen.json()["key_id"]

    res = await client.post(f"/v1/agents/rot-agent/keys/{key_id}/rotate")
    assert res.status_code == 200
    data = res.json()
    assert data["plain_key"] is not None
    assert data["key_id"] != key_id  # new key id

    # Old key should be disabled
    keys_res = await client.get("/v1/agents/rot-agent/keys")
    keys = keys_res.json()["keys"]
    old = [k for k in keys if k["key_id"] == key_id]
    assert len(old) == 1
    assert old[0]["enabled"] is False


@pytest.mark.asyncio
async def test_revoke_key(client: AsyncClient):
    await client.post("/v1/agents", json={"agent_id": "rev-agent", "name": "Rev"})
    gen = await client.post("/v1/agents/rev-agent/keys?name=revoke-me")
    key_id = gen.json()["key_id"]

    res = await client.delete(f"/v1/agents/rev-agent/keys/{key_id}")
    assert res.status_code == 204

    # Key should be disabled
    keys_res = await client.get("/v1/agents/rev-agent/keys")
    keys = keys_res.json()["keys"]
    revoked = [k for k in keys if k["key_id"] == key_id]
    assert len(revoked) == 1
    assert revoked[0]["enabled"] is False


@pytest.mark.asyncio
async def test_generate_key_agent_not_found(client: AsyncClient):
    res = await client.post("/v1/agents/nonexistent/keys?name=x")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Activity Timeline (APEP-124)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_activity_empty(client: AsyncClient):
    await client.post("/v1/agents", json={"agent_id": "act-agent", "name": "Act"})
    res = await client.get("/v1/agents/act-agent/activity")
    assert res.status_code == 200
    data = res.json()
    assert data["agent_id"] == "act-agent"
    assert data["entries"] == []
    assert data["total"] == 0


# ---------------------------------------------------------------------------
# Bulk Role Assignment (APEP-125)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_role_assignment(client: AsyncClient):
    await client.post("/v1/agents", json={"agent_id": "b1", "name": "B1"})
    await client.post("/v1/agents", json={"agent_id": "b2", "name": "B2"})

    res = await client.post(
        "/v1/agents/bulk/roles",
        json={"agent_ids": ["b1", "b2"], "roles": ["admin", "writer"]},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["updated"] == 2

    # Verify roles were assigned
    a1 = await client.get("/v1/agents/b1")
    assert set(a1.json()["roles"]) == {"admin", "writer"}
    a2 = await client.get("/v1/agents/b2")
    assert set(a2.json()["roles"]) == {"admin", "writer"}


# ---------------------------------------------------------------------------
# Delegation Chain (APEP-126)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delegations_empty(client: AsyncClient):
    await client.post("/v1/agents", json={"agent_id": "del-agent", "name": "Del"})
    res = await client.get("/v1/agents/del-agent/delegations")
    assert res.status_code == 200
    data = res.json()
    assert data["agent_id"] == "del-agent"
    assert isinstance(data["grants"], list)


@pytest.mark.asyncio
async def test_delegations_not_found(client: AsyncClient):
    res = await client.get("/v1/agents/ghost/delegations")
    assert res.status_code == 404
