"""Tests for AgentPEPClient health_check methods (APEP-215 friction #10)."""

import httpx
import pytest
import respx

from agentpep.client import AgentPEPClient
from agentpep.exceptions import AgentPEPConnectionError


@respx.mock
async def test_health_check_async():
    respx.get("http://localhost:8000/health").mock(
        return_value=httpx.Response(200, json={"status": "ok", "version": "0.1.0"})
    )
    client = AgentPEPClient(base_url="http://localhost:8000")
    result = await client.health_check()
    assert result["status"] == "ok"
    assert result["version"] == "0.1.0"
    await client.aclose()


@respx.mock
async def test_health_check_connection_error():
    respx.get("http://localhost:8000/health").mock(side_effect=httpx.ConnectError("refused"))
    client = AgentPEPClient(base_url="http://localhost:8000")
    with pytest.raises(AgentPEPConnectionError):
        await client.health_check()
    await client.aclose()
