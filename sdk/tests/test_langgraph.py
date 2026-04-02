"""Tests for LangGraph integration (APEP-034, APEP-036)."""

import pytest
import httpx
import respx

from agentpep.client import AgentPEPClient
from agentpep.exceptions import PolicyDeniedError
from agentpep.integrations.langgraph import agentpep_pre_hook, enforce_tool_node


MOCK_ALLOW = {
    "request_id": "00000000-0000-0000-0000-000000000001",
    "decision": "ALLOW",
    "risk_score": 0.1,
    "reason": "Allowed",
    "latency_ms": 1,
}

MOCK_DENY = {
    "request_id": "00000000-0000-0000-0000-000000000002",
    "decision": "DENY",
    "reason": "Denied by policy",
    "latency_ms": 1,
}


@pytest.fixture
def client() -> AgentPEPClient:
    return AgentPEPClient(base_url="http://testserver:8000")


class TestPreHook:
    @respx.mock
    async def test_pre_hook_allow(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="send_email")
        state = {"tool_args": {"to": "user@example.com"}}

        result = await hook(state)
        assert result["agentpep_decision"] == "ALLOW"
        assert result["agentpep_risk_score"] == 0.1

    @respx.mock
    async def test_pre_hook_deny(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="delete_all")
        state = {}

        with pytest.raises(PolicyDeniedError):
            await hook(state)

    @respx.mock
    async def test_pre_hook_reads_tool_name_from_state(self, client: AgentPEPClient) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent")
        state = {"tool_name": "dynamic_tool", "tool_args": {}}

        await hook(state)
        body = route.calls[0].request.content
        assert b"dynamic_tool" in body


class TestEnforceToolNode:
    @respx.mock
    async def test_guard_no_messages_passthrough(self, client: AgentPEPClient) -> None:
        guard = enforce_tool_node(client, agent_id="lg-agent")
        state: dict = {"messages": []}
        result = await guard(state)
        assert result == state

    @respx.mock
    async def test_guard_with_tool_call_allow(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        class FakeMessage:
            tool_calls = [{"name": "read_file", "args": {"path": "/tmp"}}]

        guard = enforce_tool_node(client, agent_id="lg-agent")
        state = {"messages": [FakeMessage()]}
        result = await guard(state)
        assert result == state

    @respx.mock
    async def test_guard_with_tool_call_deny(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )

        class FakeMessage:
            tool_calls = [{"name": "delete_db", "args": {}}]

        guard = enforce_tool_node(client, agent_id="lg-agent")
        state = {"messages": [FakeMessage()]}

        with pytest.raises(PolicyDeniedError):
            await guard(state)
