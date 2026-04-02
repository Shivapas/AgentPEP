"""Tests for @enforce decorator (APEP-031, APEP-036)."""

import pytest
import httpx
import respx

from agentpep.client import AgentPEPClient
from agentpep.decorator import enforce
from agentpep.exceptions import PolicyDeniedError
from agentpep.models import PolicyDecision
from agentpep.offline import OfflineEvaluator, OfflineRule


MOCK_ALLOW = {
    "request_id": "00000000-0000-0000-0000-000000000001",
    "decision": "ALLOW",
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


class TestAsyncEnforceDecorator:
    @respx.mock
    async def test_async_function_allowed(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        @enforce(client, agent_id="test-agent")
        async def my_tool(x: int) -> int:
            return x * 2

        result = await my_tool(x=5)
        assert result == 10

    @respx.mock
    async def test_async_function_denied(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )

        call_count = 0

        @enforce(client, agent_id="test-agent")
        async def dangerous_tool() -> None:
            nonlocal call_count
            call_count += 1

        with pytest.raises(PolicyDeniedError):
            await dangerous_tool()

        assert call_count == 0, "Function should not execute when denied"

    @respx.mock
    async def test_custom_tool_name(self, client: AgentPEPClient) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        @enforce(client, agent_id="test-agent", tool_name="custom_name")
        async def my_tool() -> str:
            return "ok"

        await my_tool()
        body = route.calls[0].request.content
        assert b"custom_name" in body


class TestSyncEnforceDecorator:
    @respx.mock
    def test_sync_function_allowed(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        @enforce(client, agent_id="test-agent")
        def my_sync_tool(x: int) -> int:
            return x + 1

        result = my_sync_tool(x=3)
        assert result == 4

    @respx.mock
    def test_sync_function_denied(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )

        @enforce(client, agent_id="test-agent")
        def my_sync_tool() -> None:
            pass

        with pytest.raises(PolicyDeniedError):
            my_sync_tool()


class TestOfflineEnforceDecorator:
    def test_offline_sync_allow(self) -> None:
        evaluator = OfflineEvaluator(
            rules=[OfflineRule(tool_pattern="read_*", action=PolicyDecision.ALLOW)]
        )

        @enforce(evaluator, agent_id="test-agent")
        def read_file(path: str) -> str:
            return f"content of {path}"

        result = read_file(path="/tmp/test")
        assert result == "content of /tmp/test"

    def test_offline_sync_deny(self) -> None:
        evaluator = OfflineEvaluator(
            rules=[OfflineRule(tool_pattern="delete_*", action=PolicyDecision.DENY)]
        )

        @enforce(evaluator, agent_id="test-agent")
        def delete_file(path: str) -> None:
            pass

        with pytest.raises(PolicyDeniedError):
            delete_file(path="/etc/important")

    async def test_offline_async_allow(self) -> None:
        evaluator = OfflineEvaluator(
            rules=[OfflineRule(tool_pattern="*", action=PolicyDecision.ALLOW)]
        )

        @enforce(evaluator, agent_id="test-agent")
        async def async_tool() -> str:
            return "executed"

        result = await async_tool()
        assert result == "executed"

    async def test_offline_async_deny_default(self) -> None:
        evaluator = OfflineEvaluator(rules=[])  # No rules → deny by default

        @enforce(evaluator, agent_id="test-agent")
        async def async_tool() -> str:
            return "should not run"

        with pytest.raises(PolicyDeniedError):
            await async_tool()
