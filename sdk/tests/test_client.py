"""Tests for AgentPEPClient — async and sync (APEP-030, APEP-036)."""

import pytest
import httpx
import respx

from agentpep.client import AgentPEPClient
from agentpep.exceptions import (
    AgentPEPConnectionError,
    AgentPEPTimeoutError,
    PolicyDeniedError,
)
from agentpep.models import PolicyDecision


MOCK_ALLOW_RESPONSE = {
    "request_id": "00000000-0000-0000-0000-000000000001",
    "decision": "ALLOW",
    "matched_rule_id": None,
    "risk_score": 0.1,
    "taint_flags": [],
    "reason": "Allowed by rule",
    "escalation_id": None,
    "latency_ms": 5,
}

MOCK_DENY_RESPONSE = {
    "request_id": "00000000-0000-0000-0000-000000000002",
    "decision": "DENY",
    "matched_rule_id": None,
    "risk_score": 0.0,
    "taint_flags": [],
    "reason": "No matching rule — deny by default",
    "escalation_id": None,
    "latency_ms": 3,
}


@pytest.fixture
def client() -> AgentPEPClient:
    return AgentPEPClient(base_url="http://testserver:8000", api_key="test-key")


@pytest.fixture
def fail_open_client() -> AgentPEPClient:
    return AgentPEPClient(base_url="http://testserver:8000", fail_open=True)


class TestAsyncEvaluate:
    @respx.mock
    async def test_evaluate_allow(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_RESPONSE)
        )
        response = await client.evaluate(
            agent_id="agent-1",
            tool_name="read_file",
            tool_args={"path": "/tmp/test.txt"},
        )
        assert response.decision == PolicyDecision.ALLOW
        assert response.risk_score == 0.1

    @respx.mock
    async def test_evaluate_deny(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY_RESPONSE)
        )
        response = await client.evaluate(
            agent_id="agent-1",
            tool_name="delete_db",
        )
        assert response.decision == PolicyDecision.DENY

    @respx.mock
    async def test_evaluate_timeout_fail_closed(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            side_effect=httpx.ReadTimeout("timeout")
        )
        with pytest.raises(AgentPEPTimeoutError):
            await client.evaluate(agent_id="agent-1", tool_name="read_file")

    @respx.mock
    async def test_evaluate_timeout_fail_open(self, fail_open_client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            side_effect=httpx.ReadTimeout("timeout")
        )
        response = await fail_open_client.evaluate(agent_id="agent-1", tool_name="read_file")
        assert response.decision == PolicyDecision.ALLOW
        assert "fail_open" in response.reason

    @respx.mock
    async def test_evaluate_connection_error_fail_closed(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            side_effect=httpx.ConnectError("refused")
        )
        with pytest.raises(AgentPEPConnectionError):
            await client.evaluate(agent_id="agent-1", tool_name="read_file")

    @respx.mock
    async def test_evaluate_connection_error_fail_open(
        self, fail_open_client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            side_effect=httpx.ConnectError("refused")
        )
        response = await fail_open_client.evaluate(agent_id="agent-1", tool_name="read_file")
        assert response.decision == PolicyDecision.ALLOW

    @respx.mock
    async def test_enforce_allow(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_RESPONSE)
        )
        response = await client.enforce(agent_id="agent-1", tool_name="read_file")
        assert response.decision == PolicyDecision.ALLOW

    @respx.mock
    async def test_enforce_deny_raises(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY_RESPONSE)
        )
        with pytest.raises(PolicyDeniedError) as exc_info:
            await client.enforce(agent_id="agent-1", tool_name="delete_db")
        assert exc_info.value.tool_name == "delete_db"
        assert exc_info.value.decision == "DENY"

    @respx.mock
    async def test_api_key_header_sent(self, client: AgentPEPClient) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_RESPONSE)
        )
        await client.evaluate(agent_id="agent-1", tool_name="read_file")
        assert route.calls[0].request.headers["X-API-Key"] == "test-key"


class TestSyncEvaluate:
    @respx.mock
    def test_evaluate_sync_allow(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_RESPONSE)
        )
        response = client.evaluate_sync(
            agent_id="agent-1",
            tool_name="read_file",
        )
        assert response.decision == PolicyDecision.ALLOW

    @respx.mock
    def test_evaluate_sync_deny(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY_RESPONSE)
        )
        response = client.evaluate_sync(agent_id="agent-1", tool_name="delete_db")
        assert response.decision == PolicyDecision.DENY

    @respx.mock
    def test_enforce_sync_deny_raises(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY_RESPONSE)
        )
        with pytest.raises(PolicyDeniedError):
            client.enforce_sync(agent_id="agent-1", tool_name="delete_db")

    @respx.mock
    def test_sync_timeout_fail_open(self, fail_open_client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            side_effect=httpx.ReadTimeout("timeout")
        )
        response = fail_open_client.evaluate_sync(agent_id="agent-1", tool_name="read_file")
        assert response.decision == PolicyDecision.ALLOW

    @respx.mock
    def test_sync_connection_error_fail_closed(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            side_effect=httpx.ConnectError("refused")
        )
        with pytest.raises(AgentPEPConnectionError):
            client.evaluate_sync(agent_id="agent-1", tool_name="read_file")
