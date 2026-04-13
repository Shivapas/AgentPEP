"""Tests for Sprint 33 LangGraph enhancements (APEP-260).

Tests trust degradation injection, MODIFY arg rewriting, DEFER handling.
"""

import pytest
import httpx
import respx

from agentpep.client import AgentPEPClient
from agentpep.exceptions import PolicyDeferredError, PolicyDeniedError
from agentpep.integrations.langgraph import agentpep_pre_hook, enforce_tool_node


MOCK_ALLOW_LOW_RISK = {
    "request_id": "00000000-0000-0000-0000-000000000001",
    "decision": "ALLOW",
    "risk_score": 0.1,
    "reason": "Allowed",
    "latency_ms": 1,
    "taint_flags": [],
}

MOCK_ALLOW_HIGH_RISK = {
    "request_id": "00000000-0000-0000-0000-000000000002",
    "decision": "ALLOW",
    "risk_score": 0.8,
    "reason": "Allowed with elevated risk",
    "latency_ms": 1,
    "taint_flags": ["UNTRUSTED"],
    "execution_token": "tok|d1|s1|a1|t1|s|1|hmac|sig",
    "receipt": "agentpep-receipt-v1|default|hmac-sha256|h|s",
}

MOCK_DEFER = {
    "request_id": "00000000-0000-0000-0000-000000000003",
    "decision": "DEFER",
    "reason": "Pending approval",
    "risk_score": 0.6,
    "latency_ms": 2,
    "defer_timeout_s": 45,
}

MOCK_MODIFY = {
    "request_id": "00000000-0000-0000-0000-000000000004",
    "decision": "MODIFY",
    "reason": "Path sanitized",
    "risk_score": 0.3,
    "latency_ms": 1,
    "modified_args": {"path": "/safe/output.txt"},
}

MOCK_DENY = {
    "request_id": "00000000-0000-0000-0000-000000000005",
    "decision": "DENY",
    "reason": "Denied",
    "latency_ms": 1,
}


@pytest.fixture
def client() -> AgentPEPClient:
    return AgentPEPClient(base_url="http://testserver:8000")


class TestPreHookTrustDegradation:
    """APEP-260: Trust degradation context injection."""

    @respx.mock
    async def test_high_risk_injects_trust_degradation(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_HIGH_RISK)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="web_search")
        state = {"tool_args": {"query": "test"}}

        result = await hook(state)
        assert result["agentpep_trust_degraded"] is True
        assert result["agentpep_taint_flags"] == ["UNTRUSTED"]
        assert result["agentpep_decision"] == "ALLOW"
        assert result["agentpep_risk_score"] == 0.8

    @respx.mock
    async def test_low_risk_no_trust_degradation(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_LOW_RISK)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="read_file")
        state = {"tool_args": {}}

        result = await hook(state)
        assert "agentpep_trust_degraded" not in result
        assert result["agentpep_decision"] == "ALLOW"

    @respx.mock
    async def test_execution_token_and_receipt_in_state(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_HIGH_RISK)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="tool")
        state = {}

        result = await hook(state)
        assert result["agentpep_execution_token"] == "tok|d1|s1|a1|t1|s|1|hmac|sig"
        assert result["agentpep_receipt"] == "agentpep-receipt-v1|default|hmac-sha256|h|s"


class TestPreHookModify:
    """APEP-260: MODIFY decision rewrites tool args in state."""

    @respx.mock
    async def test_modify_rewrites_tool_args(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_MODIFY)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="write_file")
        state = {"tool_args": {"path": "/etc/passwd"}}

        result = await hook(state)
        assert result["tool_args"] == {"path": "/safe/output.txt"}
        assert result["agentpep_decision"] == "MODIFY"
        assert result["agentpep_args_modified"] is True
        assert result["agentpep_risk_score"] == 0.3

    @respx.mock
    async def test_modify_preserves_other_state(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_MODIFY)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="write_file")
        state = {"tool_args": {"path": "/etc/passwd"}, "other_key": "preserved"}

        result = await hook(state)
        assert result["other_key"] == "preserved"
        assert result["tool_args"] == {"path": "/safe/output.txt"}


class TestPreHookDefer:
    """APEP-260: DEFER decision raises PolicyDeferredError."""

    @respx.mock
    async def test_defer_raises(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DEFER)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="deploy")
        state = {}

        with pytest.raises(PolicyDeferredError) as exc_info:
            await hook(state)

        assert exc_info.value.tool_name == "deploy"
        assert exc_info.value.defer_timeout_s == 45
        assert "approval" in exc_info.value.reason


class TestEnforceToolNodeModify:
    """APEP-260: MODIFY rewrites tool call args in messages."""

    @respx.mock
    async def test_modify_rewrites_message_args(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_MODIFY)
        )

        class FakeMessage:
            tool_calls = [{"name": "write_file", "args": {"path": "/etc/passwd"}}]

        guard = enforce_tool_node(client, agent_id="lg-agent")
        state = {"messages": [FakeMessage()]}
        result = await guard(state)

        # Verify args were rewritten in-place
        assert FakeMessage.tool_calls[0]["args"] == {"path": "/safe/output.txt"}

    @respx.mock
    async def test_defer_raises_in_enforce_tool_node(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DEFER)
        )

        class FakeMessage:
            tool_calls = [{"name": "deploy_app", "args": {}}]

        guard = enforce_tool_node(client, agent_id="lg-agent")
        state = {"messages": [FakeMessage()]}

        with pytest.raises(PolicyDeferredError):
            await guard(state)


class TestBackwardCompatibility:
    """Ensure existing ALLOW/DENY behavior unchanged."""

    @respx.mock
    async def test_allow_still_works(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_LOW_RISK)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="tool")
        state = {"tool_args": {}}

        result = await hook(state)
        assert result["agentpep_decision"] == "ALLOW"

    @respx.mock
    async def test_deny_still_raises(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="tool")

        with pytest.raises(PolicyDeniedError):
            await hook({})
