"""Integration tests for Sprint 33 SDK features (APEP-266).

Full flows: DEFER/MODIFY through OpenAI hooks and LangGraph nodes,
token validation + receipt, and backward compatibility.
"""

import json

import pytest
import httpx
import respx

from agentpep.client import AgentPEPClient
from agentpep.exceptions import PolicyDeferredError, PolicyDeniedError
from agentpep.integrations.openai_agents import AgentPEPHooks, enforce_tool
from agentpep.integrations.langgraph import agentpep_pre_hook, enforce_tool_node
from agentpep.models import PolicyDecision, PolicyDecisionResponse


# ---------------------------------------------------------------------------
# Mock responses
# ---------------------------------------------------------------------------

MOCK_ALLOW = {
    "request_id": "00000000-0000-0000-0000-000000000001",
    "decision": "ALLOW",
    "risk_score": 0.1,
    "reason": "Allowed",
    "latency_ms": 1,
}

MOCK_ALLOW_WITH_TOKEN_RECEIPT = {
    "request_id": "00000000-0000-0000-0000-000000000001",
    "decision": "ALLOW",
    "risk_score": 0.2,
    "reason": "Allowed with token",
    "latency_ms": 1,
    "execution_token": "tok|dec1|sess|agent1|read_file|sess1|1|hmac|sig123",
    "receipt": "agentpep-receipt-v1|default|hmac-sha256|hash123|sig456",
}

MOCK_DEFER = {
    "request_id": "00000000-0000-0000-0000-000000000004",
    "decision": "DEFER",
    "reason": "Awaiting human approval",
    "risk_score": 0.6,
    "latency_ms": 2,
    "defer_timeout_s": 30,
}

MOCK_MODIFY = {
    "request_id": "00000000-0000-0000-0000-000000000005",
    "decision": "MODIFY",
    "reason": "Arguments sanitized",
    "risk_score": 0.4,
    "latency_ms": 1,
    "modified_args": {"path": "/safe/dir/file.txt", "mode": "read"},
}

MOCK_DENY = {
    "request_id": "00000000-0000-0000-0000-000000000002",
    "decision": "DENY",
    "reason": "Denied by RBAC",
    "risk_score": 0.9,
    "latency_ms": 1,
}

# Legacy response without new Sprint 33 fields
MOCK_ALLOW_LEGACY = {
    "request_id": "00000000-0000-0000-0000-000000000001",
    "decision": "ALLOW",
    "risk_score": 0.1,
    "reason": "Allowed",
    "latency_ms": 1,
}


@pytest.fixture
def client() -> AgentPEPClient:
    return AgentPEPClient(base_url="http://testserver:8000")


# ---------------------------------------------------------------------------
# OpenAI Agents: DEFER flow
# ---------------------------------------------------------------------------


class TestOpenAIDeferFlow:
    """Full DEFER flow through OpenAI Agents hooks."""

    @respx.mock
    async def test_hooks_defer_raises(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DEFER)
        )
        hooks = AgentPEPHooks(client, agent_id="test-agent")

        class FakeTool:
            name = "deploy_service"

        with pytest.raises(PolicyDeferredError) as exc_info:
            await hooks.on_tool_start(
                context=object(), agent=None, tool=FakeTool()
            )
        assert exc_info.value.defer_timeout_s == 30
        assert "deploy_service" in str(exc_info.value)

    @respx.mock
    async def test_enforce_tool_defer_raises(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DEFER)
        )
        guard = enforce_tool(client, agent_id="test-agent")
        with pytest.raises(PolicyDeferredError) as exc_info:
            await guard(
                tool_name="deploy_service",
                tool_args={"env": "prod"},
            )
        assert exc_info.value.defer_timeout_s == 30


# ---------------------------------------------------------------------------
# OpenAI Agents: MODIFY flow
# ---------------------------------------------------------------------------


class TestOpenAIModifyFlow:
    """Full MODIFY flow through OpenAI Agents hooks."""

    @respx.mock
    async def test_hooks_modify_stores_args(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_MODIFY)
        )
        hooks = AgentPEPHooks(client, agent_id="test-agent")

        class FakeTool:
            name = "read_file"

        await hooks.on_tool_start(
            context=object(), agent=None, tool=FakeTool()
        )
        assert hooks._pending_modified_args == {"path": "/safe/dir/file.txt", "mode": "read"}

    @respx.mock
    async def test_enforce_tool_modify_returns_args(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_MODIFY)
        )
        guard = enforce_tool(client, agent_id="test-agent")
        resp = await guard(
            tool_name="read_file",
            tool_args={"path": "/etc/passwd"},
        )
        assert resp.decision == PolicyDecision.MODIFY
        assert resp.modified_args == {"path": "/safe/dir/file.txt", "mode": "read"}


# ---------------------------------------------------------------------------
# LangGraph: MODIFY flow
# ---------------------------------------------------------------------------


class TestLangGraphModifyFlow:
    """Full MODIFY flow through LangGraph nodes."""

    @respx.mock
    async def test_pre_hook_modify_rewrites_state(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_MODIFY)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="read_file")
        state = {"tool_args": {"path": "/etc/passwd"}}
        result = await hook(state)
        assert result["agentpep_decision"] == "MODIFY"
        assert result["tool_args"] == {"path": "/safe/dir/file.txt", "mode": "read"}
        assert result.get("agentpep_args_modified") is True

    @respx.mock
    async def test_enforce_tool_node_modify_rewrites_tc(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_MODIFY)
        )

        class FakeMessage:
            tool_calls = [{"name": "read_file", "args": {"path": "/etc/passwd"}}]

        node = enforce_tool_node(client, agent_id="lg-agent")
        state = {"messages": [FakeMessage()]}
        result = await node(state)

        # Verify args were rewritten in-place
        assert FakeMessage.tool_calls[0]["args"] == {"path": "/safe/dir/file.txt", "mode": "read"}


# ---------------------------------------------------------------------------
# LangGraph: DEFER flow
# ---------------------------------------------------------------------------


class TestLangGraphDeferFlow:
    """Full DEFER flow through LangGraph nodes."""

    @respx.mock
    async def test_pre_hook_defer_raises(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DEFER)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="deploy_service")
        state = {"tool_args": {"env": "prod"}}
        with pytest.raises(PolicyDeferredError) as exc_info:
            await hook(state)
        assert exc_info.value.defer_timeout_s == 30

    @respx.mock
    async def test_enforce_tool_node_defer_raises(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DEFER)
        )

        class FakeMessage:
            tool_calls = [{"name": "deploy_service", "args": {"env": "prod"}}]

        node = enforce_tool_node(client, agent_id="lg-agent")
        state = {"messages": [FakeMessage()]}
        with pytest.raises(PolicyDeferredError):
            await node(state)


# ---------------------------------------------------------------------------
# Token validation + receipt
# ---------------------------------------------------------------------------


class TestTokenReceiptFlow:
    """Token validation and receipt attachment through hooks."""

    @respx.mock
    async def test_hooks_attach_receipt_on_allow(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_WITH_TOKEN_RECEIPT)
        )
        hooks = AgentPEPHooks(client, agent_id="test-agent")

        class FakeTool:
            name = "read_file"

        await hooks.on_tool_start(context=object(), agent=None, tool=FakeTool())
        assert hooks._last_receipt is not None
        assert "agentpep-receipt-v1" in hooks._last_receipt

    @respx.mock
    async def test_langgraph_receipt_in_state(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_WITH_TOKEN_RECEIPT)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="read_file")
        state = {"tool_args": {"path": "/tmp/data"}}
        result = await hook(state)
        assert result["agentpep_decision"] == "ALLOW"
        assert result.get("agentpep_receipt") is not None


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Ensure old server responses (without new fields) still work."""

    @respx.mock
    async def test_legacy_allow_response_works(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_LEGACY)
        )
        hooks = AgentPEPHooks(client, agent_id="test-agent")

        class FakeTool:
            name = "safe_tool"

        await hooks.on_tool_start(context=object(), agent=None, tool=FakeTool())
        assert hooks._last_receipt is None
        assert hooks._pending_modified_args is None

    @respx.mock
    async def test_legacy_response_langgraph(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_LEGACY)
        )
        hook = agentpep_pre_hook(client, agent_id="lg-agent", tool_name="safe_tool")
        state = {"tool_args": {}}
        result = await hook(state)
        assert result["agentpep_decision"] == "ALLOW"
        assert result.get("agentpep_args_modified") is None

    def test_policy_decision_response_defaults(self) -> None:
        """Response model defaults for new fields."""
        resp = PolicyDecisionResponse(
            request_id="00000000-0000-0000-0000-000000000001",
            decision="ALLOW",
            reason="ok",
        )
        assert resp.modified_args is None
        assert resp.defer_timeout_s == 60

    def test_old_decisions_still_parse(self) -> None:
        for d in ["ALLOW", "DENY", "ESCALATE", "DRY_RUN", "TIMEOUT"]:
            resp = PolicyDecisionResponse(
                request_id="00000000-0000-0000-0000-000000000001",
                decision=d,
                reason="test",
            )
            assert resp.decision.value == d
