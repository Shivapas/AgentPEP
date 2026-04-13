"""Tests for Sprint 33 OpenAI Agents SDK enhancements (APEP-259).

Tests execution token validation, receipt attachment, DEFER/MODIFY handling.
"""

import json

import pytest
import httpx
import respx

from agentpep.client import AgentPEPClient
from agentpep.exceptions import PolicyDeferredError, PolicyDeniedError
from agentpep.integrations.openai_agents import AgentPEPHooks, enforce_tool


MOCK_ALLOW = {
    "request_id": "00000000-0000-0000-0000-000000000001",
    "decision": "ALLOW",
    "risk_score": 0.1,
    "reason": "Allowed by policy",
    "latency_ms": 1,
}

MOCK_ALLOW_WITH_TOKEN = {
    **MOCK_ALLOW,
    "execution_token": "tok|dec1|sess|agent1|read_file|sess1|1|hmac|sig123",
    "receipt": "agentpep-receipt-v1|default|hmac-sha256|hash123|sig456",
}

MOCK_DEFER = {
    "request_id": "00000000-0000-0000-0000-000000000004",
    "decision": "DEFER",
    "reason": "Awaiting human approval for sensitive operation",
    "risk_score": 0.6,
    "latency_ms": 2,
    "defer_timeout_s": 30,
}

MOCK_MODIFY = {
    "request_id": "00000000-0000-0000-0000-000000000005",
    "decision": "MODIFY",
    "reason": "Arguments sanitized for safety",
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


@pytest.fixture
def client() -> AgentPEPClient:
    return AgentPEPClient(base_url="http://testserver:8000")


class TestExecutionTokenValidation:
    """APEP-259: Execution token validation on ALLOW."""

    @respx.mock
    async def test_on_tool_start_validates_execution_token(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_WITH_TOKEN)
        )

        hooks = AgentPEPHooks(client=client, agent_id="agent1")

        class FakeTool:
            name = "read_file"

        # Should not raise — token is valid
        await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())


class TestReceiptAttachment:
    """APEP-259: Receipt storage on ALLOW."""

    @respx.mock
    async def test_on_tool_start_attaches_receipt(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_WITH_TOKEN)
        )

        hooks = AgentPEPHooks(client=client, agent_id="agent1")

        class FakeTool:
            name = "read_file"

        await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())
        assert hooks._last_receipt == "agentpep-receipt-v1|default|hmac-sha256|hash123|sig456"

    @respx.mock
    async def test_receipt_cleared_after_tool_end(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW_WITH_TOKEN)
        )

        hooks = AgentPEPHooks(client=client, agent_id="agent1")

        class FakeTool:
            name = "read_file"

        await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())
        assert hooks._last_receipt is not None

        await hooks.on_tool_end(
            context=object(), agent=object(), tool=FakeTool(), result="ok"
        )
        assert hooks._last_receipt is None


class TestDeferHandling:
    """APEP-259: DEFER decision raises PolicyDeferredError."""

    @respx.mock
    async def test_on_tool_start_defer_raises(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DEFER)
        )

        hooks = AgentPEPHooks(client=client, agent_id="oai-agent")

        class FakeTool:
            name = "send_email"

        with pytest.raises(PolicyDeferredError) as exc_info:
            await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())

        assert exc_info.value.tool_name == "send_email"
        assert exc_info.value.defer_timeout_s == 30
        assert "human approval" in exc_info.value.reason

    @respx.mock
    async def test_enforce_tool_defer(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DEFER)
        )

        guard = enforce_tool(client, agent_id="oai-agent")
        with pytest.raises(PolicyDeferredError) as exc_info:
            await guard(tool_name="send_email", tool_args={"to": "user@example.com"})

        assert exc_info.value.defer_timeout_s == 30

    @respx.mock
    async def test_defer_triggers_on_decision_callback(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DEFER)
        )

        decisions: list = []
        hooks = AgentPEPHooks(
            client=client,
            agent_id="oai-agent",
            on_decision=decisions.append,
        )

        class FakeTool:
            name = "send_email"

        with pytest.raises(PolicyDeferredError):
            await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())

        assert len(decisions) == 1
        assert decisions[0].decision.value == "DEFER"


class TestModifyHandling:
    """APEP-259: MODIFY decision stores modified args."""

    @respx.mock
    async def test_on_tool_start_modify_stores_args(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_MODIFY)
        )

        hooks = AgentPEPHooks(client=client, agent_id="oai-agent")

        class FakeTool:
            name = "read_file"

        # Should NOT raise — MODIFY allows execution with modified args
        await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())
        assert hooks._pending_modified_args == {
            "path": "/safe/dir/file.txt",
            "mode": "read",
        }

    @respx.mock
    async def test_enforce_tool_modify_returns_response(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_MODIFY)
        )

        guard = enforce_tool(client, agent_id="oai-agent")
        response = await guard(
            tool_name="read_file", tool_args={"path": "/etc/shadow"}
        )
        assert response.decision.value == "MODIFY"
        assert response.modified_args == {"path": "/safe/dir/file.txt", "mode": "read"}

    @respx.mock
    async def test_modified_args_cleared_after_tool_end(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_MODIFY)
        )

        hooks = AgentPEPHooks(client=client, agent_id="oai-agent")

        class FakeTool:
            name = "read_file"

        await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())
        assert hooks._pending_modified_args is not None

        await hooks.on_tool_end(
            context=object(), agent=object(), tool=FakeTool(), result="ok"
        )
        assert hooks._pending_modified_args is None


class TestBackwardCompatibility:
    """Ensure responses without Sprint 33 fields still work."""

    @respx.mock
    async def test_response_without_new_fields(
        self, client: AgentPEPClient
    ) -> None:
        # Simulate an older server that doesn't return modified_args or defer_timeout_s
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        hooks = AgentPEPHooks(client=client, agent_id="oai-agent")

        class FakeTool:
            name = "read_file"

        # Should not raise
        await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())
        assert hooks._last_receipt is None
        assert hooks._pending_modified_args is None

    @respx.mock
    async def test_deny_still_raises(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )

        hooks = AgentPEPHooks(client=client, agent_id="oai-agent")

        class FakeTool:
            name = "delete_file"

        with pytest.raises(PolicyDeniedError):
            await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())
