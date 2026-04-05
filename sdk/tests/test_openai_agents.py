"""Tests for OpenAI Agents SDK integration (APEP-158, APEP-159, APEP-160)."""

import json

import pytest
import httpx
import respx

from agentpep.client import AgentPEPClient
from agentpep.exceptions import PolicyDeniedError
from agentpep.integrations.openai_agents import (
    AgentPEPHooks,
    enforce_tool,
    map_openai_tool_call,
)


MOCK_ALLOW = {
    "request_id": "00000000-0000-0000-0000-000000000001",
    "decision": "ALLOW",
    "risk_score": 0.1,
    "reason": "Allowed by policy",
    "latency_ms": 1,
}

MOCK_DENY = {
    "request_id": "00000000-0000-0000-0000-000000000002",
    "decision": "DENY",
    "reason": "Denied by RBAC rule: no file-delete for reader role",
    "risk_score": 0.9,
    "latency_ms": 1,
}

MOCK_ESCALATE = {
    "request_id": "00000000-0000-0000-0000-000000000003",
    "decision": "ESCALATE",
    "reason": "Taint check triggered escalation",
    "risk_score": 0.7,
    "latency_ms": 2,
}


@pytest.fixture
def client() -> AgentPEPClient:
    return AgentPEPClient(base_url="http://testserver:8000")


# --- APEP-159: map_openai_tool_call ---


class TestMapOpenAIToolCall:
    def test_function_tool_with_json_string_args(self) -> None:
        class FakeTool:
            name = "send_email"

        tool = FakeTool()
        args_json = json.dumps({"to": "user@example.com", "body": "Hello"})
        name, args = map_openai_tool_call(tool, args_json)

        assert name == "send_email"
        assert args == {"to": "user@example.com", "body": "Hello"}

    def test_function_tool_with_dict_args(self) -> None:
        class FakeTool:
            name = "read_file"

        name, args = map_openai_tool_call(FakeTool(), {"path": "/tmp/data.txt"})
        assert name == "read_file"
        assert args == {"path": "/tmp/data.txt"}

    def test_tool_without_name_uses_class_name(self) -> None:
        class CustomSearchTool:
            pass

        name, args = map_openai_tool_call(CustomSearchTool(), {"query": "test"})
        assert name == "CustomSearchTool"
        assert args == {"query": "test"}

    def test_empty_json_string(self) -> None:
        class FakeTool:
            name = "noop"

        name, args = map_openai_tool_call(FakeTool(), "")
        assert name == "noop"
        assert args == {}

    def test_invalid_json_string_wrapped(self) -> None:
        class FakeTool:
            name = "raw_tool"

        name, args = map_openai_tool_call(FakeTool(), "not-json")
        assert name == "raw_tool"
        assert args == {"raw_input": "not-json"}

    def test_non_string_non_dict_wrapped(self) -> None:
        class FakeTool:
            name = "num_tool"

        name, args = map_openai_tool_call(FakeTool(), 42)
        assert name == "num_tool"
        assert args == {"raw_input": "42"}


# --- APEP-158: AgentPEPHooks ---


class TestAgentPEPHooks:
    @respx.mock
    async def test_on_tool_start_allow(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        hooks = AgentPEPHooks(client=client, agent_id="oai-agent")

        class FakeTool:
            name = "read_file"

        # Should not raise
        await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())

    @respx.mock
    async def test_on_tool_start_deny_raises(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )

        hooks = AgentPEPHooks(client=client, agent_id="oai-agent")

        class FakeTool:
            name = "delete_file"

        with pytest.raises(PolicyDeniedError) as exc_info:
            await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())

        assert exc_info.value.tool_name == "delete_file"
        assert "RBAC" in exc_info.value.reason

    @respx.mock
    async def test_on_tool_start_escalate_raises(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ESCALATE)
        )

        hooks = AgentPEPHooks(client=client, agent_id="oai-agent")

        class FakeTool:
            name = "web_search"

        with pytest.raises(PolicyDeniedError):
            await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())

    @respx.mock
    async def test_on_tool_start_sends_correct_payload(
        self, client: AgentPEPClient
    ) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        hooks = AgentPEPHooks(
            client=client,
            agent_id="oai-agent",
            session_id="sess-42",
            delegation_chain=["orchestrator", "oai-agent"],
        )

        class FakeTool:
            name = "send_email"

        await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())

        body = json.loads(route.calls[0].request.content)
        assert body["agent_id"] == "oai-agent"
        assert body["tool_name"] == "send_email"
        assert body["session_id"] == "sess-42"
        assert body["delegation_chain"] == ["orchestrator", "oai-agent"]

    @respx.mock
    async def test_on_tool_start_with_tool_input_context(
        self, client: AgentPEPClient
    ) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        hooks = AgentPEPHooks(client=client, agent_id="oai-agent")

        class FakeTool:
            name = "send_email"

        class FakeContext:
            tool_input = json.dumps({"to": "admin@example.com"})

        await hooks.on_tool_start(
            context=FakeContext(), agent=object(), tool=FakeTool()
        )

        body = json.loads(route.calls[0].request.content)
        assert body["tool_args"] == {"to": "admin@example.com"}

    @respx.mock
    async def test_on_decision_callback(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        decisions: list = []
        hooks = AgentPEPHooks(
            client=client,
            agent_id="oai-agent",
            on_decision=decisions.append,
        )

        class FakeTool:
            name = "read_file"

        await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())
        assert len(decisions) == 1
        assert decisions[0].decision.value == "ALLOW"

    async def test_noop_hooks(self, client: AgentPEPClient) -> None:
        hooks = AgentPEPHooks(client=client, agent_id="oai-agent")
        # These should be no-ops
        await hooks.on_tool_end(context=object(), agent=object(), tool=object(), result="ok")
        await hooks.on_start(context=object(), agent=object())
        await hooks.on_end(context=object(), agent=object(), output="done")
        await hooks.on_handoff(context=object(), agent=object(), source=object())


# --- APEP-160: RBAC integration test scenarios ---


class TestOpenAIRBACIntegration:
    """Integration tests: OpenAI agent tool calls intercepted/denied by RBAC rules."""

    @respx.mock
    async def test_reader_role_denied_write_tool(self, client: AgentPEPClient) -> None:
        """A reader-role agent is denied access to a write tool."""
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(
                200,
                json={
                    "request_id": "00000000-0000-0000-0000-000000000010",
                    "decision": "DENY",
                    "reason": "Role 'reader' not permitted for tool 'write_file'",
                    "risk_score": 0.8,
                    "latency_ms": 2,
                },
            )
        )

        hooks = AgentPEPHooks(client=client, agent_id="reader-agent")

        class WriteFileTool:
            name = "write_file"

        with pytest.raises(PolicyDeniedError) as exc_info:
            await hooks.on_tool_start(
                context=object(), agent=object(), tool=WriteFileTool()
            )
        assert exc_info.value.tool_name == "write_file"
        assert exc_info.value.decision == "DENY"

    @respx.mock
    async def test_admin_role_allowed_write_tool(self, client: AgentPEPClient) -> None:
        """An admin-role agent is allowed access to the same write tool."""
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        hooks = AgentPEPHooks(client=client, agent_id="admin-agent")

        class WriteFileTool:
            name = "write_file"

        # Should not raise
        await hooks.on_tool_start(
            context=object(), agent=object(), tool=WriteFileTool()
        )

    @respx.mock
    async def test_tool_call_with_blocked_arguments(
        self, client: AgentPEPClient
    ) -> None:
        """Tool call denied due to argument validation (e.g. blocked path)."""
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(
                200,
                json={
                    "request_id": "00000000-0000-0000-0000-000000000011",
                    "decision": "DENY",
                    "reason": "Argument 'path' matched blocklist pattern '/etc/*'",
                    "risk_score": 0.95,
                    "latency_ms": 3,
                },
            )
        )

        guard = enforce_tool(client, agent_id="sandbox-agent")
        with pytest.raises(PolicyDeniedError) as exc_info:
            await guard(
                tool_name="read_file",
                tool_args={"path": "/etc/shadow"},
            )
        assert exc_info.value.decision == "DENY"

    @respx.mock
    async def test_multiple_tool_calls_mixed_decisions(
        self, client: AgentPEPClient
    ) -> None:
        """Simulate a sequence of tool calls where some are allowed, others denied."""
        responses = [
            httpx.Response(200, json=MOCK_ALLOW),
            httpx.Response(200, json=MOCK_DENY),
            httpx.Response(200, json=MOCK_ALLOW),
        ]
        respx.post("http://testserver:8000/v1/intercept").mock(side_effect=responses)

        hooks = AgentPEPHooks(client=client, agent_id="mixed-agent")

        class AllowedTool:
            name = "read_file"

        class DeniedTool:
            name = "delete_file"

        class AllowedTool2:
            name = "list_files"

        # First: allowed
        await hooks.on_tool_start(context=object(), agent=object(), tool=AllowedTool())

        # Second: denied
        with pytest.raises(PolicyDeniedError):
            await hooks.on_tool_start(
                context=object(), agent=object(), tool=DeniedTool()
            )

        # Third: allowed again
        await hooks.on_tool_start(context=object(), agent=object(), tool=AllowedTool2())

    @respx.mock
    async def test_delegation_chain_deny(self, client: AgentPEPClient) -> None:
        """Tool call denied because delegation chain is too deep / unauthorized."""
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(
                200,
                json={
                    "request_id": "00000000-0000-0000-0000-000000000012",
                    "decision": "DENY",
                    "reason": "Delegation chain exceeds max depth",
                    "risk_score": 1.0,
                    "latency_ms": 5,
                },
            )
        )

        hooks = AgentPEPHooks(
            client=client,
            agent_id="deep-agent",
            delegation_chain=["a", "b", "c", "d", "e", "deep-agent"],
        )

        class SomeTool:
            name = "execute_query"

        with pytest.raises(PolicyDeniedError):
            await hooks.on_tool_start(
                context=object(), agent=object(), tool=SomeTool()
            )

    @respx.mock
    async def test_dry_run_allows_execution(self, client: AgentPEPClient) -> None:
        """DRY_RUN decision should not block tool execution."""
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(
                200,
                json={
                    "request_id": "00000000-0000-0000-0000-000000000013",
                    "decision": "DRY_RUN",
                    "reason": "Dry run mode active",
                    "risk_score": 0.5,
                    "latency_ms": 1,
                },
            )
        )

        hooks = AgentPEPHooks(client=client, agent_id="dryrun-agent")

        class FakeTool:
            name = "send_email"

        # Should not raise
        await hooks.on_tool_start(context=object(), agent=object(), tool=FakeTool())
