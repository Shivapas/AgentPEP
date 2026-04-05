"""Tests for AutoGen integration (APEP-161, APEP-162, APEP-163)."""

import json
from typing import Any

import pytest
import httpx
import respx

from agentpep.client import AgentPEPClient
from agentpep.exceptions import PolicyDeniedError
from agentpep.integrations.autogen import (
    AgentPEPSpeakerHook,
    AgentPEPStudioPlugin,
    map_autogen_tool_call,
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
    "reason": "Denied by RBAC rule",
    "risk_score": 0.9,
    "latency_ms": 1,
}

MOCK_ESCALATE = {
    "request_id": "00000000-0000-0000-0000-000000000003",
    "decision": "ESCALATE",
    "reason": "Confused-deputy detected: unauthorized delegation",
    "risk_score": 0.85,
    "latency_ms": 3,
}


@pytest.fixture
def client() -> AgentPEPClient:
    return AgentPEPClient(base_url="http://testserver:8000")


# --- map_autogen_tool_call ---


class TestMapAutogenToolCall:
    def test_openai_style_tool_calls(self) -> None:
        message = {
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "send_email",
                        "arguments": json.dumps({"to": "user@example.com"}),
                    },
                }
            ]
        }
        result = map_autogen_tool_call(message)
        assert len(result) == 1
        assert result[0] == ("send_email", {"to": "user@example.com"})

    def test_multiple_tool_calls(self) -> None:
        message = {
            "tool_calls": [
                {
                    "function": {"name": "read_file", "arguments": '{"path": "/tmp"}'}
                },
                {
                    "function": {
                        "name": "write_file",
                        "arguments": '{"path": "/tmp/out", "content": "data"}',
                    }
                },
            ]
        }
        result = map_autogen_tool_call(message)
        assert len(result) == 2
        assert result[0][0] == "read_file"
        assert result[1][0] == "write_file"

    def test_legacy_function_call(self) -> None:
        message = {
            "function_call": {
                "name": "search",
                "arguments": json.dumps({"query": "test"}),
            }
        }
        result = map_autogen_tool_call(message)
        assert len(result) == 1
        assert result[0] == ("search", {"query": "test"})

    def test_no_tool_calls(self) -> None:
        message = {"content": "Hello, how are you?"}
        result = map_autogen_tool_call(message)
        assert result == []

    def test_invalid_json_arguments(self) -> None:
        message = {
            "tool_calls": [
                {"function": {"name": "broken", "arguments": "not-json"}}
            ]
        }
        result = map_autogen_tool_call(message)
        assert result[0] == ("broken", {"raw_input": "not-json"})

    def test_dict_arguments(self) -> None:
        message = {
            "tool_calls": [
                {"function": {"name": "tool_a", "arguments": {"key": "val"}}}
            ]
        }
        result = map_autogen_tool_call(message)
        assert result[0] == ("tool_a", {"key": "val"})


# --- APEP-161: AgentPEPSpeakerHook ---


class FakeAgent:
    def __init__(self, name: str = "test-agent") -> None:
        self.name = name


class TestSpeakerHook:
    @respx.mock
    async def test_check_message_allow(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        hook = AgentPEPSpeakerHook(client=client)
        message = {
            "tool_calls": [
                {"function": {"name": "read_file", "arguments": '{"path": "/tmp"}'}}
            ]
        }

        responses = await hook.check_message(FakeAgent(), message)
        assert len(responses) == 1
        assert responses[0].decision.value == "ALLOW"

    @respx.mock
    async def test_check_message_deny(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )

        hook = AgentPEPSpeakerHook(client=client)
        message = {
            "tool_calls": [
                {"function": {"name": "delete_db", "arguments": "{}"}}
            ]
        }

        with pytest.raises(PolicyDeniedError) as exc_info:
            await hook.check_message(FakeAgent(), message)
        assert exc_info.value.tool_name == "delete_db"

    @respx.mock
    async def test_check_message_no_tool_calls(self, client: AgentPEPClient) -> None:
        hook = AgentPEPSpeakerHook(client=client)
        message = {"content": "Just a text message"}

        responses = await hook.check_message(FakeAgent(), message)
        assert responses == []

    @respx.mock
    async def test_custom_agent_id_fn(self, client: AgentPEPClient) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        hook = AgentPEPSpeakerHook(
            client=client,
            agent_id_fn=lambda agent: f"custom-{agent.name}",
        )
        message = {
            "tool_calls": [
                {"function": {"name": "tool_a", "arguments": "{}"}}
            ]
        }

        await hook.check_message(FakeAgent("worker"), message)
        body = json.loads(route.calls[0].request.content)
        assert body["agent_id"] == "custom-worker"

    @respx.mock
    async def test_delegation_chain_fn(self, client: AgentPEPClient) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        hook = AgentPEPSpeakerHook(
            client=client,
            delegation_chain_fn=lambda: ["orchestrator", "worker"],
        )
        message = {
            "tool_calls": [
                {"function": {"name": "tool_a", "arguments": "{}"}}
            ]
        }

        await hook.check_message(FakeAgent(), message)
        body = json.loads(route.calls[0].request.content)
        assert body["delegation_chain"] == ["orchestrator", "worker"]

    @respx.mock
    async def test_intercept_reply_with_tool_calls(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        hook = AgentPEPSpeakerHook(client=client)
        messages = [
            {
                "tool_calls": [
                    {"function": {"name": "read_file", "arguments": "{}"}}
                ]
            }
        ]

        result = await hook.intercept_reply(
            recipient=FakeAgent("recipient"),
            messages=messages,
            sender=FakeAgent("sender"),
        )
        assert result == (False, None)

    @respx.mock
    async def test_intercept_reply_deny_raises(
        self, client: AgentPEPClient
    ) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )

        hook = AgentPEPSpeakerHook(client=client)
        messages = [
            {
                "tool_calls": [
                    {"function": {"name": "delete_db", "arguments": "{}"}}
                ]
            }
        ]

        with pytest.raises(PolicyDeniedError):
            await hook.intercept_reply(
                recipient=FakeAgent(),
                messages=messages,
                sender=FakeAgent(),
            )

    @respx.mock
    def test_check_message_sync_allow(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        hook = AgentPEPSpeakerHook(client=client)
        message = {
            "tool_calls": [
                {"function": {"name": "read_file", "arguments": "{}"}}
            ]
        }

        responses = hook.check_message_sync(FakeAgent(), message)
        assert len(responses) == 1
        assert responses[0].decision.value == "ALLOW"

    @respx.mock
    def test_check_message_sync_deny(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )

        hook = AgentPEPSpeakerHook(client=client)
        message = {
            "tool_calls": [
                {"function": {"name": "delete_db", "arguments": "{}"}}
            ]
        }

        with pytest.raises(PolicyDeniedError):
            hook.check_message_sync(FakeAgent(), message)


# --- APEP-163: Confused-deputy scenarios in AutoGen multi-agent ---


class TestAutoGenConfusedDeputy:
    """Integration tests for AutoGen multi-agent confused-deputy scenarios."""

    @respx.mock
    async def test_agent_a_tricks_agent_b_into_calling_tool(
        self, client: AgentPEPClient
    ) -> None:
        """Agent A sends a message that tricks Agent B into calling a
        privileged tool. The delegation chain should trigger a DENY."""
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(
                200,
                json={
                    "request_id": "00000000-0000-0000-0000-000000000020",
                    "decision": "DENY",
                    "reason": "Confused deputy: agent-b not authorized to use "
                    "delete_user on behalf of agent-a",
                    "risk_score": 0.95,
                    "latency_ms": 4,
                },
            )
        )

        # Agent B is the speaker; delegation chain shows A delegated to B
        hook = AgentPEPSpeakerHook(
            client=client,
            delegation_chain_fn=lambda: ["agent-a", "agent-b"],
        )

        message = {
            "tool_calls": [
                {
                    "function": {
                        "name": "delete_user",
                        "arguments": json.dumps({"user_id": "admin"}),
                    }
                }
            ]
        }

        with pytest.raises(PolicyDeniedError) as exc_info:
            await hook.check_message(FakeAgent("agent-b"), message)
        assert "confused deputy" in exc_info.value.reason.lower() or \
               "DENY" == exc_info.value.decision

    @respx.mock
    async def test_deep_delegation_chain_exceeds_max_depth(
        self, client: AgentPEPClient
    ) -> None:
        """A multi-agent conversation with a deep delegation chain is denied."""
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(
                200,
                json={
                    "request_id": "00000000-0000-0000-0000-000000000021",
                    "decision": "DENY",
                    "reason": "Delegation chain depth 6 exceeds maximum 5",
                    "risk_score": 1.0,
                    "latency_ms": 2,
                },
            )
        )

        chain = ["orchestrator", "planner", "executor", "helper", "sub-helper", "tool-agent"]
        hook = AgentPEPSpeakerHook(
            client=client,
            delegation_chain_fn=lambda: chain,
        )

        message = {
            "tool_calls": [
                {"function": {"name": "execute_query", "arguments": "{}"}}
            ]
        }

        with pytest.raises(PolicyDeniedError):
            await hook.check_message(FakeAgent("tool-agent"), message)

    @respx.mock
    async def test_escalation_on_cross_agent_taint(
        self, client: AgentPEPClient
    ) -> None:
        """Tool call escalated due to untrusted taint crossing agent boundary."""
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ESCALATE)
        )

        hook = AgentPEPSpeakerHook(
            client=client,
            delegation_chain_fn=lambda: ["web-scraper", "processor"],
        )

        message = {
            "tool_calls": [
                {
                    "function": {
                        "name": "send_email",
                        "arguments": json.dumps({
                            "to": "ceo@company.com",
                            "body": "Scraped data with possible injection",
                        }),
                    }
                }
            ]
        }

        with pytest.raises(PolicyDeniedError) as exc_info:
            await hook.check_message(FakeAgent("processor"), message)
        assert exc_info.value.decision == "ESCALATE"

    @respx.mock
    async def test_legitimate_delegation_allowed(
        self, client: AgentPEPClient
    ) -> None:
        """A properly authorized delegation chain is allowed."""
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        hook = AgentPEPSpeakerHook(
            client=client,
            delegation_chain_fn=lambda: ["user-facing-agent", "file-reader"],
        )

        message = {
            "tool_calls": [
                {
                    "function": {
                        "name": "read_file",
                        "arguments": json.dumps({"path": "/tmp/report.txt"}),
                    }
                }
            ]
        }

        responses = await hook.check_message(FakeAgent("file-reader"), message)
        assert len(responses) == 1
        assert responses[0].decision.value == "ALLOW"

    @respx.mock
    async def test_multi_tool_call_partial_deny(
        self, client: AgentPEPClient
    ) -> None:
        """First tool call allowed, second denied — ensures early termination."""
        responses = [
            httpx.Response(200, json=MOCK_ALLOW),
            httpx.Response(200, json=MOCK_DENY),
        ]
        respx.post("http://testserver:8000/v1/intercept").mock(
            side_effect=responses
        )

        hook = AgentPEPSpeakerHook(
            client=client,
            delegation_chain_fn=lambda: ["agent-a", "agent-b"],
        )

        message = {
            "tool_calls": [
                {"function": {"name": "read_file", "arguments": "{}"}},
                {"function": {"name": "delete_file", "arguments": "{}"}},
            ]
        }

        with pytest.raises(PolicyDeniedError) as exc_info:
            await hook.check_message(FakeAgent("agent-b"), message)
        assert exc_info.value.tool_name == "delete_file"


# --- APEP-162: AutoGen Studio plugin ---


class FakeAgentWithReply:
    """Fake AutoGen agent that supports register_reply."""

    def __init__(self, name: str = "studio-agent") -> None:
        self.name = name
        self._replies: list = []

    def register_reply(self, trigger: Any = None, reply_func: Any = None, position: int = 0) -> None:
        self._replies.insert(position, (trigger, reply_func))


class TestStudioPlugin:
    def test_register_agent(self, client: AgentPEPClient) -> None:
        plugin = AgentPEPStudioPlugin(client=client)
        agent = FakeAgentWithReply("my-agent")

        plugin.register_agent(agent)
        assert "my-agent" in plugin.registered_agents
        assert len(agent._replies) == 1

    def test_register_agents(self, client: AgentPEPClient) -> None:
        plugin = AgentPEPStudioPlugin(client=client)
        agents = [FakeAgentWithReply("a1"), FakeAgentWithReply("a2")]

        plugin.register_agents(agents)
        assert plugin.registered_agents == ["a1", "a2"]

    def test_register_agent_without_register_reply(
        self, client: AgentPEPClient
    ) -> None:
        plugin = AgentPEPStudioPlugin(client=client)

        class BareAgent:
            name = "bare"

        plugin.register_agent(BareAgent())
        # Should not crash; agent skipped
        assert plugin.registered_agents == []

    def test_plugin_metadata(self, client: AgentPEPClient) -> None:
        plugin = AgentPEPStudioPlugin(client=client)
        assert plugin.name == "AgentPEP Policy Enforcement"
        assert plugin.version == "0.1.0"
        assert "RBAC" in plugin.description

    @respx.mock
    async def test_evaluate_tool_call(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        plugin = AgentPEPStudioPlugin(client=client, session_id="studio-sess")
        response = await plugin.evaluate_tool_call(
            agent_id="studio-agent",
            tool_name="search",
            tool_args={"query": "test"},
        )
        assert response.decision.value == "ALLOW"
