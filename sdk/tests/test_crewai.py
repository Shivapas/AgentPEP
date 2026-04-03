"""Tests for CrewAI integration (APEP-165, APEP-166, APEP-167).

Covers:
- AgentPEPCrewAITool ALLOW / DENY paths
- CrewAIRoleMapping resolution and multi-agent role mapping
- wrap_crew_tools helper
- Multi-agent workflow with confused-deputy detection via delegation_chain
"""

import pytest
import httpx
import respx
from unittest.mock import MagicMock

from agentpep.client import AgentPEPClient
from agentpep.exceptions import PolicyDeniedError
from agentpep.integrations.crewai import (
    AgentPEPCrewAITool,
    CrewAIRoleMapping,
    wrap_crew_tools,
)

MOCK_ALLOW = {
    "request_id": "00000000-0000-0000-0000-000000000001",
    "decision": "ALLOW",
    "risk_score": 0.1,
    "reason": "Allowed by policy",
    "latency_ms": 2,
}

MOCK_DENY = {
    "request_id": "00000000-0000-0000-0000-000000000002",
    "decision": "DENY",
    "reason": "Denied by policy",
    "latency_ms": 1,
}

MOCK_ESCALATE = {
    "request_id": "00000000-0000-0000-0000-000000000003",
    "decision": "ESCALATE",
    "reason": "Confused deputy detected: delegation chain depth exceeded",
    "risk_score": 0.95,
    "latency_ms": 3,
}


@pytest.fixture
def client() -> AgentPEPClient:
    return AgentPEPClient(base_url="http://testserver:8000")


class FakeCrewAITool:
    """Minimal mock of a CrewAI BaseTool for testing."""

    name = "search_web"
    description = "Search the web for information"
    args_schema = None

    def _run(self, **kwargs):
        return f"results for {kwargs.get('query', '')}"


class FakeDeleteTool:
    """Tool that should be denied by policy."""

    name = "delete_database"
    description = "Delete the entire database"
    args_schema = None

    def _run(self, **kwargs):
        return "deleted"


class FakeWriteTool:
    """Writer agent tool."""

    name = "write_file"
    description = "Write content to a file"
    args_schema = None

    def _run(self, **kwargs):
        return f"wrote to {kwargs.get('path', '')}"


# ---------------------------------------------------------------------------
# APEP-165 — Task execution interceptor tests
# ---------------------------------------------------------------------------


class TestAgentPEPCrewAITool:
    @respx.mock
    def test_tool_allow_forwards_to_wrapped(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        fake_tool = FakeCrewAITool()
        wrapper = AgentPEPCrewAITool(
            wrapped_tool=fake_tool,
            client=client,
            agent_id="crew-agent",
        )

        result = wrapper._run(query="test query")
        assert result == "results for test query"

    @respx.mock
    def test_tool_deny_raises_policy_denied(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )

        fake_tool = FakeDeleteTool()
        wrapper = AgentPEPCrewAITool(
            wrapped_tool=fake_tool,
            client=client,
            agent_id="crew-agent",
        )

        with pytest.raises(PolicyDeniedError) as exc_info:
            wrapper._run(target="production")
        assert exc_info.value.tool_name == "delete_database"
        assert exc_info.value.decision == "DENY"

    @respx.mock
    def test_tool_forwards_name_and_args(self, client: AgentPEPClient) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        fake_tool = FakeCrewAITool()
        wrapper = AgentPEPCrewAITool(
            wrapped_tool=fake_tool,
            client=client,
            agent_id="crew-agent",
            session_id="session-42",
        )

        wrapper._run(query="hello")

        body = route.calls[0].request.content
        assert b"search_web" in body
        assert b"session-42" in body

    @respx.mock
    def test_tool_metadata_forwarded(self, client: AgentPEPClient) -> None:
        fake_tool = FakeCrewAITool()
        wrapper = AgentPEPCrewAITool(
            wrapped_tool=fake_tool,
            client=client,
            agent_id="crew-agent",
        )

        assert wrapper.name == "search_web"
        assert wrapper.description == "Search the web for information"

    @respx.mock
    def test_tool_dry_run_allows_execution(self, client: AgentPEPClient) -> None:
        mock_dry_run = {
            **MOCK_ALLOW,
            "decision": "DRY_RUN",
            "reason": "Dry run mode",
        }
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=mock_dry_run)
        )

        fake_tool = FakeCrewAITool()
        wrapper = AgentPEPCrewAITool(
            wrapped_tool=fake_tool,
            client=client,
            agent_id="crew-agent",
        )

        result = wrapper._run(query="dry run")
        assert result == "results for dry run"


# ---------------------------------------------------------------------------
# APEP-166 — Role mapping tests
# ---------------------------------------------------------------------------


class TestCrewAIRoleMapping:
    def test_resolve_mapped_role(self) -> None:
        mapping = CrewAIRoleMapping(
            role_map={
                "Researcher": "crewai-researcher",
                "Writer": "crewai-writer",
            },
        )
        assert mapping.resolve("Researcher") == "crewai-researcher"
        assert mapping.resolve("Writer") == "crewai-writer"

    def test_resolve_unmapped_returns_default(self) -> None:
        mapping = CrewAIRoleMapping(
            role_map={"Researcher": "crewai-researcher"},
            default_role="crewai-fallback",
        )
        assert mapping.resolve("Unknown") == "crewai-fallback"

    def test_register_new_mapping(self) -> None:
        mapping = CrewAIRoleMapping()
        mapping.register("Editor", "crewai-editor")
        assert mapping.resolve("Editor") == "crewai-editor"

    def test_mappings_returns_copy(self) -> None:
        role_map = {"A": "role-a"}
        mapping = CrewAIRoleMapping(role_map=role_map)
        result = mapping.mappings
        result["B"] = "role-b"
        assert "B" not in mapping.mappings

    @respx.mock
    def test_role_mapping_used_in_tool(self, client: AgentPEPClient) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        mapping = CrewAIRoleMapping(
            role_map={"Researcher": "crewai-researcher"},
        )

        fake_tool = FakeCrewAITool()
        wrapper = AgentPEPCrewAITool(
            wrapped_tool=fake_tool,
            client=client,
            agent_id="fallback-id",
            role_mapping=mapping,
            crewai_role="Researcher",
        )

        wrapper._run(query="test")
        body = route.calls[0].request.content
        assert b"crewai-researcher" in body

    @respx.mock
    def test_role_mapping_fallback_when_no_role(self, client: AgentPEPClient) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        mapping = CrewAIRoleMapping(
            role_map={"Researcher": "crewai-researcher"},
        )

        fake_tool = FakeCrewAITool()
        wrapper = AgentPEPCrewAITool(
            wrapped_tool=fake_tool,
            client=client,
            agent_id="my-agent-id",
            role_mapping=mapping,
            # crewai_role not set — should fall back to agent_id
        )

        wrapper._run(query="test")
        body = route.calls[0].request.content
        assert b"my-agent-id" in body


# ---------------------------------------------------------------------------
# wrap_crew_tools helper
# ---------------------------------------------------------------------------


class TestWrapCrewTools:
    @respx.mock
    def test_wrap_multiple_tools(self, client: AgentPEPClient) -> None:
        tools = [FakeCrewAITool(), FakeDeleteTool(), FakeWriteTool()]
        wrapped = wrap_crew_tools(
            tools,
            client,
            agent_id="crew-agent",
        )
        assert len(wrapped) == 3
        assert wrapped[0].name == "search_web"
        assert wrapped[1].name == "delete_database"
        assert wrapped[2].name == "write_file"

    @respx.mock
    def test_wrap_with_role_mapping(self, client: AgentPEPClient) -> None:
        mapping = CrewAIRoleMapping(role_map={"Writer": "crewai-writer"})
        tools = [FakeWriteTool()]
        wrapped = wrap_crew_tools(
            tools,
            client,
            agent_id="default-id",
            role_mapping=mapping,
            crewai_role="Writer",
        )
        assert len(wrapped) == 1
        assert wrapped[0].crewai_role == "Writer"


# ---------------------------------------------------------------------------
# APEP-167 — Multi-agent workflow with confused-deputy detection
# ---------------------------------------------------------------------------


class TestMultiAgentConfusedDeputy:
    """Tests simulating a multi-agent CrewAI crew where one agent delegates
    a tool call through another, and the delegation chain is validated
    by AgentPEP for confused-deputy attacks."""

    @respx.mock
    def test_delegation_chain_forwarded(self, client: AgentPEPClient) -> None:
        """Verify that the delegation_chain is sent in the intercept request."""
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        fake_tool = FakeWriteTool()
        wrapper = AgentPEPCrewAITool(
            wrapped_tool=fake_tool,
            client=client,
            agent_id="crew-writer",
            delegation_chain=["crew-manager", "crew-writer"],
        )

        result = wrapper._run(path="/tmp/out.txt")
        assert result == "wrote to /tmp/out.txt"

        body = route.calls[0].request.content
        assert b"crew-manager" in body
        assert b"crew-writer" in body

    @respx.mock
    def test_confused_deputy_escalation(self, client: AgentPEPClient) -> None:
        """When a delegation chain triggers confused-deputy detection,
        the server returns ESCALATE and the tool raises PolicyDeniedError."""
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ESCALATE)
        )

        fake_tool = FakeDeleteTool()
        wrapper = AgentPEPCrewAITool(
            wrapped_tool=fake_tool,
            client=client,
            agent_id="crew-intern",
            delegation_chain=[
                "crew-manager",
                "crew-researcher",
                "crew-writer",
                "crew-reviewer",
                "crew-intern",
            ],
        )

        with pytest.raises(PolicyDeniedError) as exc_info:
            wrapper._run(target="production")
        assert exc_info.value.decision == "ESCALATE"
        assert "confused deputy" in exc_info.value.reason.lower()

    @respx.mock
    def test_multi_agent_different_roles_different_decisions(
        self, client: AgentPEPClient
    ) -> None:
        """Simulate two crew agents with different roles: one allowed, one denied."""
        call_count = 0

        def side_effect(request):
            nonlocal call_count
            call_count += 1
            body = request.content.decode()
            if "crewai-researcher" in body:
                return httpx.Response(200, json=MOCK_ALLOW)
            return httpx.Response(200, json=MOCK_DENY)

        respx.post("http://testserver:8000/v1/intercept").mock(side_effect=side_effect)

        mapping = CrewAIRoleMapping(
            role_map={
                "Researcher": "crewai-researcher",
                "Intern": "crewai-intern",
            },
        )

        search_tool = FakeCrewAITool()

        # Researcher can use search_web
        researcher_wrapper = AgentPEPCrewAITool(
            wrapped_tool=search_tool,
            client=client,
            agent_id="default",
            role_mapping=mapping,
            crewai_role="Researcher",
        )
        result = researcher_wrapper._run(query="quantum computing")
        assert result == "results for quantum computing"

        # Intern is denied the same tool
        intern_wrapper = AgentPEPCrewAITool(
            wrapped_tool=search_tool,
            client=client,
            agent_id="default",
            role_mapping=mapping,
            crewai_role="Intern",
        )
        with pytest.raises(PolicyDeniedError):
            intern_wrapper._run(query="classified data")

        assert call_count == 2
