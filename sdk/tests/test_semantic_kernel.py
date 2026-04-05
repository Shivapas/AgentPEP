"""Tests for Semantic Kernel integration (APEP-168, APEP-169, APEP-170).

Covers:
- AgentPEPFunctionFilter async ALLOW / DENY paths
- AgentPEPFunctionFilterSync sync paths
- SKPluginMapper tool name resolution and plugin alias mapping
- Plugin metadata extraction
- Filter pipeline continuation semantics
"""

import pytest
import httpx
import respx
from unittest.mock import AsyncMock, MagicMock

from agentpep.client import AgentPEPClient
from agentpep.exceptions import PolicyDeniedError
from agentpep.integrations.semantic_kernel import (
    AgentPEPFunctionFilter,
    AgentPEPFunctionFilterSync,
    SKPluginMapper,
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

MOCK_DRY_RUN = {
    "request_id": "00000000-0000-0000-0000-000000000003",
    "decision": "DRY_RUN",
    "reason": "Dry run mode",
    "risk_score": 0.05,
    "latency_ms": 1,
}


@pytest.fixture
def client() -> AgentPEPClient:
    return AgentPEPClient(base_url="http://testserver:8000")


class FakeKernelFunction:
    """Minimal mock of a Semantic Kernel KernelFunction."""

    def __init__(
        self,
        name: str = "add",
        plugin_name: str | None = "MathPlugin",
        description: str = "Add two numbers",
    ):
        self.name = name
        self.plugin_name = plugin_name
        self.description = description
        self.parameters = []


class FakeKernelParam:
    """Minimal mock of a Semantic Kernel KernelParameterMetadata."""

    def __init__(self, name: str, description: str = "", type_: str = "int", is_required: bool = True):
        self.name = name
        self.description = description
        self.type_ = type_
        self.is_required = is_required


class FakeContext:
    """Minimal mock of FunctionInvocationContext."""

    def __init__(self, function: FakeKernelFunction, arguments: dict | None = None):
        self.function = function
        self.arguments = arguments or {}
        self.result = None


# ---------------------------------------------------------------------------
# APEP-169 — SKPluginMapper tests
# ---------------------------------------------------------------------------


class TestSKPluginMapper:
    def test_tool_name_with_plugin(self) -> None:
        mapper = SKPluginMapper()
        assert mapper.tool_name("MathPlugin", "add") == "MathPlugin.add"

    def test_tool_name_without_plugin(self) -> None:
        mapper = SKPluginMapper()
        assert mapper.tool_name(None, "standalone_func") == "standalone_func"

    def test_tool_name_with_alias(self) -> None:
        mapper = SKPluginMapper(
            plugin_alias={"MathPlugin": "math", "FilePlugin": "file"},
        )
        assert mapper.tool_name("MathPlugin", "add") == "math.add"
        assert mapper.tool_name("FilePlugin", "read") == "file.read"

    def test_tool_name_custom_separator(self) -> None:
        mapper = SKPluginMapper(separator="/")
        assert mapper.tool_name("MathPlugin", "add") == "MathPlugin/add"

    def test_register_alias(self) -> None:
        mapper = SKPluginMapper()
        mapper.register_alias("LongPluginName", "short")
        assert mapper.tool_name("LongPluginName", "func") == "short.func"

    def test_extract_args_from_context(self) -> None:
        mapper = SKPluginMapper()
        func = FakeKernelFunction()
        ctx = FakeContext(func, arguments={"a": 1, "b": 2})
        args = mapper.extract_args(ctx)
        assert args == {"a": 1, "b": 2}

    def test_extract_args_empty(self) -> None:
        mapper = SKPluginMapper()
        func = FakeKernelFunction()
        ctx = FakeContext(func)
        args = mapper.extract_args(ctx)
        assert args == {}

    def test_extract_metadata(self) -> None:
        mapper = SKPluginMapper()
        func = FakeKernelFunction(name="add", plugin_name="MathPlugin", description="Add two numbers")
        func.parameters = [
            FakeKernelParam("a", "First number", "int", True),
            FakeKernelParam("b", "Second number", "int", True),
        ]
        meta = mapper.extract_metadata(func)
        assert meta["name"] == "add"
        assert meta["plugin_name"] == "MathPlugin"
        assert meta["description"] == "Add two numbers"
        assert len(meta["parameters"]) == 2
        assert meta["parameters"][0]["name"] == "a"
        assert meta["parameters"][0]["required"] is True
        assert meta["parameters"][1]["type"] == "int"


# ---------------------------------------------------------------------------
# APEP-168 — AgentPEPFunctionFilter (async) tests
# ---------------------------------------------------------------------------


class TestAgentPEPFunctionFilter:
    @respx.mock
    async def test_filter_allow_continues_pipeline(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        next_filter = AsyncMock()
        func = FakeKernelFunction(name="add", plugin_name="MathPlugin")
        ctx = FakeContext(func, arguments={"a": 1, "b": 2})

        policy_filter = AgentPEPFunctionFilter(client=client, agent_id="sk-agent")
        await policy_filter(ctx, next_filter)

        next_filter.assert_awaited_once_with(ctx)

    @respx.mock
    async def test_filter_deny_blocks_pipeline(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )

        next_filter = AsyncMock()
        func = FakeKernelFunction(name="delete_all", plugin_name="AdminPlugin")
        ctx = FakeContext(func)

        policy_filter = AgentPEPFunctionFilter(client=client, agent_id="sk-agent")

        with pytest.raises(PolicyDeniedError) as exc_info:
            await policy_filter(ctx, next_filter)

        assert exc_info.value.tool_name == "AdminPlugin.delete_all"
        assert exc_info.value.decision == "DENY"
        next_filter.assert_not_awaited()

    @respx.mock
    async def test_filter_dry_run_continues_pipeline(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DRY_RUN)
        )

        next_filter = AsyncMock()
        func = FakeKernelFunction(name="read", plugin_name="FilePlugin")
        ctx = FakeContext(func, arguments={"path": "/tmp/test.txt"})

        policy_filter = AgentPEPFunctionFilter(client=client, agent_id="sk-agent")
        await policy_filter(ctx, next_filter)

        next_filter.assert_awaited_once_with(ctx)

    @respx.mock
    async def test_filter_sends_correct_tool_name(self, client: AgentPEPClient) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        next_filter = AsyncMock()
        func = FakeKernelFunction(name="search", plugin_name="WebPlugin")
        ctx = FakeContext(func, arguments={"query": "AI safety"})

        policy_filter = AgentPEPFunctionFilter(client=client, agent_id="sk-agent")
        await policy_filter(ctx, next_filter)

        body = route.calls[0].request.content
        assert b"WebPlugin.search" in body

    @respx.mock
    async def test_filter_with_plugin_alias(self, client: AgentPEPClient) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        next_filter = AsyncMock()
        mapper = SKPluginMapper(plugin_alias={"MathPlugin": "math"})
        func = FakeKernelFunction(name="add", plugin_name="MathPlugin")
        ctx = FakeContext(func, arguments={"a": 5, "b": 3})

        policy_filter = AgentPEPFunctionFilter(
            client=client, agent_id="sk-agent", plugin_mapper=mapper
        )
        await policy_filter(ctx, next_filter)

        body = route.calls[0].request.content
        assert b"math.add" in body

    @respx.mock
    async def test_filter_forwards_args(self, client: AgentPEPClient) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        next_filter = AsyncMock()
        func = FakeKernelFunction(name="send", plugin_name="EmailPlugin")
        ctx = FakeContext(func, arguments={"to": "user@example.com", "subject": "Hello"})

        policy_filter = AgentPEPFunctionFilter(client=client, agent_id="sk-agent")
        await policy_filter(ctx, next_filter)

        body = route.calls[0].request.content.decode()
        assert "user@example.com" in body
        assert "Hello" in body

    @respx.mock
    async def test_filter_no_plugin_name(self, client: AgentPEPClient) -> None:
        route = respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        next_filter = AsyncMock()
        func = FakeKernelFunction(name="standalone", plugin_name=None)
        ctx = FakeContext(func)

        policy_filter = AgentPEPFunctionFilter(client=client, agent_id="sk-agent")
        await policy_filter(ctx, next_filter)

        body = route.calls[0].request.content
        assert b"standalone" in body


# ---------------------------------------------------------------------------
# AgentPEPFunctionFilterSync tests
# ---------------------------------------------------------------------------


class TestAgentPEPFunctionFilterSync:
    @respx.mock
    def test_sync_filter_allow(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )

        next_filter = MagicMock()
        func = FakeKernelFunction(name="add", plugin_name="MathPlugin")
        ctx = FakeContext(func, arguments={"a": 1, "b": 2})

        policy_filter = AgentPEPFunctionFilterSync(client=client, agent_id="sk-agent")
        policy_filter(ctx, next_filter)

        next_filter.assert_called_once_with(ctx)

    @respx.mock
    def test_sync_filter_deny(self, client: AgentPEPClient) -> None:
        respx.post("http://testserver:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )

        next_filter = MagicMock()
        func = FakeKernelFunction(name="destroy", plugin_name="AdminPlugin")
        ctx = FakeContext(func)

        policy_filter = AgentPEPFunctionFilterSync(client=client, agent_id="sk-agent")

        with pytest.raises(PolicyDeniedError) as exc_info:
            policy_filter(ctx, next_filter)

        assert exc_info.value.tool_name == "AdminPlugin.destroy"
        next_filter.assert_not_called()
