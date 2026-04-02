"""Tests for SDK taint labelling methods — APEP-041, APEP-042."""

import pytest
import respx
from httpx import Response

from agentpep.client import AgentPEPClient
from agentpep.models import TaintLevel, TaintNodeResponse, TaintSource


MOCK_LABEL_RESPONSE = {
    "node_id": "00000000-0000-0000-0000-000000000010",
    "session_id": "test-session",
    "taint_level": "UNTRUSTED",
    "source": "WEB",
    "propagated_from": [],
    "value_hash": "abc123",
}

MOCK_PROPAGATE_RESPONSE = {
    "node_id": "00000000-0000-0000-0000-000000000011",
    "session_id": "test-session",
    "taint_level": "UNTRUSTED",
    "source": "TOOL_OUTPUT",
    "propagated_from": ["00000000-0000-0000-0000-000000000010"],
    "value_hash": "def456",
}


@pytest.fixture
def client() -> AgentPEPClient:
    return AgentPEPClient(base_url="http://testserver:8000", api_key="test-key")


class TestAsyncLabelTaint:
    @respx.mock
    @pytest.mark.asyncio
    async def test_label_web_source(self, client: AgentPEPClient):
        respx.post("http://testserver:8000/v1/taint/label").mock(
            return_value=Response(200, json=MOCK_LABEL_RESPONSE)
        )
        result = await client.label_taint(
            session_id="test-session",
            source=TaintSource.WEB,
            value="fetched content",
        )
        assert isinstance(result, TaintNodeResponse)
        assert result.taint_level == TaintLevel.UNTRUSTED
        assert result.source == TaintSource.WEB

    @respx.mock
    @pytest.mark.asyncio
    async def test_label_with_explicit_level(self, client: AgentPEPClient):
        mock_resp = {**MOCK_LABEL_RESPONSE, "taint_level": "QUARANTINE"}
        respx.post("http://testserver:8000/v1/taint/label").mock(
            return_value=Response(200, json=mock_resp)
        )
        result = await client.label_taint(
            session_id="test-session",
            source=TaintSource.WEB,
            taint_level=TaintLevel.QUARANTINE,
        )
        assert result.taint_level == TaintLevel.QUARANTINE


class TestAsyncPropagateTaint:
    @respx.mock
    @pytest.mark.asyncio
    async def test_propagate_taint(self, client: AgentPEPClient):
        respx.post("http://testserver:8000/v1/taint/propagate").mock(
            return_value=Response(200, json=MOCK_PROPAGATE_RESPONSE)
        )
        result = await client.propagate_taint(
            session_id="test-session",
            parent_node_ids=["00000000-0000-0000-0000-000000000010"],
            source=TaintSource.TOOL_OUTPUT,
        )
        assert isinstance(result, TaintNodeResponse)
        assert result.taint_level == TaintLevel.UNTRUSTED
        assert len(result.propagated_from) == 1


class TestSyncLabelTaint:
    @respx.mock
    def test_label_sync(self, client: AgentPEPClient):
        respx.post("http://testserver:8000/v1/taint/label").mock(
            return_value=Response(200, json=MOCK_LABEL_RESPONSE)
        )
        result = client.label_taint_sync(
            session_id="test-session",
            source=TaintSource.WEB,
            value="data",
        )
        assert isinstance(result, TaintNodeResponse)
        assert result.taint_level == TaintLevel.UNTRUSTED


class TestSyncPropagateTaint:
    @respx.mock
    def test_propagate_sync(self, client: AgentPEPClient):
        respx.post("http://testserver:8000/v1/taint/propagate").mock(
            return_value=Response(200, json=MOCK_PROPAGATE_RESPONSE)
        )
        result = client.propagate_taint_sync(
            session_id="test-session",
            parent_node_ids=["00000000-0000-0000-0000-000000000010"],
            source=TaintSource.TOOL_OUTPUT,
        )
        assert isinstance(result, TaintNodeResponse)
        assert result.taint_level == TaintLevel.UNTRUSTED
