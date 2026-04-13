"""Tests for Sprint 32 — Cloud Audit Backends.

APEP-250: CloudWatchAuditBackend
APEP-251: DatadogAuditBackend
APEP-252: LokiAuditBackend
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.backends.audit import AuditBackend


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sample_record() -> dict:
    return {
        "decision_id": "d-001",
        "decision": "ALLOW",
        "timestamp": "2026-04-13T00:00:00Z",
        "sequence_number": 1,
        "record_hash": "abc123",
        "previous_hash": "genesis",
        "agent_id": "agent-1",
        "agent_role": "developer",
        "session_id": "sess-1",
        "tool_name": "file.read",
        "matched_rule_id": "rule-1",
        "risk_score": 0.2,
        "escalation_id": None,
        "tool_args_hash": "sha256-abc",
        "taint_flags": ["UNTRUSTED"],
        "delegation_chain": ["agent-0", "agent-1"],
        "latency_ms": 12,
    }


# ---------------------------------------------------------------------------
# APEP-250: CloudWatchAuditBackend
# ---------------------------------------------------------------------------


class TestCloudWatchAuditBackend:
    """Tests for the CloudWatch audit backend."""

    def _make_backend(self):
        from app.backends.cloudwatch_audit import CloudWatchAuditBackend

        return CloudWatchAuditBackend(
            log_group_name="/test/audit",
            log_stream_name="test-stream",
            region_name="us-east-1",
        )

    def test_implements_audit_backend(self):
        backend = self._make_backend()
        assert isinstance(backend, AuditBackend)

    @pytest.mark.asyncio
    async def test_write_decision_when_not_ready(self):
        backend = self._make_backend()
        assert not backend.is_running
        result = await backend.write_decision(_sample_record())
        assert result is False

    @pytest.mark.asyncio
    async def test_write_decision_success(self):
        backend = self._make_backend()
        mock_client = MagicMock()
        mock_client.put_log_events.return_value = {"nextSequenceToken": "tok-1"}
        backend._client = mock_client
        backend._ready = True

        result = await backend.write_decision(_sample_record())
        assert result is True
        mock_client.put_log_events.assert_called_once()

        call_kwargs = mock_client.put_log_events.call_args[1]
        assert call_kwargs["logGroupName"] == "/test/audit"
        assert call_kwargs["logStreamName"] == "test-stream"
        assert len(call_kwargs["logEvents"]) == 1
        event_msg = json.loads(call_kwargs["logEvents"][0]["message"])
        assert event_msg["decision_id"] == "d-001"

    @pytest.mark.asyncio
    async def test_write_decision_stores_sequence_token(self):
        backend = self._make_backend()
        mock_client = MagicMock()
        mock_client.put_log_events.return_value = {"nextSequenceToken": "tok-2"}
        backend._client = mock_client
        backend._ready = True

        await backend.write_decision(_sample_record())
        assert backend._sequence_token == "tok-2"

        # Second call should include the sequence token
        mock_client.put_log_events.return_value = {"nextSequenceToken": "tok-3"}
        await backend.write_decision(_sample_record())
        call_kwargs = mock_client.put_log_events.call_args[1]
        assert call_kwargs["sequenceToken"] == "tok-2"

    @pytest.mark.asyncio
    async def test_write_batch(self):
        backend = self._make_backend()
        mock_client = MagicMock()
        mock_client.put_log_events.return_value = {"nextSequenceToken": "tok-1"}
        backend._client = mock_client
        backend._ready = True

        records = [_sample_record(), _sample_record()]
        result = await backend.write_batch(records)
        assert result == 2

    @pytest.mark.asyncio
    async def test_write_batch_empty(self):
        backend = self._make_backend()
        backend._ready = True
        backend._client = MagicMock()
        result = await backend.write_batch([])
        assert result == 0

    @pytest.mark.asyncio
    async def test_query_returns_parsed_events(self):
        backend = self._make_backend()
        mock_client = MagicMock()
        record = _sample_record()
        mock_client.filter_log_events.return_value = {
            "events": [{"message": json.dumps(record)}]
        }
        backend._client = mock_client
        backend._ready = True

        results = await backend.query({"decision": "ALLOW"})
        assert len(results) == 1
        assert results[0]["decision_id"] == "d-001"

    @pytest.mark.asyncio
    async def test_verify_integrity(self):
        backend = self._make_backend()
        result = await backend.verify_integrity()
        assert result.valid is True
        assert "append-only" in result.detail

    @pytest.mark.asyncio
    async def test_initialize_without_boto3(self):
        backend = self._make_backend()
        with patch.dict("sys.modules", {"boto3": None}):
            await backend.initialize()
        assert not backend.is_running

    @pytest.mark.asyncio
    async def test_close(self):
        backend = self._make_backend()
        backend._client = MagicMock()
        backend._ready = True
        await backend.close()
        assert not backend.is_running
        assert backend._client is None

    @pytest.mark.asyncio
    async def test_verbosity_filtering_applied(self, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "audit_verbosity", "MINIMAL")
        backend = self._make_backend()
        mock_client = MagicMock()
        mock_client.put_log_events.return_value = {"nextSequenceToken": "tok-1"}
        backend._client = mock_client
        backend._ready = True

        await backend.write_decision(_sample_record())
        call_kwargs = mock_client.put_log_events.call_args[1]
        event_msg = json.loads(call_kwargs["logEvents"][0]["message"])
        assert "tool_args_hash" not in event_msg
        assert "decision" in event_msg


# ---------------------------------------------------------------------------
# APEP-251: DatadogAuditBackend
# ---------------------------------------------------------------------------


class TestDatadogAuditBackend:
    """Tests for the Datadog audit backend."""

    def _make_backend(self):
        from app.backends.datadog_audit import DatadogAuditBackend

        return DatadogAuditBackend(
            api_key="test-api-key",
            site="datadoghq.com",
            service_name="agentpep-test",
        )

    def test_implements_audit_backend(self):
        backend = self._make_backend()
        assert isinstance(backend, AuditBackend)

    @pytest.mark.asyncio
    async def test_write_decision_when_not_ready(self):
        backend = self._make_backend()
        result = await backend.write_decision(_sample_record())
        assert result is False

    @pytest.mark.asyncio
    async def test_write_decision_success(self):
        backend = self._make_backend()
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        backend._client = mock_client
        backend._ready = True

        result = await backend.write_decision(_sample_record())
        assert result is True
        mock_client.post.assert_called_once()

        call_args = mock_client.post.call_args
        url = call_args[0][0]
        assert "datadoghq.com" in url
        body = call_args[1]["json"]
        assert len(body) == 1
        assert body[0]["ddsource"] == "agentpep"
        assert body[0]["service"] == "agentpep-test"

    @pytest.mark.asyncio
    async def test_write_decision_api_error(self):
        backend = self._make_backend()
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        backend._client = mock_client
        backend._ready = True

        result = await backend.write_decision(_sample_record())
        assert result is False

    @pytest.mark.asyncio
    async def test_write_batch_success(self):
        backend = self._make_backend()
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        backend._client = mock_client
        backend._ready = True

        records = [_sample_record(), _sample_record(), _sample_record()]
        result = await backend.write_batch(records)
        assert result == 3

        body = mock_client.post.call_args[1]["json"]
        assert len(body) == 3

    @pytest.mark.asyncio
    async def test_query_returns_empty(self):
        backend = self._make_backend()
        result = await backend.query({"decision": "ALLOW"})
        assert result == []

    @pytest.mark.asyncio
    async def test_verify_integrity(self):
        backend = self._make_backend()
        result = await backend.verify_integrity()
        assert result.valid is True
        assert "Datadog" in result.detail

    @pytest.mark.asyncio
    async def test_initialize_creates_client(self):
        backend = self._make_backend()
        await backend.initialize()
        assert backend.is_running
        assert backend._client is not None
        await backend.close()

    @pytest.mark.asyncio
    async def test_initialize_without_api_key(self):
        from app.backends.datadog_audit import DatadogAuditBackend

        backend = DatadogAuditBackend(api_key="", site="datadoghq.com")
        await backend.initialize()
        assert not backend.is_running

    @pytest.mark.asyncio
    async def test_close(self):
        backend = self._make_backend()
        await backend.initialize()
        assert backend.is_running
        await backend.close()
        assert not backend.is_running

    @pytest.mark.asyncio
    async def test_dd_api_key_header(self):
        backend = self._make_backend()
        await backend.initialize()
        assert backend._client.headers["DD-API-KEY"] == "test-api-key"
        await backend.close()

    @pytest.mark.asyncio
    async def test_verbosity_filtering_applied(self, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "audit_verbosity", "MINIMAL")
        backend = self._make_backend()
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        backend._client = mock_client
        backend._ready = True

        await backend.write_decision(_sample_record())
        body = mock_client.post.call_args[1]["json"]
        message = json.loads(body[0]["message"])
        assert "tool_args_hash" not in message
        assert "decision" in message


# ---------------------------------------------------------------------------
# APEP-252: LokiAuditBackend
# ---------------------------------------------------------------------------


class TestLokiAuditBackend:
    """Tests for the Loki audit backend."""

    def _make_backend(self):
        from app.backends.loki_audit import LokiAuditBackend

        return LokiAuditBackend(
            push_url="http://loki:3100/loki/api/v1/push",
            labels={"app": "agentpep", "env": "test"},
            tenant_id="test-tenant",
        )

    def test_implements_audit_backend(self):
        backend = self._make_backend()
        assert isinstance(backend, AuditBackend)

    @pytest.mark.asyncio
    async def test_write_decision_when_not_ready(self):
        backend = self._make_backend()
        result = await backend.write_decision(_sample_record())
        assert result is False

    @pytest.mark.asyncio
    async def test_write_decision_success(self):
        backend = self._make_backend()
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        backend._client = mock_client
        backend._ready = True

        result = await backend.write_decision(_sample_record())
        assert result is True
        mock_client.post.assert_called_once()

        call_args = mock_client.post.call_args
        url = call_args[0][0]
        assert "loki" in url
        body = call_args[1]["json"]
        assert "streams" in body
        assert len(body["streams"]) == 1
        stream = body["streams"][0]
        assert stream["stream"]["app"] == "agentpep"
        assert len(stream["values"]) == 1
        # values[0] is [timestamp_ns, json_message]
        msg = json.loads(stream["values"][0][1])
        assert msg["decision_id"] == "d-001"

    @pytest.mark.asyncio
    async def test_write_batch(self):
        backend = self._make_backend()
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        backend._client = mock_client
        backend._ready = True

        records = [_sample_record(), _sample_record()]
        result = await backend.write_batch(records)
        assert result == 2

        body = mock_client.post.call_args[1]["json"]
        assert len(body["streams"][0]["values"]) == 2

    @pytest.mark.asyncio
    async def test_write_decision_api_error(self):
        backend = self._make_backend()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        backend._client = mock_client
        backend._ready = True

        result = await backend.write_decision(_sample_record())
        assert result is False

    @pytest.mark.asyncio
    async def test_query_returns_empty(self):
        backend = self._make_backend()
        result = await backend.query({"decision": "ALLOW"})
        assert result == []

    @pytest.mark.asyncio
    async def test_verify_integrity(self):
        backend = self._make_backend()
        result = await backend.verify_integrity()
        assert result.valid is True
        assert "Loki" in result.detail

    @pytest.mark.asyncio
    async def test_initialize_creates_client(self):
        backend = self._make_backend()
        await backend.initialize()
        assert backend.is_running
        assert backend._client is not None
        await backend.close()

    @pytest.mark.asyncio
    async def test_initialize_without_push_url(self):
        from app.backends.loki_audit import LokiAuditBackend

        backend = LokiAuditBackend(push_url="")
        await backend.initialize()
        assert not backend.is_running

    @pytest.mark.asyncio
    async def test_tenant_id_header(self):
        backend = self._make_backend()
        await backend.initialize()
        assert backend._client.headers["X-Scope-OrgID"] == "test-tenant"
        await backend.close()

    @pytest.mark.asyncio
    async def test_no_tenant_id_header_when_empty(self):
        from app.backends.loki_audit import LokiAuditBackend

        backend = LokiAuditBackend(
            push_url="http://loki:3100/loki/api/v1/push",
            tenant_id="",
        )
        await backend.initialize()
        assert "X-Scope-OrgID" not in backend._client.headers
        await backend.close()

    @pytest.mark.asyncio
    async def test_close(self):
        backend = self._make_backend()
        await backend.initialize()
        assert backend.is_running
        await backend.close()
        assert not backend.is_running

    @pytest.mark.asyncio
    async def test_verbosity_filtering_applied(self, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "audit_verbosity", "STANDARD")
        backend = self._make_backend()
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        backend._client = mock_client
        backend._ready = True

        await backend.write_decision(_sample_record())
        body = mock_client.post.call_args[1]["json"]
        msg = json.loads(body["streams"][0]["values"][0][1])
        assert "agent_id" in msg
        assert "tool_args_hash" not in msg
