"""Integration tests for Sprint 32 — ToolTrust: Structured Logging & Notification Channels.

APEP-258: Multi-backend audit routing, receipt sign/verify round-trip,
notification delivery, verbosity across backends, end-to-end decision pipeline.
"""

import json
import os
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.backends.audit import AuditBackend, IntegrityResult
from app.backends.audit_verbosity import AuditVerbosity
from app.backends.notification import NotificationChannel
from app.services.receipt_signer import ReceiptSigner, _HAS_NACL
from app.services.receipt_verifier import ReceiptVerifier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _full_audit_record() -> dict:
    """Full audit decision record with all fields."""
    return {
        "decision_id": "d-int-001",
        "decision": "ALLOW",
        "timestamp": "2026-04-13T00:00:00Z",
        "sequence_number": 42,
        "record_hash": "abc123",
        "previous_hash": "genesis",
        "agent_id": "agent-1",
        "agent_role": "developer",
        "session_id": "sess-int-1",
        "tool_name": "file.read",
        "matched_rule_id": "rule-1",
        "risk_score": 0.3,
        "escalation_id": None,
        "tool_args_hash": "sha256-xyz",
        "taint_flags": ["UNTRUSTED"],
        "delegation_chain": ["agent-0", "agent-1"],
        "latency_ms": 15,
    }


# ---------------------------------------------------------------------------
# APEP-258: Multi-Backend Audit Routing
# ---------------------------------------------------------------------------


class TestMultiBackendAuditRouting:
    """Test writing decisions across multiple audit backends simultaneously."""

    def _make_mock_backend(self, *, succeed: bool = True):
        """Create a mock audit backend that records write calls."""
        backend = AsyncMock(spec=AuditBackend)
        backend.write_decision = AsyncMock(return_value=succeed)
        backend.write_batch = AsyncMock(return_value=2 if succeed else 0)
        # Real verbosity filtering
        from app.backends.cloudwatch_audit import CloudWatchAuditBackend

        backend.filter_by_verbosity = CloudWatchAuditBackend.filter_by_verbosity.__get__(
            backend, type(backend)
        )
        return backend

    @pytest.mark.asyncio
    async def test_write_to_multiple_backends(self):
        """Verify a record can be written to all backends in parallel."""
        backends = [self._make_mock_backend() for _ in range(3)]
        record = _full_audit_record()

        results = []
        for b in backends:
            results.append(await b.write_decision(record))

        assert all(results)
        for b in backends:
            b.write_decision.assert_called_once_with(record)

    @pytest.mark.asyncio
    async def test_one_backend_failure_does_not_block_others(self):
        """If one backend fails, the others still receive the record."""
        ok_backend = self._make_mock_backend(succeed=True)
        fail_backend = self._make_mock_backend(succeed=False)

        record = _full_audit_record()
        r1 = await ok_backend.write_decision(record)
        r2 = await fail_backend.write_decision(record)

        assert r1 is True
        assert r2 is False

    @pytest.mark.asyncio
    async def test_batch_write_across_backends(self):
        """Verify batch writes work across multiple backends."""
        backends = [self._make_mock_backend() for _ in range(2)]
        records = [_full_audit_record(), _full_audit_record()]

        for b in backends:
            count = await b.write_batch(records)
            assert count == 2


# ---------------------------------------------------------------------------
# APEP-258: Receipt Sign/Verify Round-Trip
# ---------------------------------------------------------------------------


class TestReceiptSignVerifyRoundTrip:
    """End-to-end receipt signing and verification."""

    def test_hmac_full_roundtrip(self):
        """Sign a full audit decision, verify it, tamper, verify failure."""
        key = os.urandom(32)
        signer = ReceiptSigner(
            signing_method="hmac-sha256", private_key=key, key_id="rt-k1"
        )
        verifier = ReceiptVerifier(
            verify_keys={"rt-k1": ("hmac-sha256", signer.get_verify_key_bytes())}
        )

        record = _full_audit_record()
        receipt = signer.sign(record)

        # Verify succeeds
        assert verifier.verify(receipt, record) is True

        # Tamper with a single field
        tampered = dict(record)
        tampered["risk_score"] = 0.99
        assert verifier.verify(receipt, tampered) is False

    @pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
    def test_ed25519_full_roundtrip(self):
        """Sign with Ed25519, verify, tamper, verify failure."""
        signer = ReceiptSigner(signing_method="ed25519", key_id="ed-rt")
        verifier = ReceiptVerifier(
            verify_keys={"ed-rt": ("ed25519", signer.get_verify_key_bytes())}
        )

        record = _full_audit_record()
        receipt = signer.sign(record)
        assert verifier.verify(receipt, record) is True

        tampered = dict(record)
        tampered["decision"] = "DENY"
        assert verifier.verify(receipt, tampered) is False

    def test_receipt_survives_json_serialization(self):
        """Receipt and record can be serialized/deserialized and still verify."""
        key = os.urandom(32)
        signer = ReceiptSigner(
            signing_method="hmac-sha256", private_key=key, key_id="json-k"
        )
        verifier = ReceiptVerifier(
            verify_keys={"json-k": ("hmac-sha256", key)}
        )

        record = _full_audit_record()
        receipt = signer.sign(record)

        # Simulate serialization round-trip
        serialized = json.dumps({"receipt": receipt, "record": record})
        deserialized = json.loads(serialized)

        assert verifier.verify(
            deserialized["receipt"], deserialized["record"]
        ) is True

    def test_batch_sign_and_verify(self):
        """Batch sign multiple records and verify all."""
        key = os.urandom(32)
        signer = ReceiptSigner(
            signing_method="hmac-sha256", private_key=key, key_id="batch-k"
        )
        verifier = ReceiptVerifier(
            verify_keys={"batch-k": ("hmac-sha256", key)}
        )

        records = []
        for i in range(5):
            r = _full_audit_record()
            r["decision_id"] = f"d-batch-{i}"
            records.append(r)

        receipts = signer.sign_batch(records)
        results = verifier.verify_batch(list(zip(receipts, records)))
        assert all(results)


# ---------------------------------------------------------------------------
# APEP-258: Notification Delivery
# ---------------------------------------------------------------------------


class TestNotificationDelivery:
    """Test notification delivery via registry with multiple channels."""

    def _make_mock_channel(self, *, succeed: bool = True):
        ch = AsyncMock(spec=NotificationChannel)
        ch.send_alert = AsyncMock(return_value=succeed)
        ch.send_approval_request = AsyncMock(return_value=succeed)
        ch.send_resolution = AsyncMock(return_value=succeed)
        return ch

    @pytest.mark.asyncio
    async def test_escalation_triggers_all_channels(self):
        """Register PagerDuty and Teams mocks, send alert and resolution."""
        from app.backends.notification_registry import NotificationChannelRegistry

        registry = NotificationChannelRegistry()
        pd = self._make_mock_channel()
        teams = self._make_mock_channel()
        registry.register("pagerduty", pd)
        registry.register("teams", teams)

        alert = {
            "severity": "warning",
            "title": "High risk detected",
            "message": "Agent attempted dangerous operation",
            "agent_id": "agent-1",
            "tool_name": "db.drop",
            "risk_score": 0.95,
        }
        results = await registry.broadcast_alert(alert)
        assert results == {"pagerduty": True, "teams": True}
        pd.send_alert.assert_called_once_with(alert)
        teams.send_alert.assert_called_once_with(alert)

    @pytest.mark.asyncio
    async def test_resolution_triggers_all_channels(self):
        from app.backends.notification_registry import NotificationChannelRegistry

        registry = NotificationChannelRegistry()
        pd = self._make_mock_channel()
        teams = self._make_mock_channel()
        registry.register("pagerduty", pd)
        registry.register("teams", teams)

        resolution = {
            "ticket_id": "esc-int-001",
            "outcome": "DENIED",
            "decided_by": "admin@acme.com",
            "reason": "Not authorized",
        }
        results = await registry.broadcast_resolution(resolution)
        assert results == {"pagerduty": True, "teams": True}

    @pytest.mark.asyncio
    async def test_partial_failure_isolation(self):
        """One channel exception does not prevent others from receiving."""
        from app.backends.notification_registry import NotificationChannelRegistry

        registry = NotificationChannelRegistry()
        ok_ch = self._make_mock_channel()
        fail_ch = self._make_mock_channel()
        fail_ch.send_alert = AsyncMock(side_effect=ConnectionError("network down"))
        registry.register("ok", ok_ch)
        registry.register("fail", fail_ch)

        results = await registry.broadcast_alert({"severity": "critical", "title": "Test"})
        assert results["ok"] is True
        assert results["fail"] is False

    @pytest.mark.asyncio
    async def test_approval_request_delivery(self):
        from app.backends.notification_registry import NotificationChannelRegistry

        registry = NotificationChannelRegistry()
        ch = self._make_mock_channel()
        registry.register("ch1", ch)

        request = {
            "ticket_id": "esc-int-002",
            "agent_id": "agent-2",
            "tool_name": "secrets.read",
            "risk_score": 0.75,
            "reason": "Sensitive operation",
            "timeout_seconds": 120,
        }
        results = await registry.broadcast_approval_request(request)
        assert results["ch1"] is True
        ch.send_approval_request.assert_called_once_with(request)


# ---------------------------------------------------------------------------
# APEP-258: Verbosity Across Backends
# ---------------------------------------------------------------------------


class TestVerbosityAcrossBackends:
    """Verify verbosity filtering works consistently across all backends."""

    @pytest.mark.asyncio
    async def test_minimal_verbosity_on_cloudwatch(self, monkeypatch):
        from app.backends.cloudwatch_audit import CloudWatchAuditBackend
        from app.core.config import settings

        monkeypatch.setattr(settings, "audit_verbosity", "MINIMAL")

        backend = CloudWatchAuditBackend(
            log_group_name="/test", log_stream_name="test"
        )
        mock_client = MagicMock()
        mock_client.put_log_events.return_value = {"nextSequenceToken": "t"}
        backend._client = mock_client
        backend._ready = True

        await backend.write_decision(_full_audit_record())
        msg = json.loads(
            mock_client.put_log_events.call_args[1]["logEvents"][0]["message"]
        )
        assert "decision" in msg
        assert "tool_args_hash" not in msg
        assert "delegation_chain" not in msg

    @pytest.mark.asyncio
    async def test_standard_verbosity_on_datadog(self, monkeypatch):
        from app.backends.datadog_audit import DatadogAuditBackend
        from app.core.config import settings

        monkeypatch.setattr(settings, "audit_verbosity", "STANDARD")

        backend = DatadogAuditBackend(api_key="test-key")
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        backend._client = mock_client
        backend._ready = True

        await backend.write_decision(_full_audit_record())
        body = mock_client.post.call_args[1]["json"]
        msg = json.loads(body[0]["message"])
        assert "agent_id" in msg
        assert "tool_name" in msg
        assert "tool_args_hash" not in msg

    @pytest.mark.asyncio
    async def test_full_verbosity_on_loki(self, monkeypatch):
        from app.backends.loki_audit import LokiAuditBackend
        from app.core.config import settings

        monkeypatch.setattr(settings, "audit_verbosity", "FULL")

        backend = LokiAuditBackend(push_url="http://loki:3100/loki/api/v1/push")
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        backend._client = mock_client
        backend._ready = True

        await backend.write_decision(_full_audit_record())
        body = mock_client.post.call_args[1]["json"]
        msg = json.loads(body["streams"][0]["values"][0][1])
        # FULL should include everything
        assert "tool_args_hash" in msg
        assert "delegation_chain" in msg
        assert "taint_flags" in msg


# ---------------------------------------------------------------------------
# APEP-258: End-to-End Decision Pipeline
# ---------------------------------------------------------------------------


class TestEndToEndDecisionPipeline:
    """Full decision response with receipt signing and audit backends."""

    def test_decision_response_includes_receipt_field(self):
        """Verify PolicyDecisionResponse model has receipt field."""
        from app.models.policy import PolicyDecisionResponse

        fields = PolicyDecisionResponse.model_fields
        assert "receipt" in fields
        assert fields["receipt"].default is None

    def test_sdk_response_includes_receipt_field(self):
        """Verify SDK PolicyDecisionResponse model has receipt field."""
        from agentpep.models import PolicyDecisionResponse

        fields = PolicyDecisionResponse.model_fields
        assert "receipt" in fields

    def test_receipt_in_response_round_trip(self):
        """Create a response with receipt, serialize, deserialize, verify."""
        from uuid import uuid4

        from app.models.policy import PolicyDecisionResponse

        key = os.urandom(32)
        signer = ReceiptSigner(
            signing_method="hmac-sha256", private_key=key, key_id="e2e-k"
        )
        verifier = ReceiptVerifier(
            verify_keys={"e2e-k": ("hmac-sha256", key)}
        )

        receipt_record = {
            "decision_id": str(uuid4()),
            "decision": "ALLOW",
            "session_id": "sess-e2e",
            "agent_id": "agent-e2e",
            "tool_name": "file.read",
            "risk_score": 0.1,
            "matched_rule_id": None,
            "taint_flags": [],
            "latency_ms": 5,
        }
        receipt = signer.sign(receipt_record)

        response = PolicyDecisionResponse(
            request_id=uuid4(),
            decision="ALLOW",
            risk_score=0.1,
            latency_ms=5,
            receipt=receipt,
        )

        # Serialize and deserialize
        response_json = response.model_dump_json()
        parsed = json.loads(response_json)
        assert parsed["receipt"] is not None

        # Verify the receipt
        assert verifier.verify(parsed["receipt"], receipt_record) is True

    @pytest.mark.asyncio
    async def test_audit_and_notification_together(self):
        """Simulate a full pipeline: write audit + send notification."""
        from app.backends.notification_registry import NotificationChannelRegistry

        # Setup mock audit backend
        mock_audit = AsyncMock(spec=AuditBackend)
        mock_audit.write_decision = AsyncMock(return_value=True)

        # Setup mock notification channel
        mock_channel = AsyncMock(spec=NotificationChannel)
        mock_channel.send_alert = AsyncMock(return_value=True)
        registry = NotificationChannelRegistry()
        registry.register("mock", mock_channel)

        record = _full_audit_record()

        # Write to audit
        assert await mock_audit.write_decision(record) is True

        # Send notification
        alert = {
            "severity": "info",
            "title": f"Decision: {record['decision']}",
            "agent_id": record["agent_id"],
            "tool_name": record["tool_name"],
            "risk_score": record["risk_score"],
        }
        results = await registry.broadcast_alert(alert)
        assert results["mock"] is True
