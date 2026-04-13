"""Tests for Sprint 32 — Notification Channels.

APEP-254: NotificationChannel ABC
APEP-255: PagerDutyChannel and MicrosoftTeamsChannel
"""

import inspect
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.backends.notification import NotificationChannel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert_payload() -> dict:
    return {
        "severity": "warning",
        "title": "High-risk tool call detected",
        "message": "Agent agent-1 attempted file.delete with risk 0.9",
        "agent_id": "agent-1",
        "tool_name": "file.delete",
        "risk_score": 0.9,
        "session_id": "sess-1",
    }


def _approval_request() -> dict:
    return {
        "ticket_id": "esc-001",
        "agent_id": "agent-1",
        "tool_name": "db.drop_table",
        "risk_score": 0.85,
        "reason": "Tool exceeds risk threshold",
        "session_id": "sess-1",
        "timeout_seconds": 300,
    }


def _resolution_payload() -> dict:
    return {
        "ticket_id": "esc-001",
        "outcome": "APPROVED",
        "decided_by": "admin@acme.com",
        "reason": "Authorized for maintenance window",
    }


# ---------------------------------------------------------------------------
# APEP-254: NotificationChannel ABC
# ---------------------------------------------------------------------------


class TestNotificationChannelABC:
    """Verify NotificationChannel defines the required abstract interface."""

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            NotificationChannel()

    def test_abc_has_required_methods(self):
        abstract_methods = {
            name
            for name, _ in inspect.getmembers(NotificationChannel)
            if getattr(
                getattr(NotificationChannel, name, None),
                "__isabstractmethod__",
                False,
            )
        }
        assert "send_alert" in abstract_methods
        assert "send_approval_request" in abstract_methods
        assert "send_resolution" in abstract_methods


# ---------------------------------------------------------------------------
# NotificationChannelRegistry
# ---------------------------------------------------------------------------


class TestNotificationChannelRegistry:
    """Verify the notification channel registry broadcast behaviour."""

    def _make_mock_channel(self, *, send_ok: bool = True) -> NotificationChannel:
        channel = AsyncMock(spec=NotificationChannel)
        channel.send_alert = AsyncMock(return_value=send_ok)
        channel.send_approval_request = AsyncMock(return_value=send_ok)
        channel.send_resolution = AsyncMock(return_value=send_ok)
        return channel

    @pytest.mark.asyncio
    async def test_register_and_list(self):
        from app.backends.notification_registry import NotificationChannelRegistry

        registry = NotificationChannelRegistry()
        ch = self._make_mock_channel()
        registry.register("test", ch)
        assert "test" in registry.list_channels()
        assert registry.get_channel("test") is ch

    @pytest.mark.asyncio
    async def test_unregister(self):
        from app.backends.notification_registry import NotificationChannelRegistry

        registry = NotificationChannelRegistry()
        ch = self._make_mock_channel()
        registry.register("test", ch)
        registry.unregister("test")
        assert "test" not in registry.list_channels()

    @pytest.mark.asyncio
    async def test_broadcast_alert_fans_out(self):
        from app.backends.notification_registry import NotificationChannelRegistry

        registry = NotificationChannelRegistry()
        ch1 = self._make_mock_channel()
        ch2 = self._make_mock_channel()
        registry.register("ch1", ch1)
        registry.register("ch2", ch2)

        results = await registry.broadcast_alert(_alert_payload())
        assert results == {"ch1": True, "ch2": True}
        ch1.send_alert.assert_called_once()
        ch2.send_alert.assert_called_once()

    @pytest.mark.asyncio
    async def test_broadcast_approval_request_fans_out(self):
        from app.backends.notification_registry import NotificationChannelRegistry

        registry = NotificationChannelRegistry()
        ch1 = self._make_mock_channel()
        ch2 = self._make_mock_channel()
        registry.register("ch1", ch1)
        registry.register("ch2", ch2)

        results = await registry.broadcast_approval_request(_approval_request())
        assert results == {"ch1": True, "ch2": True}

    @pytest.mark.asyncio
    async def test_broadcast_resolution_fans_out(self):
        from app.backends.notification_registry import NotificationChannelRegistry

        registry = NotificationChannelRegistry()
        ch1 = self._make_mock_channel()
        registry.register("ch1", ch1)

        results = await registry.broadcast_resolution(_resolution_payload())
        assert results == {"ch1": True}

    @pytest.mark.asyncio
    async def test_one_failure_does_not_block_others(self):
        from app.backends.notification_registry import NotificationChannelRegistry

        registry = NotificationChannelRegistry()
        ch_ok = self._make_mock_channel(send_ok=True)
        ch_fail = self._make_mock_channel()
        ch_fail.send_alert = AsyncMock(side_effect=RuntimeError("boom"))
        registry.register("ok", ch_ok)
        registry.register("fail", ch_fail)

        results = await registry.broadcast_alert(_alert_payload())
        assert results["ok"] is True
        assert results["fail"] is False

    @pytest.mark.asyncio
    async def test_reset(self):
        from app.backends.notification_registry import NotificationChannelRegistry

        registry = NotificationChannelRegistry()
        registry.register("ch1", self._make_mock_channel())
        registry.reset()
        assert registry.list_channels() == []


# ---------------------------------------------------------------------------
# APEP-255: PagerDutyChannel
# ---------------------------------------------------------------------------


class TestPagerDutyChannel:
    """Tests for the PagerDuty notification channel."""

    def _make_channel(self):
        from app.backends.pagerduty_channel import PagerDutyChannel

        return PagerDutyChannel(routing_key="test-routing-key")

    def test_implements_notification_channel(self):
        ch = self._make_channel()
        assert isinstance(ch, NotificationChannel)

    @pytest.mark.asyncio
    async def test_send_alert_success(self):
        ch = self._make_channel()
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        ch._client = mock_client
        ch._ready = True

        result = await ch.send_alert(_alert_payload())
        assert result is True
        call_args = mock_client.post.call_args
        payload = call_args[1]["json"]
        assert payload["event_action"] == "trigger"
        assert payload["routing_key"] == "test-routing-key"
        assert payload["payload"]["severity"] == "warning"

    @pytest.mark.asyncio
    async def test_send_alert_api_error(self):
        ch = self._make_channel()
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        ch._client = mock_client
        ch._ready = True

        result = await ch.send_alert(_alert_payload())
        assert result is False

    @pytest.mark.asyncio
    async def test_send_approval_request_payload(self):
        ch = self._make_channel()
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        ch._client = mock_client
        ch._ready = True

        result = await ch.send_approval_request(_approval_request())
        assert result is True
        payload = mock_client.post.call_args[1]["json"]
        assert payload["event_action"] == "trigger"
        assert "esc-001" in payload["dedup_key"]
        assert payload["payload"]["custom_details"]["ticket_id"] == "esc-001"

    @pytest.mark.asyncio
    async def test_send_resolution_uses_dedup_key(self):
        ch = self._make_channel()
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        ch._client = mock_client
        ch._ready = True

        result = await ch.send_resolution(_resolution_payload())
        assert result is True
        payload = mock_client.post.call_args[1]["json"]
        assert payload["event_action"] == "resolve"
        assert "esc-001" in payload["dedup_key"]

    @pytest.mark.asyncio
    async def test_severity_mapping(self):
        ch = self._make_channel()
        assert ch._map_severity("critical") == "critical"
        assert ch._map_severity("CRITICAL") == "critical"
        assert ch._map_severity("unknown") == "warning"

    @pytest.mark.asyncio
    async def test_not_ready_returns_false(self):
        ch = self._make_channel()
        assert await ch.send_alert(_alert_payload()) is False

    @pytest.mark.asyncio
    async def test_initialize_and_close(self):
        ch = self._make_channel()
        await ch.initialize()
        assert ch.is_running
        await ch.close()
        assert not ch.is_running

    @pytest.mark.asyncio
    async def test_initialize_without_routing_key(self):
        from app.backends.pagerduty_channel import PagerDutyChannel

        ch = PagerDutyChannel(routing_key="")
        await ch.initialize()
        assert not ch.is_running


# ---------------------------------------------------------------------------
# APEP-255: MicrosoftTeamsChannel
# ---------------------------------------------------------------------------


class TestMicrosoftTeamsChannel:
    """Tests for the Microsoft Teams notification channel."""

    def _make_channel(self):
        from app.backends.teams_channel import MicrosoftTeamsChannel

        return MicrosoftTeamsChannel(
            webhook_url="https://teams.example.com/webhook"
        )

    def test_implements_notification_channel(self):
        ch = self._make_channel()
        assert isinstance(ch, NotificationChannel)

    @pytest.mark.asyncio
    async def test_send_alert_success(self):
        ch = self._make_channel()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        ch._client = mock_client
        ch._ready = True

        result = await ch.send_alert(_alert_payload())
        assert result is True
        call_args = mock_client.post.call_args
        url = call_args[0][0]
        assert url == "https://teams.example.com/webhook"
        card = call_args[1]["json"]
        assert card["type"] == "message"
        assert len(card["attachments"]) == 1
        content = card["attachments"][0]["content"]
        assert content["type"] == "AdaptiveCard"

    @pytest.mark.asyncio
    async def test_send_approval_request_card_structure(self):
        ch = self._make_channel()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        ch._client = mock_client
        ch._ready = True

        result = await ch.send_approval_request(_approval_request())
        assert result is True
        card = mock_client.post.call_args[1]["json"]
        content = card["attachments"][0]["content"]
        facts = content["body"][1]["facts"]
        fact_titles = [f["title"] for f in facts]
        assert "Ticket ID" in fact_titles
        assert "Agent" in fact_titles
        assert "Tool" in fact_titles

    @pytest.mark.asyncio
    async def test_send_resolution_card_structure(self):
        ch = self._make_channel()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        ch._client = mock_client
        ch._ready = True

        result = await ch.send_resolution(_resolution_payload())
        assert result is True
        card = mock_client.post.call_args[1]["json"]
        content = card["attachments"][0]["content"]
        # Title should contain ticket id and outcome
        title_text = content["body"][0]["text"]
        assert "esc-001" in title_text
        assert "APPROVED" in title_text

    @pytest.mark.asyncio
    async def test_api_error_returns_false(self):
        ch = self._make_channel()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        ch._client = mock_client
        ch._ready = True

        result = await ch.send_alert(_alert_payload())
        assert result is False

    @pytest.mark.asyncio
    async def test_not_ready_returns_false(self):
        ch = self._make_channel()
        assert await ch.send_alert(_alert_payload()) is False

    @pytest.mark.asyncio
    async def test_initialize_and_close(self):
        ch = self._make_channel()
        await ch.initialize()
        assert ch.is_running
        await ch.close()
        assert not ch.is_running

    @pytest.mark.asyncio
    async def test_initialize_without_webhook_url(self):
        from app.backends.teams_channel import MicrosoftTeamsChannel

        ch = MicrosoftTeamsChannel(webhook_url="")
        await ch.initialize()
        assert not ch.is_running
