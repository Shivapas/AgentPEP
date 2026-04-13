"""NotificationChannelRegistry — per-tenant notification channel management.

Sprint 32 — APEP-254: Registry that holds named NotificationChannel
instances and broadcasts notifications to all registered channels.
Follows the AuthProviderRegistry pattern from Sprint 31 (APEP-243).
"""

from __future__ import annotations

import logging
from typing import Any

from app.backends.notification import NotificationChannel

logger = logging.getLogger(__name__)


class NotificationChannelRegistry:
    """Central registry for notification channel instances.

    Channels are registered by name and broadcast methods fan out
    to all registered channels.  Per-channel exceptions are caught
    to ensure one failing channel does not block the others.
    """

    def __init__(self) -> None:
        self._channels: dict[str, NotificationChannel] = {}

    def register(self, name: str, channel: NotificationChannel) -> None:
        """Register a notification channel by name."""
        self._channels[name] = channel
        logger.info("Notification channel registered: %s", name)

    def unregister(self, name: str) -> None:
        """Remove a registered notification channel."""
        if name in self._channels:
            del self._channels[name]
            logger.info("Notification channel unregistered: %s", name)

    def get_channel(self, name: str) -> NotificationChannel | None:
        """Return a channel by name, or None if not registered."""
        return self._channels.get(name)

    def list_channels(self) -> list[str]:
        """Return the names of all registered channels."""
        return list(self._channels.keys())

    async def broadcast_alert(self, alert: dict[str, Any]) -> dict[str, bool]:
        """Send an alert to all registered channels.

        Returns:
            A dict mapping channel name to delivery success.
        """
        results: dict[str, bool] = {}
        for name, channel in self._channels.items():
            try:
                results[name] = await channel.send_alert(alert)
            except Exception:
                logger.exception("Alert delivery failed for channel %s", name)
                results[name] = False
        return results

    async def broadcast_approval_request(
        self, request: dict[str, Any]
    ) -> dict[str, bool]:
        """Send an approval request to all registered channels.

        Returns:
            A dict mapping channel name to delivery success.
        """
        results: dict[str, bool] = {}
        for name, channel in self._channels.items():
            try:
                results[name] = await channel.send_approval_request(request)
            except Exception:
                logger.exception(
                    "Approval request delivery failed for channel %s", name
                )
                results[name] = False
        return results

    async def broadcast_resolution(
        self, resolution: dict[str, Any]
    ) -> dict[str, bool]:
        """Send a resolution notification to all registered channels.

        Returns:
            A dict mapping channel name to delivery success.
        """
        results: dict[str, bool] = {}
        for name, channel in self._channels.items():
            try:
                results[name] = await channel.send_resolution(resolution)
            except Exception:
                logger.exception(
                    "Resolution delivery failed for channel %s", name
                )
                results[name] = False
        return results

    def reset(self) -> None:
        """Clear all registered channels (for testing)."""
        self._channels.clear()


# Module-level singleton
notification_registry = NotificationChannelRegistry()
