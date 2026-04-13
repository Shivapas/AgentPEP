"""NotificationChannel ABC — pluggable notification interface for AgentPEP.

Sprint 32 — APEP-254: Abstract base class for notification channels with
methods: send_alert, send_approval_request, send_resolution.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class NotificationChannel(ABC):
    """Abstract base class for AgentPEP notification channels.

    Implementations deliver alerts, approval requests, and resolution
    notifications to external systems (PagerDuty, Microsoft Teams, etc.).
    """

    @abstractmethod
    async def send_alert(self, alert: dict[str, Any]) -> bool:
        """Send a security or policy alert notification.

        Args:
            alert: Alert payload containing at minimum:
                - severity: str ("critical", "error", "warning", "info")
                - title: str
                - message: str
                - agent_id: str (optional)
                - tool_name: str (optional)
                - risk_score: float (optional)
                - session_id: str (optional)

        Returns:
            True if the alert was delivered successfully.
        """

    @abstractmethod
    async def send_approval_request(self, request: dict[str, Any]) -> bool:
        """Send an escalation approval request notification.

        Args:
            request: Approval request payload containing at minimum:
                - ticket_id: str
                - agent_id: str
                - tool_name: str
                - risk_score: float
                - reason: str
                - session_id: str (optional)
                - timeout_seconds: int (optional)

        Returns:
            True if the request was delivered successfully.
        """

    @abstractmethod
    async def send_resolution(self, resolution: dict[str, Any]) -> bool:
        """Send an escalation resolution notification.

        Args:
            resolution: Resolution payload containing at minimum:
                - ticket_id: str
                - outcome: str ("APPROVED", "DENIED", "TIMEOUT")
                - decided_by: str (optional)
                - reason: str (optional)

        Returns:
            True if the resolution notification was delivered successfully.
        """

    async def initialize(self) -> None:
        """Perform any startup initialization. Override in subclasses if needed."""

    async def close(self) -> None:
        """Clean up resources. Override in subclasses if needed."""
