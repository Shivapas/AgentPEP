"""MicrosoftTeamsChannel — Microsoft Teams Incoming Webhook notification channel.

Sprint 32 — APEP-255: Implements NotificationChannel for Microsoft Teams,
sending Adaptive Card payloads via incoming webhooks.
"""

from __future__ import annotations

import logging
from typing import Any

from app.backends.notification import NotificationChannel
from app.core.config import settings

logger = logging.getLogger(__name__)

# Severity-to-colour mapping for Adaptive Card accent bars
_SEVERITY_COLORS: dict[str, str] = {
    "critical": "attention",
    "error": "attention",
    "warning": "warning",
    "info": "good",
}


class MicrosoftTeamsChannel(NotificationChannel):
    """Microsoft Teams notification channel using Incoming Webhooks.

    Sends Adaptive Card payloads for alerts, approval requests, and
    resolution notifications.
    """

    def __init__(self, webhook_url: str | None = None) -> None:
        self._webhook_url = webhook_url or settings.teams_webhook_url
        self._client: Any = None
        self._ready = False

    async def initialize(self) -> None:
        if not self._webhook_url:
            logger.warning(
                "Teams webhook URL not configured — MicrosoftTeamsChannel disabled"
            )
            return
        try:
            import httpx

            self._client = httpx.AsyncClient(
                headers={"Content-Type": "application/json"},
                timeout=httpx.Timeout(10.0),
            )
            self._ready = True
            logger.info("MicrosoftTeamsChannel initialized")
        except Exception:
            logger.exception("Failed to initialize MicrosoftTeamsChannel")

    def _build_card(
        self,
        title: str,
        body_facts: list[dict[str, str]],
        style: str = "default",
    ) -> dict[str, Any]:
        """Build an Adaptive Card payload for Teams."""
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": title,
                                "weight": "Bolder",
                                "size": "Medium",
                                "style": style,
                            },
                            {
                                "type": "FactSet",
                                "facts": body_facts,
                            },
                        ],
                    },
                }
            ],
        }

    async def _post_card(self, card: dict[str, Any]) -> bool:
        """POST an Adaptive Card to the Teams webhook."""
        if not self._ready or self._client is None:
            return False
        try:
            response = await self._client.post(self._webhook_url, json=card)
            if response.status_code >= 400:
                logger.warning(
                    "Teams webhook returned %d", response.status_code
                )
                return False
            return True
        except Exception:
            logger.exception("Failed to post to Teams webhook")
            return False

    async def send_alert(self, alert: dict[str, Any]) -> bool:
        severity = alert.get("severity", "info")
        style = _SEVERITY_COLORS.get(severity, "default")
        title = f"🔔 {alert.get('title', 'AgentPEP Alert')}"

        facts = [
            {"title": "Severity", "value": severity.upper()},
            {"title": "Message", "value": alert.get("message", "—")},
        ]
        if alert.get("agent_id"):
            facts.append({"title": "Agent", "value": alert["agent_id"]})
        if alert.get("tool_name"):
            facts.append({"title": "Tool", "value": alert["tool_name"]})
        if "risk_score" in alert:
            facts.append(
                {"title": "Risk Score", "value": str(alert["risk_score"])}
            )

        card = self._build_card(title, facts, style=style)
        return await self._post_card(card)

    async def send_approval_request(self, request: dict[str, Any]) -> bool:
        ticket_id = request.get("ticket_id", "unknown")
        title = f"⏳ Escalation Approval Required — Ticket {ticket_id}"

        facts = [
            {"title": "Ticket ID", "value": ticket_id},
            {"title": "Agent", "value": request.get("agent_id", "—")},
            {"title": "Tool", "value": request.get("tool_name", "—")},
            {"title": "Risk Score", "value": str(request.get("risk_score", 0.0))},
            {"title": "Reason", "value": request.get("reason", "—")},
        ]
        if request.get("timeout_seconds"):
            facts.append(
                {
                    "title": "Timeout",
                    "value": f"{request['timeout_seconds']}s",
                }
            )

        card = self._build_card(title, facts, style="warning")
        return await self._post_card(card)

    async def send_resolution(self, resolution: dict[str, Any]) -> bool:
        ticket_id = resolution.get("ticket_id", "unknown")
        outcome = resolution.get("outcome", "UNKNOWN")
        title = f"✅ Escalation Resolved — Ticket {ticket_id}: {outcome}"

        facts = [
            {"title": "Ticket ID", "value": ticket_id},
            {"title": "Outcome", "value": outcome},
        ]
        if resolution.get("decided_by"):
            facts.append(
                {"title": "Decided By", "value": resolution["decided_by"]}
            )
        if resolution.get("reason"):
            facts.append(
                {"title": "Reason", "value": resolution["reason"]}
            )

        card = self._build_card(title, facts, style="good")
        return await self._post_card(card)

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                logger.exception(
                    "Error closing MicrosoftTeamsChannel HTTP client"
                )
            finally:
                self._ready = False
                self._client = None

    @property
    def is_running(self) -> bool:
        return self._ready
