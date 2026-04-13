"""PagerDutyChannel — PagerDuty Events API v2 notification channel.

Sprint 32 — APEP-255: Implements NotificationChannel for PagerDuty,
sending trigger and resolve events via the Events API v2.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.backends.notification import NotificationChannel
from app.core.config import settings

logger = logging.getLogger(__name__)

_PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

_DEFAULT_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "error": "error",
    "warning": "warning",
    "info": "info",
}


class PagerDutyChannel(NotificationChannel):
    """PagerDuty notification channel using the Events API v2.

    Sends trigger events for alerts and approval requests, and
    resolve events for resolutions.
    """

    def __init__(
        self,
        routing_key: str | None = None,
        severity_mapping: dict[str, str] | None = None,
    ) -> None:
        self._routing_key = routing_key or settings.pagerduty_routing_key
        self._severity_map = severity_mapping or _DEFAULT_SEVERITY_MAP
        self._client: Any = None
        self._ready = False

    async def initialize(self) -> None:
        if not self._routing_key:
            logger.warning(
                "PagerDuty routing key not configured — PagerDutyChannel disabled"
            )
            return
        try:
            import httpx

            self._client = httpx.AsyncClient(
                headers={"Content-Type": "application/json"},
                timeout=httpx.Timeout(10.0),
            )
            self._ready = True
            logger.info("PagerDutyChannel initialized")
        except Exception:
            logger.exception("Failed to initialize PagerDutyChannel")

    def _map_severity(self, severity: str) -> str:
        return self._severity_map.get(severity.lower(), "warning")

    def _build_trigger_payload(
        self, summary: str, severity: str, dedup_key: str, custom_details: dict
    ) -> dict[str, Any]:
        return {
            "routing_key": self._routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": summary,
                "severity": self._map_severity(severity),
                "source": "agentpep",
                "component": "policy-engine",
                "custom_details": custom_details,
            },
        }

    async def send_alert(self, alert: dict[str, Any]) -> bool:
        if not self._ready or self._client is None:
            return False
        try:
            severity = alert.get("severity", "warning")
            title = alert.get("title", "AgentPEP Alert")
            dedup_key = f"agentpep-alert-{alert.get('session_id', 'unknown')}"

            payload = self._build_trigger_payload(
                summary=title,
                severity=severity,
                dedup_key=dedup_key,
                custom_details={
                    "message": alert.get("message", ""),
                    "agent_id": alert.get("agent_id", ""),
                    "tool_name": alert.get("tool_name", ""),
                    "risk_score": alert.get("risk_score", 0.0),
                    "session_id": alert.get("session_id", ""),
                },
            )

            response = await self._client.post(
                _PAGERDUTY_EVENTS_URL, json=payload
            )
            if response.status_code >= 400:
                logger.warning(
                    "PagerDuty API returned %d for alert", response.status_code
                )
                return False
            return True
        except Exception:
            logger.exception("Failed to send PagerDuty alert")
            return False

    async def send_approval_request(self, request: dict[str, Any]) -> bool:
        if not self._ready or self._client is None:
            return False
        try:
            ticket_id = request.get("ticket_id", "unknown")
            dedup_key = f"agentpep-escalation-{ticket_id}"

            payload = self._build_trigger_payload(
                summary=f"AgentPEP Escalation: {request.get('tool_name', 'unknown')} "
                f"requires approval (ticket {ticket_id})",
                severity="warning",
                dedup_key=dedup_key,
                custom_details={
                    "ticket_id": ticket_id,
                    "agent_id": request.get("agent_id", ""),
                    "tool_name": request.get("tool_name", ""),
                    "risk_score": request.get("risk_score", 0.0),
                    "reason": request.get("reason", ""),
                    "session_id": request.get("session_id", ""),
                    "timeout_seconds": request.get("timeout_seconds", 300),
                },
            )

            response = await self._client.post(
                _PAGERDUTY_EVENTS_URL, json=payload
            )
            if response.status_code >= 400:
                logger.warning(
                    "PagerDuty API returned %d for approval request",
                    response.status_code,
                )
                return False
            return True
        except Exception:
            logger.exception("Failed to send PagerDuty approval request")
            return False

    async def send_resolution(self, resolution: dict[str, Any]) -> bool:
        if not self._ready or self._client is None:
            return False
        try:
            ticket_id = resolution.get("ticket_id", "unknown")
            dedup_key = f"agentpep-escalation-{ticket_id}"

            payload = {
                "routing_key": self._routing_key,
                "event_action": "resolve",
                "dedup_key": dedup_key,
            }

            response = await self._client.post(
                _PAGERDUTY_EVENTS_URL, json=payload
            )
            if response.status_code >= 400:
                logger.warning(
                    "PagerDuty API returned %d for resolution",
                    response.status_code,
                )
                return False
            return True
        except Exception:
            logger.exception("Failed to send PagerDuty resolution")
            return False

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                logger.exception("Error closing PagerDutyChannel HTTP client")
            finally:
                self._ready = False
                self._client = None

    @property
    def is_running(self) -> bool:
        return self._ready
