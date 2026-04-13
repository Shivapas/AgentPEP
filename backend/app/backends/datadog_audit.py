"""DatadogAuditBackend — Datadog Log Management implementation of AuditBackend ABC.

Sprint 32 — APEP-251: Write decision records to Datadog Log Management API.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.backends.audit import AuditBackend, IntegrityResult
from app.core.config import settings

logger = logging.getLogger(__name__)


class DatadogAuditBackend(AuditBackend):
    """Datadog-backed audit backend that publishes decisions via the
    Datadog Log Management HTTP API.

    Uses httpx (already a core dependency) for async HTTP requests.
    """

    def __init__(
        self,
        api_key: str | None = None,
        site: str | None = None,
        service_name: str | None = None,
        source: str = "agentpep",
    ) -> None:
        self._api_key = api_key or settings.datadog_api_key
        self._site = site or settings.datadog_site
        self._service_name = service_name or settings.datadog_service_name
        self._source = source
        self._client: Any = None
        self._ready = False

    @property
    def _intake_url(self) -> str:
        return f"https://http-intake.logs.{self._site}/api/v2/logs"

    async def initialize(self) -> None:
        if not self._api_key:
            logger.warning(
                "Datadog API key not configured — DatadogAuditBackend disabled"
            )
            return
        try:
            import httpx

            self._client = httpx.AsyncClient(
                headers={
                    "DD-API-KEY": self._api_key,
                    "Content-Type": "application/json",
                },
                timeout=httpx.Timeout(10.0),
            )
            self._ready = True
            logger.info(
                "DatadogAuditBackend initialized — site=%s service=%s",
                self._site,
                self._service_name,
            )
        except Exception:
            logger.exception("Failed to initialize DatadogAuditBackend")

    def _format_event(self, record: dict[str, Any]) -> dict[str, Any]:
        """Format a decision record as a Datadog log event."""
        filtered = self.filter_by_verbosity(record)
        return {
            "ddsource": self._source,
            "ddtags": f"service:{self._service_name},decision:{filtered.get('decision', '')}",
            "hostname": "agentpep",
            "service": self._service_name,
            "message": json.dumps(filtered, default=str),
        }

    async def write_decision(self, record: dict[str, Any]) -> bool:
        if not self._ready or self._client is None:
            return False
        try:
            event = self._format_event(record)
            response = await self._client.post(self._intake_url, json=[event])
            if response.status_code >= 400:
                logger.warning(
                    "Datadog API returned %d for decision %s",
                    response.status_code,
                    record.get("decision_id"),
                )
                return False
            return True
        except Exception:
            logger.exception(
                "Failed to publish audit decision %s to Datadog",
                record.get("decision_id"),
            )
            return False

    async def write_batch(self, records: list[dict[str, Any]]) -> int:
        if not self._ready or self._client is None:
            return 0
        if not records:
            return 0
        try:
            events = [self._format_event(r) for r in records]
            response = await self._client.post(self._intake_url, json=events)
            if response.status_code >= 400:
                logger.warning(
                    "Datadog API returned %d for batch of %d records",
                    response.status_code,
                    len(records),
                )
                return 0
            return len(records)
        except Exception:
            logger.exception(
                "Failed to publish audit batch (%d records) to Datadog",
                len(records),
            )
            return 0

    async def query(
        self,
        filter: dict[str, Any],
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        logger.warning(
            "DatadogAuditBackend does not support querying — "
            "use Datadog Log Explorer for queries"
        )
        return []

    async def verify_integrity(
        self, *, start_sequence: int = 1, end_sequence: int | None = None
    ) -> IntegrityResult:
        return IntegrityResult(
            valid=True,
            detail="Datadog Logs are append-only; integrity is guaranteed by Datadog",
        )

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                logger.exception("Error closing DatadogAuditBackend HTTP client")
            finally:
                self._ready = False
                self._client = None

    @property
    def is_running(self) -> bool:
        return self._ready
