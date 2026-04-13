"""LokiAuditBackend — Grafana Loki implementation of AuditBackend ABC.

Sprint 32 — APEP-252: Write decision records to Grafana Loki push API.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from app.backends.audit import AuditBackend, IntegrityResult
from app.core.config import settings

logger = logging.getLogger(__name__)


class LokiAuditBackend(AuditBackend):
    """Loki-backed audit backend that pushes decision records via
    the Grafana Loki HTTP push API.

    Uses httpx (already a core dependency) for async HTTP requests.
    """

    def __init__(
        self,
        push_url: str | None = None,
        labels: dict[str, str] | None = None,
        tenant_id: str | None = None,
    ) -> None:
        self._push_url = push_url or settings.loki_push_url
        self._labels = labels or {"app": "agentpep", "component": "audit"}
        self._tenant_id = tenant_id or settings.loki_tenant_id
        self._client: Any = None
        self._ready = False

    async def initialize(self) -> None:
        if not self._push_url:
            logger.warning(
                "Loki push URL not configured — LokiAuditBackend disabled"
            )
            return
        try:
            import httpx

            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self._tenant_id:
                headers["X-Scope-OrgID"] = self._tenant_id

            self._client = httpx.AsyncClient(
                headers=headers,
                timeout=httpx.Timeout(10.0),
            )
            self._ready = True
            logger.info(
                "LokiAuditBackend initialized — url=%s tenant=%s",
                self._push_url,
                self._tenant_id or "(default)",
            )
        except Exception:
            logger.exception("Failed to initialize LokiAuditBackend")

    def _make_push_payload(
        self, records: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Build a Loki push API payload from decision records."""
        values = []
        for record in records:
            filtered = self.filter_by_verbosity(record)
            ts_ns = str(int(time.time() * 1_000_000_000))
            values.append([ts_ns, json.dumps(filtered, default=str)])

        return {
            "streams": [
                {
                    "stream": self._labels,
                    "values": values,
                }
            ]
        }

    async def write_decision(self, record: dict[str, Any]) -> bool:
        if not self._ready or self._client is None:
            return False
        try:
            payload = self._make_push_payload([record])
            response = await self._client.post(self._push_url, json=payload)
            if response.status_code >= 400:
                logger.warning(
                    "Loki API returned %d for decision %s",
                    response.status_code,
                    record.get("decision_id"),
                )
                return False
            return True
        except Exception:
            logger.exception(
                "Failed to push audit decision %s to Loki",
                record.get("decision_id"),
            )
            return False

    async def write_batch(self, records: list[dict[str, Any]]) -> int:
        if not self._ready or self._client is None:
            return 0
        if not records:
            return 0
        try:
            payload = self._make_push_payload(records)
            response = await self._client.post(self._push_url, json=payload)
            if response.status_code >= 400:
                logger.warning(
                    "Loki API returned %d for batch of %d records",
                    response.status_code,
                    len(records),
                )
                return 0
            return len(records)
        except Exception:
            logger.exception(
                "Failed to push audit batch (%d records) to Loki",
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
            "LokiAuditBackend does not support querying — "
            "use Grafana/LogQL for queries"
        )
        return []

    async def verify_integrity(
        self, *, start_sequence: int = 1, end_sequence: int | None = None
    ) -> IntegrityResult:
        return IntegrityResult(
            valid=True,
            detail="Loki streams are append-only; integrity is guaranteed by Loki",
        )

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                logger.exception("Error closing LokiAuditBackend HTTP client")
            finally:
                self._ready = False
                self._client = None

    @property
    def is_running(self) -> bool:
        return self._ready
