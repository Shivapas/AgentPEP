"""APEP-175: Splunk HTTP Event Collector (HEC) forwarder.

Consumes authorization decisions from Kafka and forwards them to a Splunk
HEC endpoint. Supports batching, retry with exponential backoff, and
configurable source/sourcetype/index metadata.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class SplunkHECConfig:
    """Configuration for the Splunk HEC forwarder."""

    hec_url: str = ""
    hec_token: str = ""
    index: str = "agentpep"
    source: str = "agentpep-engine"
    sourcetype: str = "agentpep:decision"
    batch_size: int = 50
    flush_interval_s: float = 5.0
    max_retries: int = 3
    timeout_s: float = 10.0
    verify_ssl: bool = True


class SplunkHECForwarder:
    """Forwards authorization decision events to Splunk via HEC.

    Usage:
        forwarder = SplunkHECForwarder(config)
        await forwarder.send_event(decision_dict)
        # or batch:
        await forwarder.flush()
    """

    def __init__(self, config: SplunkHECConfig | None = None) -> None:
        self._config = config or SplunkHECConfig()
        self._buffer: list[dict] = []
        self._lock = asyncio.Lock()
        self._client: httpx.AsyncClient | None = None

    @property
    def config(self) -> SplunkHECConfig:
        return self._config

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.timeout_s),
                verify=self._config.verify_ssl,
            )
        return self._client

    def _build_hec_event(self, decision: dict) -> dict:
        """Wrap a decision dict in Splunk HEC event envelope."""
        return {
            "time": decision.get("timestamp", time.time()),
            "source": self._config.source,
            "sourcetype": self._config.sourcetype,
            "index": self._config.index,
            "event": decision,
        }

    async def send_event(self, decision: dict) -> None:
        """Buffer a decision event; auto-flush when batch_size is reached."""
        async with self._lock:
            self._buffer.append(decision)
            if len(self._buffer) >= self._config.batch_size:
                await self._flush_locked()

    async def flush(self) -> None:
        """Force-flush all buffered events to Splunk."""
        async with self._lock:
            await self._flush_locked()

    async def _flush_locked(self) -> None:
        """Send buffered events to Splunk HEC (must be called with lock held)."""
        if not self._buffer:
            return

        if not self._config.hec_url or not self._config.hec_token:
            logger.warning("Splunk HEC not configured — dropping %d events", len(self._buffer))
            self._buffer.clear()
            return

        events = [self._build_hec_event(d) for d in self._buffer]
        payload = "\n".join(json.dumps(e) for e in events)
        self._buffer.clear()

        headers = {
            "Authorization": f"Splunk {self._config.hec_token}",
            "Content-Type": "application/json",
        }

        client = self._get_client()
        for attempt in range(1, self._config.max_retries + 1):
            try:
                resp = await client.post(
                    self._config.hec_url,
                    content=payload,
                    headers=headers,
                )
                if resp.status_code == 200:
                    logger.info("Splunk HEC: forwarded %d events", len(events))
                    return
                logger.warning(
                    "Splunk HEC returned %d on attempt %d: %s",
                    resp.status_code,
                    attempt,
                    resp.text,
                )
            except httpx.HTTPError as exc:
                logger.warning("Splunk HEC attempt %d failed: %s", attempt, exc)

            if attempt < self._config.max_retries:
                await asyncio.sleep(2**attempt)

        logger.error("Splunk HEC: failed to send %d events after %d attempts",
                      len(events), self._config.max_retries)

    async def close(self) -> None:
        """Flush remaining events and close HTTP client."""
        await self.flush()
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# Module-level singleton
splunk_forwarder = SplunkHECForwarder()
