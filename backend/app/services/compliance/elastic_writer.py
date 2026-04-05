"""APEP-176: Elasticsearch index writer.

Writes authorization decision events to a configurable Elasticsearch index.
Supports batching via the Bulk API, retry with backoff, and index template
configuration.
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

logger = logging.getLogger(__name__)


@dataclass
class ElasticsearchConfig:
    """Configuration for the Elasticsearch writer."""

    es_url: str = ""
    index_name: str = "agentpep-decisions"
    api_key: str = ""
    username: str = ""
    password: str = ""
    batch_size: int = 100
    flush_interval_s: float = 5.0
    max_retries: int = 3
    timeout_s: float = 10.0
    verify_ssl: bool = True


class ElasticsearchWriter:
    """Writes authorization decisions to an Elasticsearch index.

    Usage:
        writer = ElasticsearchWriter(config)
        await writer.index_event(decision_dict)
        await writer.flush()
    """

    def __init__(self, config: ElasticsearchConfig | None = None) -> None:
        self._config = config or ElasticsearchConfig()
        self._buffer: list[dict] = []
        self._lock = asyncio.Lock()
        self._client: httpx.AsyncClient | None = None

    @property
    def config(self) -> ElasticsearchConfig:
        return self._config

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            auth = None
            if self._config.username and self._config.password:
                auth = httpx.BasicAuth(self._config.username, self._config.password)
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.timeout_s),
                verify=self._config.verify_ssl,
                auth=auth,
            )
        return self._client

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/x-ndjson"}
        if self._config.api_key:
            headers["Authorization"] = f"ApiKey {self._config.api_key}"
        return headers

    def _prepare_document(self, decision: dict) -> dict:
        """Prepare a decision document for Elasticsearch indexing."""
        doc = dict(decision)
        if "timestamp" in doc and isinstance(doc["timestamp"], datetime):
            doc["timestamp"] = doc["timestamp"].isoformat()
        if "@timestamp" not in doc:
            doc["@timestamp"] = doc.get(
                "timestamp",
                datetime.now(UTC).isoformat(),
            )
        return doc

    async def index_event(self, decision: dict) -> None:
        """Buffer a decision for bulk indexing; auto-flush at batch_size."""
        async with self._lock:
            self._buffer.append(decision)
            if len(self._buffer) >= self._config.batch_size:
                await self._flush_locked()

    async def flush(self) -> None:
        """Force-flush all buffered events to Elasticsearch."""
        async with self._lock:
            await self._flush_locked()

    async def _flush_locked(self) -> None:
        """Bulk-index buffered events (must be called with lock held)."""
        if not self._buffer:
            return

        if not self._config.es_url:
            logger.warning("Elasticsearch not configured — dropping %d events", len(self._buffer))
            self._buffer.clear()
            return

        # Build NDJSON bulk payload
        lines: list[str] = []
        for decision in self._buffer:
            action = json.dumps({"index": {"_index": self._config.index_name}})
            doc = json.dumps(self._prepare_document(decision), default=str)
            lines.append(action)
            lines.append(doc)
        payload = "\n".join(lines) + "\n"
        count = len(self._buffer)
        self._buffer.clear()

        headers = self._build_headers()
        client = self._get_client()
        bulk_url = f"{self._config.es_url.rstrip('/')}/_bulk"

        for attempt in range(1, self._config.max_retries + 1):
            try:
                resp = await client.post(bulk_url, content=payload, headers=headers)
                if resp.status_code in (200, 201):
                    body = resp.json()
                    if not body.get("errors", False):
                        logger.info("Elasticsearch: indexed %d events", count)
                        return
                    # Partial failures
                    error_count = sum(
                        1
                        for item in body.get("items", [])
                        if "error" in item.get("index", {})
                    )
                    logger.warning(
                        "Elasticsearch bulk: %d/%d failed on attempt %d",
                        error_count,
                        count,
                        attempt,
                    )
                else:
                    logger.warning(
                        "Elasticsearch returned %d on attempt %d: %s",
                        resp.status_code,
                        attempt,
                        resp.text[:500],
                    )
            except httpx.HTTPError as exc:
                logger.warning("Elasticsearch attempt %d failed: %s", attempt, exc)

            if attempt < self._config.max_retries:
                await asyncio.sleep(2**attempt)

        logger.error(
            "Elasticsearch: failed to index %d events after %d attempts",
            count,
            self._config.max_retries,
        )

    async def close(self) -> None:
        """Flush remaining events and close HTTP client."""
        await self.flush()
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# Module-level singleton
elastic_writer = ElasticsearchWriter()
