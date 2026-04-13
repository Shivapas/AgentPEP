"""RedisStorageBackend — Redis implementation of StorageBackend ABC.

Sprint 31 — APEP-244: Redis-backed policy cache, session store,
and taint graph persistence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import Any

from app.backends.storage import StorageBackend
from app.core.config import settings

logger = logging.getLogger(__name__)

_DEFAULT_KEY_PREFIX = "agentpep"


class RedisStorageBackend(StorageBackend):
    """Redis-backed storage implementing the StorageBackend interface.

    Maps StorageBackend operations to Redis data structures:
    - ``get()`` — ``HGET`` on a hash keyed by collection name.
    - ``put()`` — ``HSET`` with optional TTL via a companion key.
    - ``delete()`` — ``HDEL``.
    - ``query()`` — ``HSCAN`` with client-side filter matching.
    - ``health_check()`` — ``PING``.

    Documents are stored as JSON-serialised strings in Redis hashes.
    The key schema is: ``{prefix}:{collection}`` → hash field = document filter key.
    """

    def __init__(
        self,
        redis_url: str = "",
        key_prefix: str = _DEFAULT_KEY_PREFIX,
        default_ttl_s: int = 3600,
    ) -> None:
        self._redis_url = redis_url or settings.redis_storage_url or settings.redis_url
        self._key_prefix = key_prefix
        self._default_ttl_s = default_ttl_s
        self._redis: Any = None

    def _collection_key(self, collection: str) -> str:
        """Build the Redis key for a collection hash."""
        return f"{self._key_prefix}:{collection}"

    @staticmethod
    def _filter_hash(filter: dict[str, Any]) -> str:
        """Produce a stable hash string from a filter dict for use as hash field key."""
        serialised = json.dumps(filter, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(serialised.encode()).hexdigest()[:32]

    @staticmethod
    def _doc_matches_filter(doc: dict[str, Any], filter: dict[str, Any]) -> bool:
        """Check if a document matches all filter key-value pairs."""
        for key, value in filter.items():
            doc_val = doc.get(key)
            if isinstance(value, dict):
                # Support simple MongoDB-style operators
                for op, operand in value.items():
                    if op == "$in" and doc_val not in operand:
                        return False
                    elif op == "$gte" and (doc_val is None or doc_val < operand):
                        return False
                    elif op == "$lte" and (doc_val is None or doc_val > operand):
                        return False
            elif doc_val != value:
                return False
        return True

    # --- Lifecycle ---

    async def initialize(self) -> None:
        """Create the Redis connection pool."""
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            await self._redis.ping()
            logger.info("RedisStorageBackend connected: %s", self._redis_url.split("@")[-1])
        except Exception:
            logger.exception("RedisStorageBackend failed to connect")
            self._redis = None

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    # --- StorageBackend interface ---

    async def get(
        self, collection: str, filter: dict[str, Any]
    ) -> dict[str, Any] | None:
        if self._redis is None:
            return None

        coll_key = self._collection_key(collection)
        field = self._filter_hash(filter)

        try:
            data = await self._redis.hget(coll_key, field)
            if data is None:
                # Scan for matching documents (filter may not match stored hash)
                return await self._scan_for_match(coll_key, filter)
            doc = json.loads(data)
            if self._doc_matches_filter(doc, filter):
                return doc
            return await self._scan_for_match(coll_key, filter)
        except Exception:
            logger.exception("RedisStorageBackend.get failed")
            return None

    async def _scan_for_match(
        self, coll_key: str, filter: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Scan all documents in a collection hash for one that matches the filter."""
        try:
            cursor = "0"
            while True:
                cursor, data = await self._redis.hscan(coll_key, cursor=cursor, count=100)
                for _field, value in data.items():
                    doc = json.loads(value)
                    if self._doc_matches_filter(doc, filter):
                        return doc
                if cursor == 0 or cursor == "0":
                    break
        except Exception:
            logger.exception("RedisStorageBackend._scan_for_match failed")
        return None

    async def put(
        self, collection: str, document: dict[str, Any], *, upsert: bool = False
    ) -> str:
        if self._redis is None:
            return ""

        coll_key = self._collection_key(collection)

        # Determine the document's unique key for the hash field
        doc_id = ""
        for id_field in ("rule_id", "agent_id", "role_id", "key_hash", "entry_id", "_id"):
            if id_field in document:
                doc_id = str(document[id_field])
                break
        if not doc_id:
            doc_id = str(uuid.uuid4())

        field = doc_id
        serialised = json.dumps(document, default=str, separators=(",", ":"))

        try:
            await self._redis.hset(coll_key, field, serialised)
            return doc_id
        except Exception:
            logger.exception("RedisStorageBackend.put failed")
            return ""

    async def delete(
        self, collection: str, filter: dict[str, Any]
    ) -> bool:
        if self._redis is None:
            return False

        coll_key = self._collection_key(collection)

        try:
            # Scan for the matching document to find its field name
            cursor = "0"
            while True:
                cursor, data = await self._redis.hscan(coll_key, cursor=cursor, count=100)
                for field, value in data.items():
                    doc = json.loads(value)
                    if self._doc_matches_filter(doc, filter):
                        await self._redis.hdel(coll_key, field)
                        return True
                if cursor == 0 or cursor == "0":
                    break
        except Exception:
            logger.exception("RedisStorageBackend.delete failed")
        return False

    async def query(
        self,
        collection: str,
        filter: dict[str, Any],
        *,
        limit: int = 100,
        offset: int = 0,
        sort: list[tuple[str, int]] | None = None,
    ) -> list[dict[str, Any]]:
        if self._redis is None:
            return []

        coll_key = self._collection_key(collection)
        matched: list[dict[str, Any]] = []

        try:
            cursor = "0"
            while True:
                cursor, data = await self._redis.hscan(coll_key, cursor=cursor, count=200)
                for _field, value in data.items():
                    doc = json.loads(value)
                    if self._doc_matches_filter(doc, filter):
                        matched.append(doc)
                if cursor == 0 or cursor == "0":
                    break
        except Exception:
            logger.exception("RedisStorageBackend.query failed")
            return []

        # Sort
        if sort:
            for field_name, direction in reversed(sort):
                matched.sort(
                    key=lambda d: d.get(field_name, ""),
                    reverse=(direction == -1),
                )

        # Paginate
        return matched[offset : offset + limit]

    async def health_check(self) -> bool:
        if self._redis is None:
            return False
        try:
            result = await self._redis.ping()
            return result is True
        except Exception:
            logger.exception("RedisStorageBackend health check failed")
            return False
