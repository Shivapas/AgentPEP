"""MongoDBStorageBackend — MongoDB implementation of StorageBackend ABC.

Sprint 29 — APEP-226: Refactors the existing MongoDB policy store as a
reference implementation of the StorageBackend plugin interface.
"""

from __future__ import annotations

import logging
from typing import Any

from app.backends.storage import StorageBackend
from app.db import mongodb as db_module

logger = logging.getLogger(__name__)


class MongoDBStorageBackend(StorageBackend):
    """MongoDB-backed storage using Motor async driver.

    Delegates to the existing Motor client managed by ``app.db.mongodb``.
    Connection pooling, timeouts, and index creation are handled by the
    shared MongoDB module (APEP-182).
    """

    async def get(
        self, collection: str, filter: dict[str, Any]
    ) -> dict[str, Any] | None:
        db = db_module.get_database()
        doc = await db[collection].find_one(filter)
        if doc is not None:
            doc.pop("_id", None)
        return doc

    async def put(
        self, collection: str, document: dict[str, Any], *, upsert: bool = False
    ) -> str:
        db = db_module.get_database()
        if upsert:
            # Use the first key as the upsert filter if available
            filter_key = next(iter(document), None)
            if filter_key:
                result = await db[collection].update_one(
                    {filter_key: document[filter_key]},
                    {"$set": document},
                    upsert=True,
                )
                return str(result.upserted_id or document.get(filter_key, ""))
        result = await db[collection].insert_one(document)
        return str(result.inserted_id)

    async def delete(
        self, collection: str, filter: dict[str, Any]
    ) -> bool:
        db = db_module.get_database()
        result = await db[collection].delete_one(filter)
        return result.deleted_count > 0

    async def query(
        self,
        collection: str,
        filter: dict[str, Any],
        *,
        limit: int = 100,
        offset: int = 0,
        sort: list[tuple[str, int]] | None = None,
    ) -> list[dict[str, Any]]:
        db = db_module.get_database()
        cursor = db[collection].find(filter)
        if sort:
            cursor = cursor.sort(sort)
        cursor = cursor.skip(offset).limit(limit)
        docs = []
        async for doc in cursor:
            doc.pop("_id", None)
            docs.append(doc)
        return docs

    async def health_check(self) -> bool:
        try:
            client = db_module.get_client()
            result = await client.admin.command("ping")
            return result.get("ok") == 1.0
        except Exception:
            logger.exception("MongoDB health check failed")
            return False

    async def close(self) -> None:
        await db_module.close_client()

    async def initialize(self) -> None:
        await db_module.init_collections()
