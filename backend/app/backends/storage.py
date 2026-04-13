"""StorageBackend ABC — pluggable storage interface for AgentPEP.

Sprint 29 — APEP-225: Abstract base class for storage backends with async
methods: get, put, delete, query, health_check.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class StorageBackend(ABC):
    """Abstract base class for AgentPEP storage backends.

    All storage operations are async to support non-blocking I/O.
    Implementations must handle their own connection lifecycle
    (initialization, pooling, cleanup).
    """

    @abstractmethod
    async def get(
        self, collection: str, filter: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Retrieve a single document matching the filter.

        Args:
            collection: The collection/table name.
            filter: Key-value pairs to match against.

        Returns:
            The matching document, or None if not found.
        """

    @abstractmethod
    async def put(
        self, collection: str, document: dict[str, Any], *, upsert: bool = False
    ) -> str:
        """Insert or upsert a document.

        Args:
            collection: The collection/table name.
            document: The document to store.
            upsert: If True, update existing document matching the same key.

        Returns:
            The inserted/updated document ID as a string.
        """

    @abstractmethod
    async def delete(
        self, collection: str, filter: dict[str, Any]
    ) -> bool:
        """Delete a single document matching the filter.

        Args:
            collection: The collection/table name.
            filter: Key-value pairs to match against.

        Returns:
            True if a document was deleted, False otherwise.
        """

    @abstractmethod
    async def query(
        self,
        collection: str,
        filter: dict[str, Any],
        *,
        limit: int = 100,
        offset: int = 0,
        sort: list[tuple[str, int]] | None = None,
    ) -> list[dict[str, Any]]:
        """Query documents matching the filter.

        Args:
            collection: The collection/table name.
            filter: Key-value pairs to match against.
            limit: Maximum number of documents to return.
            offset: Number of documents to skip.
            sort: List of (field, direction) tuples. Direction: 1=ASC, -1=DESC.

        Returns:
            List of matching documents.
        """

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the storage backend is healthy and reachable.

        Returns:
            True if the backend is operational, False otherwise.
        """

    async def close(self) -> None:
        """Clean up resources. Override in subclasses if needed."""

    async def initialize(self) -> None:
        """Perform any startup initialization. Override in subclasses if needed."""
