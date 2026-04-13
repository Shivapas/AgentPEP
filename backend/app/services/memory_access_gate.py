"""MemoryAccessGate — govern agent persist/read operations on memory stores.

Sprint 33:
  APEP-261: MemoryAccessGate core — enforce policies on memory store access.
  APEP-262: Write authorisation — allowed writers, prohibited content
            patterns, entry count limits per session.
  APEP-263: Read authorisation — lazy retention enforcement with max_age
            purging at read time.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.db import mongodb as db_module

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class MemoryOperation(StrEnum):
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"


class MemoryAccessPolicy(BaseModel):
    """Policy governing access to a memory store (APEP-261)."""

    policy_id: UUID = Field(default_factory=uuid4)
    store_pattern: str = Field(
        ..., description="Glob pattern matching memory store names"
    )
    allowed_writers: list[str] = Field(
        default_factory=list,
        description="Agent ID glob patterns allowed to write",
    )
    allowed_readers: list[str] = Field(
        default_factory=list,
        description="Agent ID glob patterns allowed to read",
    )
    prohibited_content_patterns: list[str] = Field(
        default_factory=list,
        description="Regex patterns for content blocked from writes (APEP-262)",
    )
    max_entries_per_session: int = Field(
        default=1000, ge=1,
        description="Max entries per session+store (APEP-262)",
    )
    max_entry_size_bytes: int = Field(
        default=65536, ge=1,
        description="Max size of a single entry value in bytes",
    )
    max_age_seconds: int | None = Field(
        default=None,
        description="Max age for entries; expired entries purged on read (APEP-263)",
    )
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class MemoryAccessRequest(BaseModel):
    """Request to access a memory store (APEP-261)."""

    request_id: UUID = Field(default_factory=uuid4)
    session_id: str
    agent_id: str
    store_name: str
    operation: MemoryOperation
    key: str = ""
    value: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class MemoryAccessResult(BaseModel):
    """Result of a memory access gate evaluation (APEP-261)."""

    allowed: bool
    reason: str = ""
    purged_keys: list[str] = Field(default_factory=list)
    entry_count: int = 0


# ---------------------------------------------------------------------------
# Gate implementation
# ---------------------------------------------------------------------------


def _agent_matches(agent_id: str, patterns: list[str]) -> bool:
    """Check if agent_id matches any of the glob patterns."""
    return any(fnmatch.fnmatch(agent_id, pat) for pat in patterns)


class MemoryAccessGate:
    """Governs agent persist/read operations on memory stores.

    Evaluates memory access requests against stored policies.
    Deny-by-default when no matching policy is found.
    """

    def __init__(self) -> None:
        self._compiled_patterns: dict[str, list[re.Pattern[str]]] = {}

    async def evaluate(self, request: MemoryAccessRequest) -> MemoryAccessResult:
        """Evaluate a memory access request against stored policies.

        Returns:
            MemoryAccessResult indicating whether access is allowed.
        """
        policy = await self._load_policy(request.store_name)
        if policy is None:
            return MemoryAccessResult(
                allowed=False,
                reason=f"No memory access policy found for store '{request.store_name}'",
            )

        if not policy.enabled:
            return MemoryAccessResult(
                allowed=False,
                reason=f"Memory access policy for store '{request.store_name}' is disabled",
            )

        if request.operation == MemoryOperation.WRITE:
            return await self._authorize_write(request, policy)
        elif request.operation == MemoryOperation.READ:
            return await self._authorize_read(request, policy)
        elif request.operation == MemoryOperation.DELETE:
            return await self._authorize_delete(request, policy)

        return MemoryAccessResult(
            allowed=False,
            reason=f"Unknown memory operation: {request.operation}",
        )

    async def _authorize_write(
        self, request: MemoryAccessRequest, policy: MemoryAccessPolicy
    ) -> MemoryAccessResult:
        """APEP-262: Validate write authorisation.

        Checks:
        1. Agent is in allowed_writers
        2. Content does not match prohibited patterns
        3. Session entry count is within limits
        4. Entry size is within limits
        """
        # Check allowed writers
        if policy.allowed_writers and not _agent_matches(
            request.agent_id, policy.allowed_writers
        ):
            return MemoryAccessResult(
                allowed=False,
                reason=(
                    f"Agent '{request.agent_id}' is not an allowed writer "
                    f"for store '{request.store_name}'"
                ),
            )

        # Check prohibited content patterns
        if request.value and policy.prohibited_content_patterns:
            for pattern_str in policy.prohibited_content_patterns:
                try:
                    if re.search(pattern_str, request.value, re.IGNORECASE):
                        return MemoryAccessResult(
                            allowed=False,
                            reason=(
                                f"Write content matches prohibited pattern "
                                f"in store '{request.store_name}'"
                            ),
                        )
                except re.error:
                    logger.warning(
                        "Invalid prohibited content regex: %s", pattern_str
                    )

        # Check entry size
        if request.value is not None:
            value_size = len(request.value.encode("utf-8"))
            if value_size > policy.max_entry_size_bytes:
                return MemoryAccessResult(
                    allowed=False,
                    reason=(
                        f"Entry size {value_size} bytes exceeds limit of "
                        f"{policy.max_entry_size_bytes} bytes"
                    ),
                )

        # Check entry count limit per session
        entry_count = await self._get_session_entry_count(
            request.session_id, request.store_name
        )
        if entry_count >= policy.max_entries_per_session:
            return MemoryAccessResult(
                allowed=False,
                reason=(
                    f"Session entry count ({entry_count}) has reached the limit of "
                    f"{policy.max_entries_per_session} for store '{request.store_name}'"
                ),
                entry_count=entry_count,
            )

        # Record the entry
        await self._record_entry(request)

        return MemoryAccessResult(
            allowed=True,
            reason="Write authorized",
            entry_count=entry_count + 1,
        )

    async def _authorize_read(
        self, request: MemoryAccessRequest, policy: MemoryAccessPolicy
    ) -> MemoryAccessResult:
        """APEP-263: Validate read authorisation with lazy retention enforcement.

        Checks:
        1. Agent is in allowed_readers
        2. If max_age_seconds is set, purge expired entries
        """
        # Check allowed readers
        if policy.allowed_readers and not _agent_matches(
            request.agent_id, policy.allowed_readers
        ):
            return MemoryAccessResult(
                allowed=False,
                reason=(
                    f"Agent '{request.agent_id}' is not an allowed reader "
                    f"for store '{request.store_name}'"
                ),
            )

        # Lazy retention enforcement: purge expired entries
        purged_keys: list[str] = []
        if policy.max_age_seconds is not None:
            purged_keys = await self._purge_expired_entries(
                request.session_id,
                request.store_name,
                policy.max_age_seconds,
            )

        entry_count = await self._get_session_entry_count(
            request.session_id, request.store_name
        )

        return MemoryAccessResult(
            allowed=True,
            reason="Read authorized",
            purged_keys=purged_keys,
            entry_count=entry_count,
        )

    async def _authorize_delete(
        self, request: MemoryAccessRequest, policy: MemoryAccessPolicy
    ) -> MemoryAccessResult:
        """Only allowed writers can delete entries."""
        if policy.allowed_writers and not _agent_matches(
            request.agent_id, policy.allowed_writers
        ):
            return MemoryAccessResult(
                allowed=False,
                reason=(
                    f"Agent '{request.agent_id}' is not an allowed writer "
                    f"(required for delete) for store '{request.store_name}'"
                ),
            )

        return MemoryAccessResult(allowed=True, reason="Delete authorized")

    async def _load_policy(self, store_name: str) -> MemoryAccessPolicy | None:
        """Load the first matching enabled policy for a store name."""
        db = db_module.get_database()
        cursor = db[db_module.MEMORY_ACCESS_POLICIES].find({"enabled": True})
        async for doc in cursor:
            doc.pop("_id", None)
            policy = MemoryAccessPolicy(**doc)
            if fnmatch.fnmatch(store_name, policy.store_pattern):
                return policy
        return None

    async def _get_session_entry_count(
        self, session_id: str, store_name: str
    ) -> int:
        """Count entries for a given session + store."""
        db = db_module.get_database()
        count = await db[db_module.MEMORY_ENTRIES].count_documents(
            {"session_id": session_id, "store_name": store_name}
        )
        return count

    async def _record_entry(self, request: MemoryAccessRequest) -> None:
        """Record a memory entry for count tracking."""
        db = db_module.get_database()
        await db[db_module.MEMORY_ENTRIES].insert_one(
            {
                "entry_id": str(uuid4()),
                "session_id": request.session_id,
                "agent_id": request.agent_id,
                "store_name": request.store_name,
                "key": request.key,
                "created_at": datetime.now(UTC),
            }
        )

    async def _purge_expired_entries(
        self, session_id: str, store_name: str, max_age_seconds: int
    ) -> list[str]:
        """APEP-263: Purge entries older than max_age and return purged keys."""
        db = db_module.get_database()
        cutoff = datetime.now(UTC) - timedelta(seconds=max_age_seconds)

        # Find entries to purge
        cursor = db[db_module.MEMORY_ENTRIES].find(
            {
                "session_id": session_id,
                "store_name": store_name,
                "created_at": {"$lt": cutoff},
            },
            {"key": 1, "_id": 0},
        )

        purged_keys: list[str] = []
        async for doc in cursor:
            purged_keys.append(doc.get("key", ""))

        if purged_keys:
            await db[db_module.MEMORY_ENTRIES].delete_many(
                {
                    "session_id": session_id,
                    "store_name": store_name,
                    "created_at": {"$lt": cutoff},
                }
            )
            logger.info(
                "Purged %d expired entries from store=%s session=%s",
                len(purged_keys),
                store_name,
                session_id,
            )

        return purged_keys


# Module-level singleton
memory_access_gate = MemoryAccessGate()
