"""AuditBackend ABC — pluggable audit interface for AgentPEP.

Sprint 29 — APEP-229: Abstract base class for audit backends with
methods: write_decision, query, verify_integrity.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class IntegrityResult:
    """Result of an audit integrity verification."""

    valid: bool
    total_records: int = 0
    verified_records: int = 0
    first_tampered_sequence: int | None = None
    first_tampered_decision_id: str | None = None
    detail: str = ""


class AuditBackend(ABC):
    """Abstract base class for AgentPEP audit backends.

    Implementations persist authorization decisions and support
    querying and integrity verification.
    """

    @abstractmethod
    async def write_decision(self, record: dict[str, Any]) -> bool:
        """Write a single audit decision record.

        Args:
            record: The audit decision as a dictionary (serialized AuditDecision).

        Returns:
            True if the record was successfully written, False otherwise.
        """

    @abstractmethod
    async def query(
        self,
        filter: dict[str, Any],
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query audit decision records.

        Args:
            filter: Key-value pairs to filter records.
            limit: Maximum number of records to return.
            offset: Number of records to skip.

        Returns:
            List of matching audit records.
        """

    @abstractmethod
    async def verify_integrity(
        self, *, start_sequence: int = 1, end_sequence: int | None = None
    ) -> IntegrityResult:
        """Verify the integrity of the audit trail.

        Checks the hash chain (or backend-specific integrity mechanism)
        across the specified sequence range.

        Args:
            start_sequence: First sequence number to verify (inclusive).
            end_sequence: Last sequence number to verify (inclusive).
                          If None, verify to the latest record.

        Returns:
            IntegrityResult with verification outcome.
        """

    async def write_batch(self, records: list[dict[str, Any]]) -> int:
        """Write a batch of audit records. Default implementation writes one-by-one.

        Args:
            records: List of audit decision dictionaries.

        Returns:
            Number of records successfully written.
        """
        count = 0
        for record in records:
            if await self.write_decision(record):
                count += 1
        return count

    async def close(self) -> None:
        """Clean up resources. Override in subclasses if needed."""

    async def initialize(self) -> None:
        """Perform any startup initialization. Override in subclasses if needed."""
