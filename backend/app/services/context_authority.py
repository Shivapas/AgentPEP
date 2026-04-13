"""ContextAuthorityTracker — classify context entries by authority level.

Sprint 33:
  APEP-264: Classify each context entry as AUTHORITATIVE / DERIVED / UNTRUSTED
            based on its source.
  APEP-265: Integrate context authority into risk scoring — downweight derived
            sources, block untrusted sources from privileged decisions.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.db import mongodb as db_module
from app.models.policy import TaintSource

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ContextAuthority(StrEnum):
    """Authority classification for context entries (APEP-264)."""

    AUTHORITATIVE = "AUTHORITATIVE"  # Direct user input, system prompts
    DERIVED = "DERIVED"  # Tool outputs, agent-generated content
    UNTRUSTED = "UNTRUSTED"  # Web content, email, external sources


class ContextEntry(BaseModel):
    """A context entry with authority classification (APEP-264)."""

    entry_id: UUID = Field(default_factory=uuid4)
    session_id: str
    source: TaintSource
    authority: ContextAuthority = ContextAuthority.UNTRUSTED
    content_hash: str = ""
    agent_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------


class ContextAuthorityTracker:
    """Classify context entries and track authority distribution per session.

    Source → Authority mapping:
      AUTHORITATIVE: USER_PROMPT, SYSTEM_PROMPT
      DERIVED: TOOL_OUTPUT, AGENT_MSG, CROSS_AGENT, SANITISED
      UNTRUSTED: WEB, EMAIL
    """

    _SOURCE_AUTHORITY_MAP: dict[TaintSource, ContextAuthority] = {
        TaintSource.USER_PROMPT: ContextAuthority.AUTHORITATIVE,
        TaintSource.SYSTEM_PROMPT: ContextAuthority.AUTHORITATIVE,
        TaintSource.TOOL_OUTPUT: ContextAuthority.DERIVED,
        TaintSource.AGENT_MSG: ContextAuthority.DERIVED,
        TaintSource.CROSS_AGENT: ContextAuthority.DERIVED,
        TaintSource.SANITISED: ContextAuthority.DERIVED,
        TaintSource.WEB: ContextAuthority.UNTRUSTED,
        TaintSource.EMAIL: ContextAuthority.UNTRUSTED,
    }

    def classify(self, source: TaintSource) -> ContextAuthority:
        """Classify a context source into an authority level."""
        return self._SOURCE_AUTHORITY_MAP.get(source, ContextAuthority.UNTRUSTED)

    async def track_entry(
        self,
        session_id: str,
        source: TaintSource,
        content_hash: str = "",
        agent_id: str | None = None,
    ) -> ContextEntry:
        """Classify and persist a context entry."""
        authority = self.classify(source)
        entry = ContextEntry(
            session_id=session_id,
            source=source,
            authority=authority,
            content_hash=content_hash,
            agent_id=agent_id,
        )

        db = db_module.get_database()
        await db[db_module.CONTEXT_ENTRIES].insert_one(
            entry.model_dump(mode="json")
        )

        return entry

    async def get_session_authorities(
        self, session_id: str
    ) -> dict[ContextAuthority, int]:
        """Return count of entries per authority level for a session."""
        db = db_module.get_database()

        counts: dict[ContextAuthority, int] = {
            ContextAuthority.AUTHORITATIVE: 0,
            ContextAuthority.DERIVED: 0,
            ContextAuthority.UNTRUSTED: 0,
        }

        cursor = db[db_module.CONTEXT_ENTRIES].find(
            {"session_id": session_id},
            {"authority": 1, "_id": 0},
        )
        async for doc in cursor:
            auth_str = doc.get("authority", "UNTRUSTED")
            try:
                auth = ContextAuthority(auth_str)
                counts[auth] = counts.get(auth, 0) + 1
            except ValueError:
                counts[ContextAuthority.UNTRUSTED] += 1

        return counts

    async def get_authority_score(self, session_id: str) -> float:
        """Compute a 0-1 risk score based on context authority distribution.

        Scoring:
          - All AUTHORITATIVE → 0.0
          - Mix with DERIVED (no UNTRUSTED) → 0.3 scaled by derived proportion
          - Any UNTRUSTED present → 0.7
          - Majority UNTRUSTED → 0.9
          - No entries → 0.0
        """
        counts = await self.get_session_authorities(session_id)
        total = sum(counts.values())

        if total == 0:
            return 0.0

        untrusted_count = counts.get(ContextAuthority.UNTRUSTED, 0)
        derived_count = counts.get(ContextAuthority.DERIVED, 0)

        if untrusted_count > 0:
            untrusted_ratio = untrusted_count / total
            if untrusted_ratio > 0.5:
                return 0.9
            return 0.7

        if derived_count > 0:
            derived_ratio = derived_count / total
            return round(0.3 * derived_ratio, 4)

        return 0.0


# Module-level singleton
context_authority_tracker = ContextAuthorityTracker()
