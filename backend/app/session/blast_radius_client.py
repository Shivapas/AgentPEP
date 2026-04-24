"""AAPM Blast Radius API client — session-init integration.

Queries the AAPM Blast Radius Calculator at session initialisation and
attaches the resulting score (0.0–1.0) to the session context so that
posture matrix elevation and PostToolUse events carry an accurate risk
dimension for the full session lifetime.

FAIL_CLOSED: Any failure to obtain a score from the AAPM API (network
timeout, HTTP error, parse error, unavailability) causes the score to
default to 1.0 — the maximum blast radius.  This ensures high-reach agents
are treated conservatively when the blast radius cannot be confirmed.

Sprint S-E08 (E08-T01, E08-T02)
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from app.core.structured_logging import get_logger

logger = get_logger(__name__)

# Default score used when the AAPM API is unavailable — maximum blast radius
# so that posture elevation applies conservatively (FAIL_CLOSED principle).
BLAST_RADIUS_FAIL_CLOSED_DEFAULT: float = 1.0

# Valid score range
_SCORE_MIN: float = 0.0
_SCORE_MAX: float = 1.0


# ---------------------------------------------------------------------------
# Session-scoped blast radius context
# ---------------------------------------------------------------------------


@dataclass
class BlastRadiusContext:
    """Blast radius score attached to a session at initialisation.

    Attributes:
        agent_id:       Agent identity whose blast radius was scored.
        session_id:     Session the score is attached to.
        score:          Blast radius score in [0.0, 1.0].
                        0.0 = minimal reach; 1.0 = maximum reach.
        source:         How the score was obtained: "api", "fallback", or "default".
        fetched_at_ms:  Unix epoch milliseconds when the score was resolved.
        api_latency_ms: Round-trip latency of the AAPM API call (0 for non-API sources).
    """

    agent_id: str
    session_id: str
    score: float
    source: str               # "api" | "fallback" | "default"
    fetched_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    api_latency_ms: int = 0

    def __post_init__(self) -> None:
        self.score = max(_SCORE_MIN, min(_SCORE_MAX, float(self.score)))

    @property
    def is_high_blast_radius(self) -> bool:
        """True if score meets the elevation threshold (≥ 0.75)."""
        return self.score >= 0.75

    @classmethod
    def fail_closed(cls, agent_id: str, session_id: str) -> "BlastRadiusContext":
        """Return a FAIL_CLOSED context with the maximum score."""
        return cls(
            agent_id=agent_id,
            session_id=session_id,
            score=BLAST_RADIUS_FAIL_CLOSED_DEFAULT,
            source="fallback",
        )


# ---------------------------------------------------------------------------
# AAPM Blast Radius API client
# ---------------------------------------------------------------------------


class BlastRadiusClient:
    """HTTP client for the AAPM Blast Radius Calculator API.

    Queries the API at session initialisation.  Any failure produces a
    FAIL_CLOSED result (score = 1.0) so that enforcement is never
    weakened by API unavailability.

    Configuration consumed from app.core.config.settings:
        aapm_blast_radius_api_url  — base URL of the AAPM Blast Radius API
        aapm_blast_radius_timeout_s — per-request HTTP timeout in seconds
    """

    async def fetch(self, agent_id: str, session_id: str) -> BlastRadiusContext:
        """Fetch the blast radius score for *agent_id* from the AAPM API.

        Returns a BlastRadiusContext. On any failure (network, timeout,
        HTTP error, parse error, API disabled) the context carries
        score = 1.0 and source = "fallback".

        Args:
            agent_id:   Agent whose blast radius to query.
            session_id: Current session identifier (used for logging).
        """
        from app.core.config import settings

        api_url: str = getattr(settings, "aapm_blast_radius_api_url", "")
        timeout_s: float = getattr(settings, "aapm_blast_radius_timeout_s", 5.0)

        if not api_url:
            logger.debug(
                "blast_radius_api_disabled",
                agent_id=agent_id,
                session_id=session_id,
                reason="aapm_blast_radius_api_url not configured",
            )
            return BlastRadiusContext(
                agent_id=agent_id,
                session_id=session_id,
                score=BLAST_RADIUS_FAIL_CLOSED_DEFAULT,
                source="default",
            )

        start_ms = int(time.time() * 1000)
        try:
            score = await asyncio.wait_for(
                self._call_api(api_url, agent_id, timeout_s),
                timeout=timeout_s,
            )
            elapsed_ms = int(time.time() * 1000) - start_ms
            ctx = BlastRadiusContext(
                agent_id=agent_id,
                session_id=session_id,
                score=score,
                source="api",
                api_latency_ms=elapsed_ms,
            )
            logger.info(
                "blast_radius_fetched",
                agent_id=agent_id,
                session_id=session_id,
                score=ctx.score,
                latency_ms=elapsed_ms,
            )
            return ctx

        except asyncio.TimeoutError:
            elapsed_ms = int(time.time() * 1000) - start_ms
            logger.warning(
                "blast_radius_api_timeout",
                agent_id=agent_id,
                session_id=session_id,
                timeout_s=timeout_s,
                elapsed_ms=elapsed_ms,
                fallback_score=BLAST_RADIUS_FAIL_CLOSED_DEFAULT,
            )
        except Exception:
            elapsed_ms = int(time.time() * 1000) - start_ms
            logger.exception(
                "blast_radius_api_error",
                agent_id=agent_id,
                session_id=session_id,
                elapsed_ms=elapsed_ms,
                fallback_score=BLAST_RADIUS_FAIL_CLOSED_DEFAULT,
            )

        return BlastRadiusContext.fail_closed(agent_id, session_id)

    async def _call_api(
        self,
        base_url: str,
        agent_id: str,
        timeout_s: float,
    ) -> float:
        """Perform the HTTP call to the AAPM Blast Radius API.

        Expected API response (JSON):
          {"agent_id": "...", "blast_radius_score": 0.42}

        Returns the parsed score clamped to [0.0, 1.0].
        Raises on any HTTP or network error so the caller can FAIL_CLOSED.
        """
        import urllib.parse
        import urllib.request

        url = f"{base_url.rstrip('/')}/v1/blast-radius/{urllib.parse.quote(agent_id, safe='')}"

        # Use stdlib urllib for the sync call run in a thread to avoid
        # introducing an httpx/aiohttp dependency at the sprint boundary.
        loop = asyncio.get_event_loop()
        raw = await loop.run_in_executor(
            None,
            lambda: _sync_get(url, timeout_s),
        )

        score = float(raw.get("blast_radius_score", BLAST_RADIUS_FAIL_CLOSED_DEFAULT))
        return max(_SCORE_MIN, min(_SCORE_MAX, score))


def _sync_get(url: str, timeout_s: float) -> dict[str, Any]:
    """Perform a synchronous GET and return the parsed JSON body."""
    import json
    import urllib.request

    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

blast_radius_client = BlastRadiusClient()
