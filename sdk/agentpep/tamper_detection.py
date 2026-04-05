"""SDK tamper detection — APEP-190.

Logs a warning if an intercept call is skipped (no-op SDK use).  Tracks
every decorated tool invocation and verifies that the policy engine was
actually consulted before execution.  If the SDK detects that a tool
function was called without a preceding ``evaluate`` or ``enforce`` call,
it emits a WARNING-level log entry for security audit.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

logger = logging.getLogger("agentpep.tamper_detection")


@dataclass(slots=True)
class _InterceptRecord:
    """Tracks a single intercept call."""

    tool_name: str
    agent_id: str
    timestamp: float


class TamperDetector:
    """Detects when SDK intercept calls are skipped or bypassed.

    Usage:
        1. Call ``record_intercept()`` when ``evaluate()`` or ``enforce()``
           is invoked on the client.
        2. Call ``verify_before_execution()`` just before the actual tool
           function runs.  If no matching intercept was recorded within the
           staleness window, a warning is logged.

    The detector is thread-safe and uses a bounded buffer to prevent
    unbounded memory growth.
    """

    def __init__(
        self,
        staleness_window_s: float = 30.0,
        max_records: int = 10_000,
    ) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, _InterceptRecord] = {}
        self._staleness_window_s = staleness_window_s
        self._max_records = max_records
        self._skipped_count = 0
        self._verified_count = 0

    def record_intercept(self, tool_name: str, agent_id: str) -> None:
        """Record that an intercept call was made for this tool+agent."""
        key = f"{agent_id}:{tool_name}"
        now = time.monotonic()
        with self._lock:
            self._records[key] = _InterceptRecord(
                tool_name=tool_name,
                agent_id=agent_id,
                timestamp=now,
            )
            # Evict stale entries if buffer is full
            if len(self._records) > self._max_records:
                self._evict_stale(now)

    def verify_before_execution(self, tool_name: str, agent_id: str) -> bool:
        """Check that an intercept call was recorded before tool execution.

        Returns True if verified, False if skipped (and logs a warning).
        """
        key = f"{agent_id}:{tool_name}"
        now = time.monotonic()
        with self._lock:
            record = self._records.pop(key, None)

        if record is None:
            self._skipped_count += 1
            logger.warning(
                "TAMPER_DETECTED: Tool '%s' executed by agent '%s' without "
                "a preceding AgentPEP intercept call. This may indicate "
                "SDK bypass or misconfiguration.",
                tool_name,
                agent_id,
            )
            return False

        elapsed = now - record.timestamp
        if elapsed > self._staleness_window_s:
            self._skipped_count += 1
            logger.warning(
                "TAMPER_DETECTED: Intercept call for tool '%s' by agent '%s' "
                "is stale (%.1fs ago, window=%.1fs). The tool may have been "
                "called without a fresh policy check.",
                tool_name,
                agent_id,
                elapsed,
                self._staleness_window_s,
            )
            return False

        self._verified_count += 1
        return True

    @property
    def skipped_count(self) -> int:
        """Number of tool executions detected without intercept calls."""
        return self._skipped_count

    @property
    def verified_count(self) -> int:
        """Number of tool executions that were properly verified."""
        return self._verified_count

    def _evict_stale(self, now: float) -> None:
        """Remove records older than staleness window (must hold lock)."""
        cutoff = now - self._staleness_window_s
        stale_keys = [
            k for k, r in self._records.items() if r.timestamp < cutoff
        ]
        for k in stale_keys:
            del self._records[k]


# Module-level singleton
tamper_detector = TamperDetector()
