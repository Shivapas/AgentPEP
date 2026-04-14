"""Velocity Anomaly Detector — Sprint 35 (APEP-278).

Statistical anomaly detection on per-agent tool call frequency using a
sliding-window z-score approach.  When an agent's call rate deviates
significantly from its historical baseline, the detector flags an anomaly
that feeds into the risk scoring engine.

Scoring logic:
  - z_score < threshold         → 0.0 (normal)
  - z_score >= threshold        → 0.5 (elevated)
  - z_score >= 2 * threshold    → 0.9 (critical)
  - Insufficient samples        → 0.0 (not enough data)
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass

from app.db import mongodb as db_module

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class VelocityResult:
    """Result of a velocity anomaly check."""

    is_anomalous: bool
    z_score: float
    current_rate: float
    baseline_mean: float
    baseline_stddev: float
    risk_score: float
    detail: str


class VelocityAnomalyDetector:
    """Detect anomalous tool call velocity for agents using z-score analysis.

    Compares the agent's current call rate (within a sliding window) against
    a historical baseline computed from older windows.  A z-score above the
    configured threshold signals anomalous activity.
    """

    def __init__(
        self,
        window_seconds: int = 300,
        z_score_threshold: float = 2.5,
        min_sample_size: int = 10,
    ) -> None:
        self.window_seconds = window_seconds
        self.z_score_threshold = z_score_threshold
        self.min_sample_size = min_sample_size

    async def check(self, agent_id: str, session_id: str) -> VelocityResult:
        """Check if the agent's current call velocity is anomalous.

        Args:
            agent_id: The agent whose velocity to check.
            session_id: Current session (for logging context).

        Returns:
            VelocityResult with anomaly flag and risk score.
        """
        current_rate = await self._get_current_frequency(agent_id, self.window_seconds)
        baseline_mean, baseline_stddev = await self._get_historical_baseline(agent_id)

        # Insufficient data — cannot compute z-score
        if baseline_stddev == 0.0 or baseline_mean == 0.0:
            return VelocityResult(
                is_anomalous=False,
                z_score=0.0,
                current_rate=current_rate,
                baseline_mean=baseline_mean,
                baseline_stddev=baseline_stddev,
                risk_score=0.0,
                detail="Insufficient historical data for baseline",
            )

        z_score = (current_rate - baseline_mean) / baseline_stddev

        risk_score = self._compute_risk_score(z_score)
        is_anomalous = z_score >= self.z_score_threshold

        if is_anomalous:
            detail = (
                f"Velocity anomaly: z-score={z_score:.2f} "
                f"(rate={current_rate:.1f}, baseline={baseline_mean:.1f}+/-{baseline_stddev:.1f})"
            )
        else:
            detail = (
                f"Normal velocity: z-score={z_score:.2f} "
                f"(rate={current_rate:.1f}, baseline={baseline_mean:.1f}+/-{baseline_stddev:.1f})"
            )

        return VelocityResult(
            is_anomalous=is_anomalous,
            z_score=z_score,
            current_rate=current_rate,
            baseline_mean=baseline_mean,
            baseline_stddev=baseline_stddev,
            risk_score=risk_score,
            detail=detail,
        )

    def _compute_risk_score(self, z_score: float) -> float:
        """Map z-score to a [0, 1] risk score."""
        if z_score < self.z_score_threshold:
            return 0.0
        if z_score >= 2 * self.z_score_threshold:
            return 0.9
        return 0.5

    async def _get_current_frequency(
        self, agent_id: str, window_seconds: int
    ) -> float:
        """Count calls by this agent within the current sliding window."""
        try:
            db = db_module.get_database()
            now = time.time()
            cutoff = now - window_seconds

            count = await db[db_module.AUDIT_DECISIONS].count_documents(
                {
                    "agent_id": agent_id,
                    "timestamp": {"$gte": _epoch_to_query(cutoff)},
                }
            )
            return float(count)
        except Exception:
            logger.warning(
                "Failed to get current frequency for velocity check",
                exc_info=True,
            )
            return 0.0

    async def _get_historical_baseline(
        self, agent_id: str, num_windows: int = 5
    ) -> tuple[float, float]:
        """Compute mean and stddev of call counts from older windows.

        Divides the historical period (num_windows * window_seconds) into
        buckets and computes the average and standard deviation of calls
        per bucket.
        """
        try:
            db = db_module.get_database()
            now = time.time()
            window = self.window_seconds

            # Collect counts for each historical window
            counts: list[float] = []
            for i in range(1, num_windows + 1):
                bucket_end = now - (i * window)
                bucket_start = bucket_end - window

                count = await db[db_module.AUDIT_DECISIONS].count_documents(
                    {
                        "agent_id": agent_id,
                        "timestamp": {
                            "$gte": _epoch_to_query(bucket_start),
                            "$lt": _epoch_to_query(bucket_end),
                        },
                    }
                )
                counts.append(float(count))

            if not counts or sum(counts) < self.min_sample_size:
                return 0.0, 0.0

            mean = sum(counts) / len(counts)
            if len(counts) < 2:
                return mean, 0.0

            variance = sum((c - mean) ** 2 for c in counts) / (len(counts) - 1)
            stddev = math.sqrt(variance)

            return mean, stddev
        except Exception:
            logger.warning(
                "Failed to get historical baseline for velocity check",
                exc_info=True,
            )
            return 0.0, 0.0


def _epoch_to_query(epoch: float) -> float:
    """Convert epoch seconds to a value suitable for MongoDB timestamp queries.

    We store as-is since the audit_decisions timestamp field may be stored
    as a Python datetime or a float depending on the test environment.
    """
    return epoch


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

velocity_anomaly_detector = VelocityAnomalyDetector()
