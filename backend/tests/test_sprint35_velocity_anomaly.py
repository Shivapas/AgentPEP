"""Sprint 35 — APEP-278: VelocityAnomalyDetector tests.

Tests for the velocity anomaly detection engine covering:
  - Z-score computation and risk scoring
  - Threshold logic (below, at, above, double threshold)
  - Insufficient sample handling
  - Singleton exists
"""

from __future__ import annotations

import pytest

from app.services.velocity_anomaly_detector import (
    VelocityAnomalyDetector,
    VelocityResult,
    velocity_anomaly_detector,
)


class TestVelocityRiskScoring:
    """APEP-278: Z-score to risk score mapping."""

    def test_below_threshold_zero_risk(self) -> None:
        detector = VelocityAnomalyDetector(z_score_threshold=2.5)
        assert detector._compute_risk_score(1.0) == 0.0

    def test_at_threshold_medium_risk(self) -> None:
        detector = VelocityAnomalyDetector(z_score_threshold=2.5)
        assert detector._compute_risk_score(2.5) == 0.5

    def test_above_threshold_medium_risk(self) -> None:
        detector = VelocityAnomalyDetector(z_score_threshold=2.5)
        assert detector._compute_risk_score(3.0) == 0.5

    def test_double_threshold_high_risk(self) -> None:
        detector = VelocityAnomalyDetector(z_score_threshold=2.5)
        assert detector._compute_risk_score(5.0) == 0.9

    def test_above_double_threshold_high_risk(self) -> None:
        detector = VelocityAnomalyDetector(z_score_threshold=2.5)
        assert detector._compute_risk_score(10.0) == 0.9

    def test_negative_z_score_zero_risk(self) -> None:
        detector = VelocityAnomalyDetector(z_score_threshold=2.5)
        assert detector._compute_risk_score(-1.0) == 0.0


class TestVelocityAnomalyDetectorCheck:
    """APEP-278: Async check method."""

    @pytest.mark.asyncio
    async def test_check_returns_velocity_result(self) -> None:
        detector = VelocityAnomalyDetector()
        result = await detector.check("test-agent", "test-session")
        assert isinstance(result, VelocityResult)
        assert 0.0 <= result.risk_score <= 1.0
        assert result.detail

    @pytest.mark.asyncio
    async def test_check_no_data_is_not_anomalous(self) -> None:
        """With no session history, should return non-anomalous."""
        detector = VelocityAnomalyDetector()
        result = await detector.check("nonexistent-agent", "empty-session")
        assert not result.is_anomalous
        assert result.risk_score == 0.0

    @pytest.mark.asyncio
    async def test_custom_thresholds(self) -> None:
        detector = VelocityAnomalyDetector(
            window_seconds=60, z_score_threshold=1.0, min_sample_size=5
        )
        assert detector.window_seconds == 60
        assert detector.z_score_threshold == 1.0
        assert detector.min_sample_size == 5


class TestVelocitySingleton:
    """Module-level singleton."""

    def test_singleton_exists(self) -> None:
        assert velocity_anomaly_detector is not None
        assert isinstance(velocity_anomaly_detector, VelocityAnomalyDetector)

    def test_default_config(self) -> None:
        assert velocity_anomaly_detector.window_seconds == 300
        assert velocity_anomaly_detector.z_score_threshold == 2.5
        assert velocity_anomaly_detector.min_sample_size == 10


class TestVelocityResult:
    """VelocityResult dataclass."""

    def test_result_fields(self) -> None:
        result = VelocityResult(
            is_anomalous=True,
            z_score=3.5,
            current_rate=50.0,
            baseline_mean=20.0,
            baseline_stddev=8.57,
            risk_score=0.5,
            detail="Velocity anomaly detected",
        )
        assert result.is_anomalous
        assert result.z_score == 3.5
        assert result.risk_score == 0.5

    def test_result_immutable(self) -> None:
        result = VelocityResult(
            is_anomalous=False, z_score=0.0, current_rate=0.0,
            baseline_mean=0.0, baseline_stddev=0.0, risk_score=0.0, detail=""
        )
        with pytest.raises(AttributeError):
            result.is_anomalous = True  # type: ignore[misc]
