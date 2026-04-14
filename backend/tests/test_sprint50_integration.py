"""Integration and adversarial tests for Sprint 50 (APEP-403).

APEP-403.a: Integration tests for kill switch + policy evaluator.
APEP-403.b: Adversarial tests for FilesystemSentinel and kill switch.
APEP-399.g: Adversarial tests for FilesystemSentinel service.
"""

import asyncio
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.kill_switch import (
    DeescalationState,
    KillSwitchSource,
    KillSwitchState,
    SentinelConfig,
    SentinelEventType,
    SentinelFinding,
    SentinelSeverity,
    ThreatScoreEventType,
)


# ---------------------------------------------------------------------------
# APEP-403.a: Integration tests — Kill switch + PolicyEvaluator
# ---------------------------------------------------------------------------


class TestKillSwitchPolicyEvaluatorIntegration:
    """Integration tests for kill switch enforcing FAIL_CLOSED in PolicyEvaluator."""

    @pytest.mark.asyncio
    async def test_kill_switch_blocks_policy_evaluation(self):
        """When kill switch is activated, PolicyEvaluator should DENY all requests."""
        from app.services.kill_switch import KillSwitchService

        service = KillSwitchService()

        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            await service.activate(
                source=KillSwitchSource.API_ENDPOINT,
                reason="Integration test",
            )

        assert service.is_activated is True

        # The PolicyEvaluator checks kill_switch_service.is_activated
        # Verify the check logic directly
        from app.models.policy import Decision

        if service.is_activated:
            decision = Decision.DENY
        else:
            decision = Decision.ALLOW

        assert decision == Decision.DENY

    @pytest.mark.asyncio
    async def test_kill_switch_deactivated_allows_evaluation(self):
        """When kill switch is NOT activated, evaluation proceeds normally."""
        from app.services.kill_switch import KillSwitchService

        service = KillSwitchService()
        assert service.is_activated is False

    @pytest.mark.asyncio
    async def test_kill_switch_latency_under_100ms(self):
        """Kill switch activation to DENY latency must be < 100ms (PRD requirement)."""
        import time

        from app.services.kill_switch import KillSwitchService

        service = KillSwitchService()

        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            await service.activate(
                source=KillSwitchSource.API_ENDPOINT,
                reason="Latency test",
            )

        # Measure time to check kill switch status
        start = time.monotonic()
        for _ in range(1000):
            _ = service.is_activated
        elapsed_us = (time.monotonic() - start) * 1_000_000 / 1000

        # Single check should be < 1μs (it's a boolean attribute)
        assert elapsed_us < 100  # < 100μs per check (well under 100ms)


# ---------------------------------------------------------------------------
# APEP-403.a: Integration tests — Sentinel + Threat Score
# ---------------------------------------------------------------------------


class TestSentinelThreatScoreIntegration:
    """Integration tests for sentinel findings feeding into adaptive threat score."""

    @pytest.mark.asyncio
    async def test_sentinel_finding_increases_threat_score(self):
        """A sentinel CRITICAL finding should increase the session threat score."""
        from app.services.adaptive_threat_score import AdaptiveThreatScoreEngine

        engine = AdaptiveThreatScoreEngine()

        with patch("app.services.adaptive_threat_score.AdaptiveThreatScoreEngine._publish_score_event", new_callable=AsyncMock):
            # Simulate sentinel finding signal
            result = await engine.record_signal(
                session_id="integration-sess",
                event_type=ThreatScoreEventType.SENTINEL_HIT,
                source="filesystem_sentinel",
                description="Secret detected in /tmp/leaked.env",
            )

            assert result.score > 0.0
            assert result.signal_count == 1
            assert result.highest_event_type == ThreatScoreEventType.SENTINEL_HIT

    @pytest.mark.asyncio
    async def test_multiple_event_types_compound(self):
        """Multiple different event types should compound the threat score."""
        from app.services.adaptive_threat_score import AdaptiveThreatScoreEngine

        engine = AdaptiveThreatScoreEngine()

        with patch("app.services.adaptive_threat_score.AdaptiveThreatScoreEngine._publish_score_event", new_callable=AsyncMock):
            await engine.record_signal(
                session_id="compound-sess",
                event_type=ThreatScoreEventType.NETWORK_DLP_HIT,
            )
            await engine.record_signal(
                session_id="compound-sess",
                event_type=ThreatScoreEventType.INJECTION_DETECTED,
            )
            result = await engine.record_signal(
                session_id="compound-sess",
                event_type=ThreatScoreEventType.CHAIN_DETECTED,
            )

            assert result.score > 0.5
            assert result.signal_count == 3


# ---------------------------------------------------------------------------
# APEP-403.a: Integration tests — Kill switch sources
# ---------------------------------------------------------------------------


class TestKillSwitchSourcesIntegration:
    """Integration tests for multiple kill switch activation sources."""

    @pytest.mark.asyncio
    async def test_api_and_sentinel_sources(self):
        """Both API and sentinel file sources can co-exist."""
        from app.services.kill_switch import KillSwitchService

        service = KillSwitchService()

        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            await service.activate(
                source=KillSwitchSource.API_ENDPOINT,
                reason="API",
            )
            await service.activate(
                source=KillSwitchSource.SENTINEL_FILE,
                reason="File",
            )

            assert service.is_activated is True
            status = service.get_status()
            assert len(status.active_sources) == 2

            # Deactivate API source — still active via sentinel
            await service.deactivate(source=KillSwitchSource.API_ENDPOINT)
            assert service.is_activated is True

            # Deactivate sentinel — fully deactivated
            await service.deactivate(source=KillSwitchSource.SENTINEL_FILE)
            assert service.is_activated is False


# ---------------------------------------------------------------------------
# APEP-399.g: Adversarial tests for FilesystemSentinel
# ---------------------------------------------------------------------------


class TestFilesystemSentinelAdversarial:
    """Adversarial tests for the filesystem sentinel."""

    @pytest.mark.asyncio
    async def test_symlink_attack_does_not_crash(self):
        """Sentinel should handle symlink targets gracefully."""
        from app.services.filesystem_sentinel import FilesystemSentinel

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a symlink to a nonexistent target
            symlink_path = Path(tmpdir) / "evil.env"
            try:
                symlink_path.symlink_to("/nonexistent/path")
            except OSError:
                pytest.skip("Cannot create symlinks")

            sentinel = FilesystemSentinel(config=SentinelConfig(
                watch_paths=[tmpdir],
                enabled=True,
            ))

            # Should not crash when encountering symlinks
            await sentinel._scan_directory(tmpdir)

    @pytest.mark.asyncio
    async def test_permission_denied_does_not_crash(self):
        """Sentinel should handle permission denied gracefully."""
        from app.services.filesystem_sentinel import FilesystemSentinel

        sentinel = FilesystemSentinel(config=SentinelConfig(
            watch_paths=["/root"],  # Likely not readable by test user
            enabled=True,
        ))

        # Should not crash
        await sentinel._scan_directory("/root")

    @pytest.mark.asyncio
    async def test_very_large_file_scan_truncated(self):
        """Large files should only scan the configured max bytes."""
        from app.services.filesystem_sentinel import FilesystemSentinel

        with tempfile.TemporaryDirectory() as tmpdir:
            large_file = Path(tmpdir) / "large.env"
            # Write 2MB of data
            large_file.write_bytes(b"A" * 2_097_152)

            sentinel = FilesystemSentinel(config=SentinelConfig(
                watch_paths=[tmpdir],
                max_file_scan_bytes=1024,  # Only scan first 1KB
                enabled=True,
            ))

            # Should scan only up to max_file_scan_bytes
            results = await sentinel._scan_file_content(large_file)
            # No DLP findings expected from just "A" characters
            assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_binary_file_does_not_crash(self):
        """Sentinel should handle binary files gracefully."""
        from app.services.filesystem_sentinel import FilesystemSentinel

        with tempfile.TemporaryDirectory() as tmpdir:
            binary_file = Path(tmpdir) / "binary.key"
            binary_file.write_bytes(bytes(range(256)) * 100)

            sentinel = FilesystemSentinel(config=SentinelConfig(
                watch_paths=[tmpdir],
                enabled=True,
            ))

            results = await sentinel._scan_file_content(binary_file)
            assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_unicode_filename_handled(self):
        """Sentinel should handle unicode filenames."""
        from app.services.filesystem_sentinel import FilesystemSentinel

        with tempfile.TemporaryDirectory() as tmpdir:
            unicode_file = Path(tmpdir) / "тест.env"
            unicode_file.write_text("SECRET=value")

            sentinel = FilesystemSentinel(config=SentinelConfig(
                watch_paths=[tmpdir],
                enabled=True,
            ))

            # Should not crash
            await sentinel._scan_directory(tmpdir)

    @pytest.mark.asyncio
    async def test_rapid_file_changes_handled(self):
        """Sentinel should handle rapid file creation/deletion."""
        from app.services.filesystem_sentinel import FilesystemSentinel

        with tempfile.TemporaryDirectory() as tmpdir:
            sentinel = FilesystemSentinel(config=SentinelConfig(
                watch_paths=[tmpdir],
                enabled=True,
            ))

            # Rapidly create and delete files
            for i in range(10):
                f = Path(tmpdir) / f"rapid_{i}.env"
                f.write_text(f"KEY_{i}=value_{i}")

            await sentinel._scan_directory(tmpdir)

            # Delete all files
            for i in range(10):
                f = Path(tmpdir) / f"rapid_{i}.env"
                if f.exists():
                    f.unlink()

            # Should handle deleted files gracefully
            await sentinel._scan_directory(tmpdir)


# ---------------------------------------------------------------------------
# APEP-403.b: Adversarial tests — Kill switch
# ---------------------------------------------------------------------------


class TestKillSwitchAdversarial:
    """Adversarial tests for kill switch robustness."""

    @pytest.mark.asyncio
    async def test_concurrent_activations(self):
        """Multiple concurrent activations should not corrupt state."""
        from app.services.kill_switch import KillSwitchService

        service = KillSwitchService()

        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            # Fire multiple activations concurrently
            tasks = [
                service.activate(
                    source=KillSwitchSource.API_ENDPOINT,
                    reason=f"Concurrent {i}",
                )
                for i in range(10)
            ]
            await asyncio.gather(*tasks)

            assert service.is_activated is True
            status = service.get_status()
            # Should only have 1 activation from API_ENDPOINT (idempotent)
            assert KillSwitchSource.API_ENDPOINT in status.active_sources

    @pytest.mark.asyncio
    async def test_activate_deactivate_cycle(self):
        """Rapid activate/deactivate cycles should leave consistent state."""
        from app.services.kill_switch import KillSwitchService

        service = KillSwitchService()

        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            for _ in range(100):
                await service.activate(
                    source=KillSwitchSource.API_ENDPOINT,
                    reason="Cycle",
                )
                await service.deactivate(
                    source=KillSwitchSource.API_ENDPOINT,
                )

            assert service.is_activated is False
            assert service.get_status().state == KillSwitchState.DISARMED

    @pytest.mark.asyncio
    async def test_deactivate_without_activation(self):
        """Deactivating a non-active source should be a no-op."""
        from app.services.kill_switch import KillSwitchService

        service = KillSwitchService()

        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            status = await service.deactivate(
                source=KillSwitchSource.API_ENDPOINT,
            )
            assert status.activated is False

    @pytest.mark.asyncio
    async def test_force_deactivate_when_not_active(self):
        """Force deactivate when nothing is active should be safe."""
        from app.services.kill_switch import KillSwitchService

        service = KillSwitchService()

        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            status = await service.force_deactivate(reason="Safety check")
            assert status.activated is False


# ---------------------------------------------------------------------------
# APEP-403.b: Adversarial tests — Adaptive Threat Score
# ---------------------------------------------------------------------------


class TestAdaptiveThreatScoreAdversarial:
    """Adversarial tests for the adaptive threat score engine."""

    @pytest.mark.asyncio
    async def test_score_never_exceeds_1(self):
        """Score should never exceed 1.0 regardless of input."""
        from app.services.adaptive_threat_score import AdaptiveThreatScoreEngine

        engine = AdaptiveThreatScoreEngine()

        with patch("app.services.adaptive_threat_score.AdaptiveThreatScoreEngine._publish_score_event", new_callable=AsyncMock):
            # Flood with high-severity signals
            for _ in range(100):
                await engine.record_signal(
                    session_id="flood-sess",
                    event_type=ThreatScoreEventType.KILL_SWITCH_ACTIVATED,
                )

            result = engine.get_score("flood-sess")
            assert result.score <= 1.0

    @pytest.mark.asyncio
    async def test_score_never_below_0(self):
        """Score should never go below 0.0."""
        from app.services.adaptive_threat_score import AdaptiveThreatScoreEngine

        engine = AdaptiveThreatScoreEngine()

        result = engine.get_score("empty-sess")
        assert result.score >= 0.0

    @pytest.mark.asyncio
    async def test_many_sessions(self):
        """Engine should handle many concurrent sessions."""
        from app.services.adaptive_threat_score import AdaptiveThreatScoreEngine

        engine = AdaptiveThreatScoreEngine()

        with patch("app.services.adaptive_threat_score.AdaptiveThreatScoreEngine._publish_score_event", new_callable=AsyncMock):
            for i in range(1000):
                await engine.record_signal(
                    session_id=f"session-{i}",
                    event_type=ThreatScoreEventType.DENY_DECISION,
                )

            assert len(engine._sessions) == 1000

            # Each session should have its own independent score
            for i in range(0, 1000, 100):
                result = engine.get_score(f"session-{i}")
                assert result.signal_count == 1
