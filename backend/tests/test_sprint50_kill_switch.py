"""Unit tests for Sprint 50 — Kill Switch, Filesystem Sentinel & Adaptive Threat Score.

APEP-396.e: Unit tests for KillSwitch service.
APEP-397.e: Security validation tests for kill switch activation sources.
APEP-398.c: Security tests for kill switch isolated API port.
APEP-399.f: Unit tests for FilesystemSentinel service.
APEP-400.e: Security validation tests for process lineage attribution on Linux.
APEP-401.e: Unit tests for AdaptiveThreatScore.
APEP-402.c: Unit tests for de-escalation timer.
"""

import asyncio
import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.models.kill_switch import (
    AdaptiveThreatScoreResult,
    DeescalationState,
    DeescalationTimer,
    DeescalationTimerStatus,
    KillSwitchActivateRequest,
    KillSwitchActivation,
    KillSwitchDeactivateRequest,
    KillSwitchEventType,
    KillSwitchSource,
    KillSwitchState,
    KillSwitchStatus,
    ProcessInfo,
    ProcessLineage,
    SentinelConfig,
    SentinelEventType,
    SentinelFinding,
    SentinelSeverity,
    SentinelStatus,
    ThreatScoreEventType,
    ThreatScoreRequest,
    ThreatSignal,
)


# ---------------------------------------------------------------------------
# APEP-396.e: KillSwitch Pydantic model tests
# ---------------------------------------------------------------------------


class TestKillSwitchModels:
    """Unit tests for kill switch Pydantic models."""

    def test_kill_switch_activation_defaults(self):
        activation = KillSwitchActivation(source=KillSwitchSource.API_ENDPOINT)
        assert activation.source == KillSwitchSource.API_ENDPOINT
        assert activation.activation_id is not None
        assert activation.activated_at is not None
        assert activation.activated_by == ""
        assert activation.reason == ""

    def test_kill_switch_activation_full(self):
        activation = KillSwitchActivation(
            source=KillSwitchSource.SIGNAL_SIGUSR1,
            activated_by="pid:12345",
            reason="SIGUSR1 signal received",
        )
        assert activation.source == KillSwitchSource.SIGNAL_SIGUSR1
        assert activation.activated_by == "pid:12345"
        assert activation.reason == "SIGUSR1 signal received"

    def test_kill_switch_status_defaults(self):
        status = KillSwitchStatus()
        assert status.state == KillSwitchState.DISARMED
        assert status.activated is False
        assert status.activations == []
        assert status.active_sources == []
        assert status.total_activations == 0

    def test_kill_switch_activate_request(self):
        req = KillSwitchActivateRequest(
            reason="Test activation",
            activated_by="test_user",
        )
        assert req.reason == "Test activation"
        assert req.activated_by == "test_user"

    def test_kill_switch_deactivate_request(self):
        req = KillSwitchDeactivateRequest(
            reason="Test deactivation",
            deactivated_by="test_admin",
        )
        assert req.reason == "Test deactivation"
        assert req.deactivated_by == "test_admin"

    def test_kill_switch_source_enum(self):
        assert KillSwitchSource.API_ENDPOINT == "API_ENDPOINT"
        assert KillSwitchSource.SIGNAL_SIGUSR1 == "SIGNAL_SIGUSR1"
        assert KillSwitchSource.SENTINEL_FILE == "SENTINEL_FILE"
        assert KillSwitchSource.CONFIG_FLAG == "CONFIG_FLAG"
        assert len(KillSwitchSource) == 4

    def test_kill_switch_state_enum(self):
        assert KillSwitchState.ARMED == "ARMED"
        assert KillSwitchState.DISARMED == "DISARMED"


# ---------------------------------------------------------------------------
# APEP-396.e: KillSwitch service tests
# ---------------------------------------------------------------------------


class TestKillSwitchService:
    """Unit tests for KillSwitchService core logic."""

    def setup_method(self):
        from app.services.kill_switch import KillSwitchService

        self.service = KillSwitchService()

    @pytest.mark.asyncio
    async def test_initially_disarmed(self):
        assert self.service.is_activated is False
        status = self.service.get_status()
        assert status.state == KillSwitchState.DISARMED
        assert status.activated is False

    @pytest.mark.asyncio
    async def test_activate_via_api(self):
        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            status = await self.service.activate(
                source=KillSwitchSource.API_ENDPOINT,
                reason="Test activation",
                activated_by="test",
            )
            assert status.activated is True
            assert status.state == KillSwitchState.ARMED
            assert KillSwitchSource.API_ENDPOINT in status.active_sources
            assert status.total_activations == 1

    @pytest.mark.asyncio
    async def test_activate_idempotent(self):
        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            await self.service.activate(
                source=KillSwitchSource.API_ENDPOINT,
                reason="First",
            )
            status = await self.service.activate(
                source=KillSwitchSource.API_ENDPOINT,
                reason="Second",
            )
            # Second activation from same source is a no-op
            assert status.total_activations == 1

    @pytest.mark.asyncio
    async def test_multiple_sources(self):
        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            await self.service.activate(
                source=KillSwitchSource.API_ENDPOINT,
                reason="API",
            )
            await self.service.activate(
                source=KillSwitchSource.SIGNAL_SIGUSR1,
                reason="Signal",
            )
            status = self.service.get_status()
            assert status.total_activations == 2
            assert len(status.active_sources) == 2
            assert status.activated is True

    @pytest.mark.asyncio
    async def test_deactivate_single_source(self):
        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            await self.service.activate(
                source=KillSwitchSource.API_ENDPOINT,
            )
            await self.service.activate(
                source=KillSwitchSource.SIGNAL_SIGUSR1,
            )
            # Deactivate one source — switch should remain active
            status = await self.service.deactivate(
                source=KillSwitchSource.API_ENDPOINT,
            )
            assert status.activated is True
            assert KillSwitchSource.API_ENDPOINT not in status.active_sources
            assert KillSwitchSource.SIGNAL_SIGUSR1 in status.active_sources

    @pytest.mark.asyncio
    async def test_deactivate_all_sources(self):
        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            await self.service.activate(
                source=KillSwitchSource.API_ENDPOINT,
            )
            status = await self.service.deactivate(
                source=KillSwitchSource.API_ENDPOINT,
            )
            assert status.activated is False
            assert status.state == KillSwitchState.DISARMED

    @pytest.mark.asyncio
    async def test_force_deactivate(self):
        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            await self.service.activate(source=KillSwitchSource.API_ENDPOINT)
            await self.service.activate(source=KillSwitchSource.SIGNAL_SIGUSR1)
            await self.service.activate(source=KillSwitchSource.CONFIG_FLAG)

            status = await self.service.force_deactivate(
                reason="Emergency reset",
                deactivated_by="admin",
            )
            assert status.activated is False
            assert status.state == KillSwitchState.DISARMED
            assert len(status.active_sources) == 0


# ---------------------------------------------------------------------------
# APEP-397.e: Kill switch activation sources tests
# ---------------------------------------------------------------------------


class TestKillSwitchActivationSources:
    """Security validation tests for the 4 kill switch activation sources."""

    def setup_method(self):
        from app.services.kill_switch import KillSwitchService

        self.service = KillSwitchService()

    @pytest.mark.asyncio
    async def test_source1_api_endpoint(self):
        """Source 1: REST API endpoint activation."""
        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            status = await self.service.activate(
                source=KillSwitchSource.API_ENDPOINT,
                reason="API activation",
                activated_by="curl",
            )
            assert KillSwitchSource.API_ENDPOINT in status.active_sources

    @pytest.mark.asyncio
    async def test_source3_sentinel_file(self):
        """Source 3: Sentinel file activation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sentinel_path = os.path.join(tmpdir, "killswitch")

            with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
                # File does not exist — not activated
                self.service._sentinel_path = sentinel_path
                assert not Path(sentinel_path).exists()

                # Create sentinel file
                Path(sentinel_path).touch()
                assert Path(sentinel_path).exists()

                # Simulate sentinel detection
                status = await self.service.activate(
                    source=KillSwitchSource.SENTINEL_FILE,
                    reason=f"Sentinel file detected: {sentinel_path}",
                )
                assert KillSwitchSource.SENTINEL_FILE in status.active_sources
                assert status.activated is True

                # Remove sentinel file and deactivate
                Path(sentinel_path).unlink()
                status = await self.service.deactivate(
                    source=KillSwitchSource.SENTINEL_FILE,
                )
                assert KillSwitchSource.SENTINEL_FILE not in status.active_sources

    @pytest.mark.asyncio
    async def test_source4_config_flag(self):
        """Source 4: Configuration flag activation."""
        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            status = await self.service.activate(
                source=KillSwitchSource.CONFIG_FLAG,
                reason="Config flag set",
            )
            assert KillSwitchSource.CONFIG_FLAG in status.active_sources

    @pytest.mark.asyncio
    async def test_all_4_sources_simultaneous(self):
        """All 4 sources can be active simultaneously."""
        with patch("app.services.kill_switch.KillSwitchService._publish_event", new_callable=AsyncMock):
            for source in KillSwitchSource:
                await self.service.activate(source=source, reason=f"Test {source.value}")

            status = self.service.get_status()
            assert len(status.active_sources) == 4
            assert status.total_activations == 4

            # Deactivate sources one by one
            for source in KillSwitchSource:
                await self.service.deactivate(source=source)

            # Still active until last source deactivated
            status = self.service.get_status()
            assert status.activated is False


# ---------------------------------------------------------------------------
# APEP-398.c: Kill switch isolated port tests
# ---------------------------------------------------------------------------


class TestKillSwitchIsolatedPort:
    """Security tests for the isolated kill switch API port."""

    def test_create_app(self):
        """Isolated app can be created."""
        from app.services.kill_switch_port import create_kill_switch_app

        app = create_kill_switch_app()
        assert app.title == "AgentPEP Kill Switch"
        routes = [r.path for r in app.routes]
        assert "/activate" in routes
        assert "/deactivate" in routes
        assert "/status" in routes
        assert "/health" in routes

    def test_app_has_no_middleware(self):
        """Isolated app has no authentication middleware."""
        from app.services.kill_switch_port import create_kill_switch_app

        app = create_kill_switch_app()
        # The app should have minimal middleware (only default Starlette ones)
        middleware_classes = [m.cls.__name__ for m in app.user_middleware]
        assert "APIKeyAuthMiddleware" not in middleware_classes
        assert "MTLSMiddleware" not in middleware_classes
        assert "CSRFMiddleware" not in middleware_classes


# ---------------------------------------------------------------------------
# APEP-399.f: FilesystemSentinel tests
# ---------------------------------------------------------------------------


class TestFilesystemSentinelModels:
    """Unit tests for FilesystemSentinel Pydantic models."""

    def test_sentinel_finding_defaults(self):
        finding = SentinelFinding(
            event_type=SentinelEventType.SECRET_DETECTED,
        )
        assert finding.event_type == SentinelEventType.SECRET_DETECTED
        assert finding.severity == SentinelSeverity.MEDIUM
        assert finding.finding_id is not None
        assert finding.timestamp is not None

    def test_sentinel_finding_full(self):
        finding = SentinelFinding(
            event_type=SentinelEventType.SECRET_DETECTED,
            severity=SentinelSeverity.CRITICAL,
            file_path="/tmp/leaked.env",
            rule_id="DLP-001",
            description="AWS key detected",
            matched_text="AKIA***",
            process_pid=1234,
            process_name="python3",
            process_lineage=["python3(1234)", "bash(1000)", "systemd(1)"],
            mitre_technique_id="T1552.001",
        )
        assert finding.file_path == "/tmp/leaked.env"
        assert finding.process_pid == 1234
        assert len(finding.process_lineage) == 3

    def test_sentinel_config_defaults(self):
        config = SentinelConfig()
        assert "/tmp" in config.watch_paths
        assert "*.env" in config.file_patterns
        assert config.scan_on_create is True
        assert config.scan_on_modify is True
        assert config.enabled is True

    def test_sentinel_status(self):
        status = SentinelStatus(
            running=True,
            watch_paths=["/tmp"],
            findings_count=5,
        )
        assert status.running is True
        assert status.findings_count == 5


class TestFilesystemSentinel:
    """Unit tests for FilesystemSentinel service logic."""

    def setup_method(self):
        from app.services.filesystem_sentinel import FilesystemSentinel

        self.sentinel = FilesystemSentinel(config=SentinelConfig(
            watch_paths=[],
            enabled=True,
        ))

    def test_initial_state(self):
        status = self.sentinel.get_status()
        assert status.running is False
        assert status.findings_count == 0

    def test_matches_pattern_env(self):
        assert self.sentinel._matches_pattern(".env") is True
        assert self.sentinel._matches_pattern("config.env") is True
        assert self.sentinel._matches_pattern("server.key") is True
        assert self.sentinel._matches_pattern("cert.pem") is True

    def test_matches_pattern_no_match(self):
        assert self.sentinel._matches_pattern("readme.txt") is False
        assert self.sentinel._matches_pattern("app.py") is False

    @pytest.mark.asyncio
    async def test_hash_file(self):
        with tempfile.NamedTemporaryFile(suffix=".env", delete=False) as f:
            f.write(b"SECRET_KEY=test123")
            f.flush()
            path = Path(f.name)

        try:
            h1 = await self.sentinel._hash_file(path)
            assert h1 is not None
            assert len(h1) == 64  # SHA-256 hex digest

            # Same content -> same hash
            h2 = await self.sentinel._hash_file(path)
            assert h1 == h2
        finally:
            path.unlink()

    @pytest.mark.asyncio
    async def test_hash_file_changes_on_modification(self):
        with tempfile.NamedTemporaryFile(suffix=".env", delete=False) as f:
            f.write(b"SECRET_KEY=test123")
            f.flush()
            path = Path(f.name)

        try:
            h1 = await self.sentinel._hash_file(path)
            path.write_text("SECRET_KEY=changed")
            h2 = await self.sentinel._hash_file(path)
            assert h1 != h2
        finally:
            path.unlink()

    @pytest.mark.asyncio
    async def test_scan_path_empty_file(self):
        with tempfile.NamedTemporaryFile(suffix=".env", delete=False) as f:
            f.write(b"")
            f.flush()
            path = Path(f.name)

        try:
            results = await self.sentinel.scan_path(str(path))
            assert results == []
        finally:
            path.unlink()

    @pytest.mark.asyncio
    async def test_scan_path_nonexistent(self):
        results = await self.sentinel.scan_path("/nonexistent/path")
        assert results == []


# ---------------------------------------------------------------------------
# APEP-400.e: Process lineage attribution tests
# ---------------------------------------------------------------------------


class TestProcessLineageModels:
    """Unit tests for process lineage Pydantic models."""

    def test_process_info(self):
        info = ProcessInfo(
            pid=1234,
            ppid=1000,
            name="python3",
            cmdline="python3 app.py",
            exe="/usr/bin/python3",
            uid=1000,
        )
        assert info.pid == 1234
        assert info.ppid == 1000
        assert info.name == "python3"

    def test_process_lineage_trusted(self):
        lineage = ProcessLineage(
            target_pid=1234,
            lineage=[
                ProcessInfo(pid=1234, ppid=1000, name="python3"),
                ProcessInfo(pid=1000, ppid=1, name="bash"),
                ProcessInfo(pid=1, ppid=0, name="systemd"),
            ],
            trusted=True,
            trust_reason="All processes in lineage are known-good",
        )
        assert lineage.trusted is True
        assert len(lineage.lineage) == 3

    def test_process_lineage_suspicious(self):
        lineage = ProcessLineage(
            target_pid=999,
            trusted=False,
            trust_reason="Suspicious indicators: deleted_exe(pid=999)",
            suspicious_indicators=["deleted_exe(pid=999)"],
        )
        assert lineage.trusted is False
        assert len(lineage.suspicious_indicators) == 1


class TestProcessLineageResolver:
    """Unit tests for process lineage resolution."""

    def test_resolver_available(self):
        from app.services.process_lineage import process_lineage_resolver

        # On Linux CI, /proc should exist
        if os.path.isdir("/proc/1"):
            assert process_lineage_resolver.available is True
        else:
            assert process_lineage_resolver.available is False

    def test_resolve_current_process(self):
        from app.services.process_lineage import process_lineage_resolver

        if not process_lineage_resolver.available:
            pytest.skip("Not on Linux with /proc")

        lineage = process_lineage_resolver.resolve(os.getpid())
        assert lineage.target_pid == os.getpid()
        assert len(lineage.lineage) >= 1
        # Current process should be first in lineage
        assert lineage.lineage[0].pid == os.getpid()

    def test_resolve_nonexistent_pid(self):
        from app.services.process_lineage import process_lineage_resolver

        if not process_lineage_resolver.available:
            pytest.skip("Not on Linux with /proc")

        lineage = process_lineage_resolver.resolve(99999999)
        assert lineage.target_pid == 99999999
        assert len(lineage.lineage) == 0

    def test_resolve_non_linux(self):
        from app.services.process_lineage import ProcessLineageResolver

        resolver = ProcessLineageResolver()
        resolver._is_linux = False
        lineage = resolver.resolve(1234)
        assert lineage.trusted is False
        assert "non-Linux" in lineage.trust_reason

    def test_suspicious_indicators_check(self):
        from app.services.process_lineage import ProcessLineageResolver

        resolver = ProcessLineageResolver()

        # Test with a deleted executable
        suspicious_info = ProcessInfo(
            pid=123,
            ppid=1,
            name="suspicious",
            exe="/usr/bin/evil (deleted)",
            cmdline="evil --attack",
        )
        indicators = resolver._check_suspicious([suspicious_info])
        assert any("deleted_exe" in i for i in indicators)

    def test_suspicious_memfd(self):
        from app.services.process_lineage import ProcessLineageResolver

        resolver = ProcessLineageResolver()

        info = ProcessInfo(
            pid=456,
            ppid=1,
            name="memfd_proc",
            exe="memfd:secret",
        )
        indicators = resolver._check_suspicious([info])
        assert any("memfd_exe" in i for i in indicators)

    def test_suspicious_dev_shm(self):
        from app.services.process_lineage import ProcessLineageResolver

        resolver = ProcessLineageResolver()

        info = ProcessInfo(
            pid=789,
            ppid=1,
            name="shm_proc",
            exe="/dev/shm/payload",
        )
        indicators = resolver._check_suspicious([info])
        assert any("dev_shm_exe" in i for i in indicators)

    def test_clean_process_no_indicators(self):
        from app.services.process_lineage import ProcessLineageResolver

        resolver = ProcessLineageResolver()

        info = ProcessInfo(
            pid=1000,
            ppid=1,
            name="python3",
            exe="/usr/bin/python3",
            cmdline="python3 /app/main.py",
        )
        indicators = resolver._check_suspicious([info])
        assert len(indicators) == 0


# ---------------------------------------------------------------------------
# APEP-401.e: AdaptiveThreatScore tests
# ---------------------------------------------------------------------------


class TestAdaptiveThreatScoreModels:
    """Unit tests for AdaptiveThreatScore Pydantic models."""

    def test_threat_signal_defaults(self):
        signal = ThreatSignal(event_type=ThreatScoreEventType.DENY_DECISION)
        assert signal.event_type == ThreatScoreEventType.DENY_DECISION
        assert signal.severity_weight == 0.1
        assert signal.signal_id is not None

    def test_threat_score_result_defaults(self):
        result = AdaptiveThreatScoreResult(session_id="sess-1")
        assert result.score == 0.0
        assert result.signal_count == 0
        assert result.escalation_recommended is False

    def test_threat_score_request(self):
        req = ThreatScoreRequest(session_id="sess-1", include_signals=True)
        assert req.session_id == "sess-1"
        assert req.include_signals is True


class TestAdaptiveThreatScoreEngine:
    """Unit tests for AdaptiveThreatScoreEngine core logic."""

    def setup_method(self):
        from app.services.adaptive_threat_score import AdaptiveThreatScoreEngine

        self.engine = AdaptiveThreatScoreEngine(
            window_seconds=600,
            escalation_threshold=0.7,
            de_escalation_threshold=0.3,
        )

    def test_initial_score_is_zero(self):
        result = self.engine.get_score("session-1")
        assert result.score == 0.0
        assert result.signal_count == 0

    @pytest.mark.asyncio
    async def test_record_signal_increases_score(self):
        with patch("app.services.adaptive_threat_score.AdaptiveThreatScoreEngine._publish_score_event", new_callable=AsyncMock):
            result = await self.engine.record_signal(
                session_id="session-1",
                event_type=ThreatScoreEventType.NETWORK_DLP_HIT,
                source="test",
            )
            assert result.score > 0.0
            assert result.signal_count == 1

    @pytest.mark.asyncio
    async def test_multiple_signals_increase_score(self):
        with patch("app.services.adaptive_threat_score.AdaptiveThreatScoreEngine._publish_score_event", new_callable=AsyncMock):
            await self.engine.record_signal(
                session_id="session-1",
                event_type=ThreatScoreEventType.NETWORK_DLP_HIT,
            )
            result = await self.engine.record_signal(
                session_id="session-1",
                event_type=ThreatScoreEventType.INJECTION_DETECTED,
            )
            assert result.score > 0.0
            assert result.signal_count == 2

    @pytest.mark.asyncio
    async def test_critical_signal_triggers_escalation(self):
        with patch("app.services.adaptive_threat_score.AdaptiveThreatScoreEngine._publish_score_event", new_callable=AsyncMock):
            # Kill switch activation has weight 1.0 — should recommend escalation
            result = await self.engine.record_signal(
                session_id="session-1",
                event_type=ThreatScoreEventType.KILL_SWITCH_ACTIVATED,
            )
            assert result.score >= 0.5
            # Add more signals to cross escalation threshold
            await self.engine.record_signal(
                session_id="session-1",
                event_type=ThreatScoreEventType.SENTINEL_HIT,
            )
            result = await self.engine.record_signal(
                session_id="session-1",
                event_type=ThreatScoreEventType.CHAIN_DETECTED,
            )
            assert result.escalation_recommended is True

    @pytest.mark.asyncio
    async def test_diminishing_returns(self):
        """Repeated signals of the same type have diminishing weight."""
        with patch("app.services.adaptive_threat_score.AdaptiveThreatScoreEngine._publish_score_event", new_callable=AsyncMock):
            r1 = await self.engine.record_signal(
                session_id="session-1",
                event_type=ThreatScoreEventType.DENY_DECISION,
            )
            r2 = await self.engine.record_signal(
                session_id="session-1",
                event_type=ThreatScoreEventType.DENY_DECISION,
            )
            # Score increase should be less for the second identical signal
            delta1 = r1.score
            delta2 = r2.score - r1.score
            assert delta2 < delta1

    @pytest.mark.asyncio
    async def test_separate_sessions_independent(self):
        with patch("app.services.adaptive_threat_score.AdaptiveThreatScoreEngine._publish_score_event", new_callable=AsyncMock):
            await self.engine.record_signal(
                session_id="session-A",
                event_type=ThreatScoreEventType.KILL_SWITCH_ACTIVATED,
            )
            result_b = self.engine.get_score("session-B")
            assert result_b.score == 0.0

    def test_clear_session(self):
        self.engine._get_or_create_session("session-1")
        assert "session-1" in self.engine._sessions
        self.engine.clear_session("session-1")
        assert "session-1" not in self.engine._sessions

    def test_get_score_includes_signals(self):
        # Directly add a signal for testing
        state = self.engine._get_or_create_session("sess-1")
        state.signals.append(ThreatSignal(
            event_type=ThreatScoreEventType.DENY_DECISION,
            severity_weight=0.2,
            session_id="sess-1",
        ))

        result = self.engine.get_score("sess-1", include_signals=True)
        assert len(result.signals) == 1
        assert result.signals[0].event_type == ThreatScoreEventType.DENY_DECISION


# ---------------------------------------------------------------------------
# APEP-402.c: De-escalation timer tests
# ---------------------------------------------------------------------------


class TestDeescalationTimer:
    """Unit tests for de-escalation timer."""

    def test_timer_model_defaults(self):
        timer = DeescalationTimer(session_id="sess-1")
        assert timer.state == DeescalationState.PENDING
        assert timer.decay_rate == 0.1
        assert timer.interval_seconds == 60
        assert timer.timer_id is not None

    def test_timer_status(self):
        status = DeescalationTimerStatus(
            session_id="sess-1",
            active_timers=[
                DeescalationTimer(session_id="sess-1", state=DeescalationState.RUNNING),
            ],
            total_timers=3,
        )
        assert len(status.active_timers) == 1
        assert status.total_timers == 3


class TestDeescalationTimerEngine:
    """Unit tests for de-escalation timer in the adaptive threat score engine."""

    def setup_method(self):
        from app.services.adaptive_threat_score import AdaptiveThreatScoreEngine

        self.engine = AdaptiveThreatScoreEngine()

    def test_create_timer(self):
        timer = self.engine.create_deescalation_timer(
            session_id="sess-1",
            decay_rate=0.2,
            interval_seconds=30,
            target_score=0.0,
        )
        assert timer.state == DeescalationState.RUNNING
        assert timer.decay_rate == 0.2
        assert timer.session_id == "sess-1"

    def test_get_deescalation_status(self):
        self.engine.create_deescalation_timer(session_id="sess-1")
        status = self.engine.get_deescalation_status("sess-1")
        assert len(status.active_timers) == 1
        assert status.total_timers == 1

    def test_cancel_timers(self):
        self.engine.create_deescalation_timer(session_id="sess-1")
        cancelled = self.engine.cancel_deescalation_timers("sess-1", "Test cancel")
        assert cancelled == 1

        status = self.engine.get_deescalation_status("sess-1")
        assert len(status.active_timers) == 0

    @pytest.mark.asyncio
    async def test_new_signal_cancels_timer(self):
        """A new threat signal should cancel running de-escalation timers."""
        with patch("app.services.adaptive_threat_score.AdaptiveThreatScoreEngine._publish_score_event", new_callable=AsyncMock):
            self.engine.create_deescalation_timer(session_id="sess-1")

            # Record new signal — should cancel timer
            await self.engine.record_signal(
                session_id="sess-1",
                event_type=ThreatScoreEventType.DENY_DECISION,
            )

            status = self.engine.get_deescalation_status("sess-1")
            for timer in status.active_timers:
                assert timer.state != DeescalationState.RUNNING

    def test_empty_session_deescalation_status(self):
        status = self.engine.get_deescalation_status("nonexistent")
        assert status.session_id == "nonexistent"
        assert len(status.active_timers) == 0
