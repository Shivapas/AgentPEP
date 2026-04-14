"""Kill Switch Service — Sprint 50 (APEP-396/397/398).

Implements an emergency deny-all kill switch with 4 independent activation
sources:
  1. REST API endpoint (APEP-396.d)
  2. UNIX signal SIGUSR1 (APEP-397)
  3. Sentinel file watcher (APEP-397)
  4. Configuration flag (APEP-397)

When activated, AgentPEP's FAIL_CLOSED mode engages and all policy
evaluations return DENY immediately.  The kill switch also publishes
a KILL_SWITCH event to the agentpep.network Kafka topic.

APEP-398: Isolated API port for kill switch activation so that
enterprise firewalls cannot block emergency access.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from pathlib import Path

from app.core.config import settings
from app.models.kill_switch import (
    KillSwitchActivation,
    KillSwitchEventType,
    KillSwitchSource,
    KillSwitchState,
    KillSwitchStatus,
)

logger = logging.getLogger(__name__)

# Sentinel file path — if this file exists, kill switch is activated
_DEFAULT_SENTINEL_PATH = "/tmp/agentpep-killswitch"


class KillSwitchService:
    """Emergency deny-all kill switch with 4 independent activation sources.

    The service is thread-safe via a simple boolean flag that is checked
    in the hot path.  Activation is immediate; deactivation requires
    explicit API call or removal of all activation sources.
    """

    def __init__(self) -> None:
        self._activated: bool = False
        self._state = KillSwitchState.DISARMED
        self._activations: list[KillSwitchActivation] = []
        self._active_sources: set[KillSwitchSource] = set()
        self._last_activated_at: float | None = None
        self._last_deactivated_at: float | None = None
        self._total_activations: int = 0
        self._sentinel_path: str = _DEFAULT_SENTINEL_PATH
        self._sentinel_task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._signal_registered: bool = False
        self._config_check_task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._running: bool = False

    # ------------------------------------------------------------------
    # Core state
    # ------------------------------------------------------------------

    @property
    def is_activated(self) -> bool:
        """Check if the kill switch is currently activated (hot-path safe)."""
        return self._activated

    def get_status(self) -> KillSwitchStatus:
        """Return current kill switch status."""
        from datetime import UTC, datetime

        return KillSwitchStatus(
            state=self._state,
            activated=self._activated,
            activations=list(self._activations[-50:]),  # Last 50 activations
            last_activated_at=(
                datetime.fromtimestamp(self._last_activated_at, tz=UTC)
                if self._last_activated_at
                else None
            ),
            last_deactivated_at=(
                datetime.fromtimestamp(self._last_deactivated_at, tz=UTC)
                if self._last_deactivated_at
                else None
            ),
            active_sources=sorted(self._active_sources),
            total_activations=self._total_activations,
        )

    # ------------------------------------------------------------------
    # Activation (APEP-396.c)
    # ------------------------------------------------------------------

    async def activate(
        self,
        source: KillSwitchSource,
        reason: str = "",
        activated_by: str = "",
    ) -> KillSwitchStatus:
        """Activate the kill switch from a specific source.

        Activation is idempotent — activating an already-active switch
        from the same source is a no-op.  Multiple sources can activate
        simultaneously; the switch remains active until ALL sources deactivate.
        """
        if source in self._active_sources:
            logger.info(
                "Kill switch already active from source %s", source.value
            )
            return self.get_status()

        activation = KillSwitchActivation(
            source=source,
            activated_by=activated_by or source.value,
            reason=reason or f"Activated via {source.value}",
        )

        self._active_sources.add(source)
        self._activations.append(activation)
        self._total_activations += 1
        self._activated = True
        self._state = KillSwitchState.ARMED
        self._last_activated_at = time.time()

        logger.critical(
            "KILL SWITCH ACTIVATED — source=%s reason=%s activated_by=%s",
            source.value,
            reason,
            activated_by,
        )

        # Publish Kafka event
        await self._publish_event(
            KillSwitchEventType.KILL_SWITCH_ACTIVATED,
            source=source,
            activated_by=activated_by,
            reason=reason,
        )

        return self.get_status()

    # ------------------------------------------------------------------
    # Deactivation
    # ------------------------------------------------------------------

    async def deactivate(
        self,
        source: KillSwitchSource,
        reason: str = "",
        deactivated_by: str = "",
    ) -> KillSwitchStatus:
        """Deactivate the kill switch for a specific source.

        The switch only fully deactivates when ALL sources have been
        deactivated.
        """
        if source not in self._active_sources:
            return self.get_status()

        self._active_sources.discard(source)

        logger.warning(
            "Kill switch source deactivated — source=%s remaining=%s",
            source.value,
            [s.value for s in self._active_sources],
        )

        if not self._active_sources:
            self._activated = False
            self._state = KillSwitchState.DISARMED
            self._last_deactivated_at = time.time()

            logger.warning(
                "KILL SWITCH FULLY DEACTIVATED — reason=%s deactivated_by=%s",
                reason,
                deactivated_by,
            )

            await self._publish_event(
                KillSwitchEventType.KILL_SWITCH_DEACTIVATED,
                source=source,
                activated_by=deactivated_by,
                reason=reason,
            )

        return self.get_status()

    async def force_deactivate(
        self,
        reason: str = "",
        deactivated_by: str = "",
    ) -> KillSwitchStatus:
        """Force-deactivate the kill switch from ALL sources."""
        self._active_sources.clear()
        self._activated = False
        self._state = KillSwitchState.DISARMED
        self._last_deactivated_at = time.time()

        logger.warning(
            "KILL SWITCH FORCE DEACTIVATED — reason=%s by=%s",
            reason,
            deactivated_by,
        )

        await self._publish_event(
            KillSwitchEventType.KILL_SWITCH_DEACTIVATED,
            reason=reason or "Force deactivation",
            activated_by=deactivated_by,
        )

        return self.get_status()

    # ------------------------------------------------------------------
    # Source 2: SIGUSR1 signal handler (APEP-397)
    # ------------------------------------------------------------------

    def register_signal_handler(self) -> None:
        """Register SIGUSR1 signal handler for kill switch activation.

        Only works on POSIX systems.  Safe to call multiple times.
        """
        if self._signal_registered:
            return

        try:
            loop = asyncio.get_running_loop()
            loop.add_signal_handler(
                signal.SIGUSR1,
                self._handle_sigusr1,
            )
            self._signal_registered = True
            logger.info("Kill switch SIGUSR1 handler registered")
        except (NotImplementedError, OSError, RuntimeError):
            logger.warning(
                "Cannot register SIGUSR1 handler — signal-based kill switch unavailable"
            )

    def _handle_sigusr1(self) -> None:
        """Handle SIGUSR1 signal — toggle kill switch."""
        if self._activated and KillSwitchSource.SIGNAL_SIGUSR1 in self._active_sources:
            asyncio.ensure_future(
                self.deactivate(
                    KillSwitchSource.SIGNAL_SIGUSR1,
                    reason="SIGUSR1 toggle (deactivate)",
                )
            )
        else:
            asyncio.ensure_future(
                self.activate(
                    KillSwitchSource.SIGNAL_SIGUSR1,
                    reason="SIGUSR1 signal received",
                    activated_by=f"pid:{os.getpid()}",
                )
            )

    # ------------------------------------------------------------------
    # Source 3: Sentinel file watcher (APEP-397)
    # ------------------------------------------------------------------

    async def start_sentinel_file_watcher(
        self,
        path: str | None = None,
        poll_interval: float = 1.0,
    ) -> None:
        """Start watching for a sentinel file that activates the kill switch.

        If the file exists, the kill switch activates.  If the file is
        removed, the sentinel source deactivates.
        """
        if self._sentinel_task is not None:
            return

        self._sentinel_path = path or _DEFAULT_SENTINEL_PATH
        self._running = True
        self._sentinel_task = asyncio.ensure_future(
            self._sentinel_file_loop(poll_interval)
        )
        logger.info(
            "Kill switch sentinel file watcher started — path=%s",
            self._sentinel_path,
        )

    async def _sentinel_file_loop(self, interval: float) -> None:
        """Poll for sentinel file existence."""
        while self._running:
            try:
                sentinel_exists = Path(self._sentinel_path).exists()

                if sentinel_exists and KillSwitchSource.SENTINEL_FILE not in self._active_sources:
                    await self.activate(
                        KillSwitchSource.SENTINEL_FILE,
                        reason=f"Sentinel file detected: {self._sentinel_path}",
                        activated_by="sentinel_watcher",
                    )
                elif not sentinel_exists and KillSwitchSource.SENTINEL_FILE in self._active_sources:
                    await self.deactivate(
                        KillSwitchSource.SENTINEL_FILE,
                        reason=f"Sentinel file removed: {self._sentinel_path}",
                        deactivated_by="sentinel_watcher",
                    )
            except Exception:
                logger.warning("Sentinel file check failed", exc_info=True)

            await asyncio.sleep(interval)

    # ------------------------------------------------------------------
    # Source 4: Config flag check (APEP-397)
    # ------------------------------------------------------------------

    async def start_config_flag_watcher(
        self,
        poll_interval: float = 5.0,
    ) -> None:
        """Start watching the config flag for kill switch state."""
        if self._config_check_task is not None:
            return

        self._running = True
        self._config_check_task = asyncio.ensure_future(
            self._config_flag_loop(poll_interval)
        )
        logger.info("Kill switch config flag watcher started")

    async def _config_flag_loop(self, interval: float) -> None:
        """Poll the configuration for the kill switch flag."""
        while self._running:
            try:
                flag = getattr(settings, "kill_switch_activated", False)

                if flag and KillSwitchSource.CONFIG_FLAG not in self._active_sources:
                    await self.activate(
                        KillSwitchSource.CONFIG_FLAG,
                        reason="Config flag AGENTPEP_KILL_SWITCH_ACTIVATED=true",
                        activated_by="config_watcher",
                    )
                elif not flag and KillSwitchSource.CONFIG_FLAG in self._active_sources:
                    await self.deactivate(
                        KillSwitchSource.CONFIG_FLAG,
                        reason="Config flag AGENTPEP_KILL_SWITCH_ACTIVATED=false",
                        deactivated_by="config_watcher",
                    )
            except Exception:
                logger.warning("Config flag check failed", exc_info=True)

            await asyncio.sleep(interval)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start all kill switch watchers and register signal handler."""
        self._running = True

        # Source 2: SIGUSR1
        self.register_signal_handler()

        # Source 3: Sentinel file
        await self.start_sentinel_file_watcher()

        # Source 4: Config flag
        await self.start_config_flag_watcher()

        # Check if config flag is already set on startup
        if getattr(settings, "kill_switch_activated", False):
            await self.activate(
                KillSwitchSource.CONFIG_FLAG,
                reason="Kill switch activated on startup via config",
                activated_by="startup",
            )

        logger.info("Kill switch service started — all 4 sources active")

    async def stop(self) -> None:
        """Stop all watchers and clean up."""
        self._running = False

        if self._sentinel_task is not None:
            self._sentinel_task.cancel()
            try:
                await self._sentinel_task
            except asyncio.CancelledError:
                pass
            self._sentinel_task = None

        if self._config_check_task is not None:
            self._config_check_task.cancel()
            try:
                await self._config_check_task
            except asyncio.CancelledError:
                pass
            self._config_check_task = None

        logger.info("Kill switch service stopped")

    # ------------------------------------------------------------------
    # Kafka events
    # ------------------------------------------------------------------

    async def _publish_event(
        self,
        event_type: KillSwitchEventType,
        source: KillSwitchSource | None = None,
        activated_by: str = "",
        reason: str = "",
    ) -> None:
        """Publish a kill switch event to Kafka."""
        try:
            from app.services.kafka_producer import kafka_producer

            event = {
                "event_type": event_type.value,
                "source": source.value if source else "",
                "activated_by": activated_by,
                "reason": reason,
                "state": self._state.value,
            }
            await kafka_producer.publish_network_event(event)
        except Exception:
            logger.warning("Failed to publish kill switch event", exc_info=True)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

kill_switch_service = KillSwitchService()
