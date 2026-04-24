"""AAPM Policy Registry pull-polling fallback — FEATURE-09 (Part A).

Polls the AAPM registry every 60 seconds for a new bundle version.  This
is the fallback for when the AAPM webhook (registry_webhook.py) is
temporarily unreachable.  When both mechanisms are active, the poller
detects a bundle already loaded by the webhook (ETag unchanged → 304 Not
Modified) and no-ops cleanly.

Polling interval: 60 seconds (configurable via
``AGENTPEP_POLICY_POLL_INTERVAL_S``; default 60).

ETag-based conditional GET:
  - ``If-None-Match: <current_etag>`` sent on every poll request.
  - 304 Not Modified → no reload.
  - 200 OK → full signature verify → reload.

Sprint S-E03 (E03-T06)
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from app.core.structured_logging import get_logger
from app.policy.bundle_version import bundle_version_tracker
from app.policy.loader import PolicyLoaderError, TrustedPolicyLoader, policy_loader
from app.policy.trusted_key import AAPM_REGISTRY_BASE_URL

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Poller
# ---------------------------------------------------------------------------

_DEFAULT_POLL_INTERVAL_S: float = 60.0
_DEFAULT_BUNDLE_URL: str = (
    AAPM_REGISTRY_BASE_URL + "global/core_enforcement/latest/bundle.tar.gz"
)


class RegistryPoller:
    """Async background task that polls the AAPM registry for bundle updates.

    Instantiate and call ``start()`` during application startup, then
    ``stop()`` during shutdown.

    The poller uses ETag-based conditional GET so that unchanged bundles
    are detected without a full download (304 Not Modified path).
    """

    def __init__(
        self,
        bundle_url: str = _DEFAULT_BUNDLE_URL,
        poll_interval_s: float = _DEFAULT_POLL_INTERVAL_S,
        tenant_id: str = "global",
        bundle_name: str = "core_enforcement",
        _loader_override: TrustedPolicyLoader | None = None,
    ) -> None:
        self._bundle_url = bundle_url
        self._poll_interval_s = poll_interval_s
        self._tenant_id = tenant_id
        self._bundle_name = bundle_name
        self._loader: TrustedPolicyLoader = _loader_override or policy_loader  # type: ignore[assignment]
        self._current_etag: str = ""
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._poll_count: int = 0
        self._reload_count: int = 0
        self._last_poll_at: float = 0.0
        self._last_error: str = ""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the background polling loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(
            self._poll_loop(), name="agentpep-policy-poll"
        )
        logger.info(
            "registry_poller_started",
            bundle_url=self._bundle_url,
            poll_interval_s=self._poll_interval_s,
        )

    async def stop(self) -> None:
        """Stop the polling loop and wait for it to exit cleanly."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("registry_poller_stopped")

    # ------------------------------------------------------------------
    # Poll loop
    # ------------------------------------------------------------------

    async def _poll_loop(self) -> None:
        """Main polling loop — runs until ``stop()`` is called."""
        while self._running:
            await self._poll_once()
            try:
                await asyncio.sleep(self._poll_interval_s)
            except asyncio.CancelledError:
                break

    async def _poll_once(self) -> None:
        """Execute a single poll cycle."""
        self._poll_count += 1
        self._last_poll_at = time.time()

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                self._sync_poll,
            )
            if result is not None:
                self._reload_count += 1
                logger.info(
                    "registry_poll_bundle_reloaded",
                    version=result["version"],
                    poll_count=self._poll_count,
                    reload_count=self._reload_count,
                )
            else:
                logger.debug(
                    "registry_poll_no_change",
                    poll_count=self._poll_count,
                    current_etag=self._current_etag,
                )
            self._last_error = ""
        except PolicyLoaderError as exc:
            self._last_error = str(exc)
            logger.error(
                "registry_poll_bundle_load_failed",
                error=str(exc),
                poll_count=self._poll_count,
            )
        except Exception as exc:
            self._last_error = str(exc)
            logger.error(
                "registry_poll_unexpected_error",
                error=str(exc),
                poll_count=self._poll_count,
            )

    def _sync_poll(self) -> dict[str, Any] | None:
        """Synchronous poll executed in the thread-pool executor.

        Returns:
            A dict describing the newly loaded bundle if a reload occurred.
            None if the bundle was unchanged (304 / ETag match).

        Raises:
            PolicyLoaderError: If the new bundle cannot be loaded or verified.
        """
        body, new_etag = self._loader.fetch_with_etag(
            self._bundle_url,
            current_etag=self._current_etag,
        )

        if body is None:
            # 304 Not Modified — bundle unchanged
            return None

        # New bundle received; verify and load
        sig_url = self._bundle_url + ".sig"
        sig_body, _ = self._loader.fetch_with_etag(sig_url)
        if sig_body is None:
            # Signature file 304'd even though bundle changed — unusual;
            # treat as load failure (FAIL_CLOSED).
            raise PolicyLoaderError(
                "Signature file returned 304 while bundle returned 200 — "
                "inconsistent registry state; reload aborted."
            )

        # Delegate full verification to the loader internals
        loaded = self._loader.load_and_track(
            bundle_url=self._bundle_url,
            tenant_id=self._tenant_id,
            bundle_name=self._bundle_name,
        )
        self._current_etag = new_etag
        return {
            "version": loaded.version.version,
            "etag": new_etag,
        }

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict[str, Any]:
        """Return poller runtime statistics for health endpoints."""
        return {
            "running": self._running,
            "poll_interval_s": self._poll_interval_s,
            "bundle_url": self._bundle_url,
            "poll_count": self._poll_count,
            "reload_count": self._reload_count,
            "last_poll_at": self._last_poll_at,
            "last_error": self._last_error,
            "current_etag": self._current_etag,
            "current_bundle_version": bundle_version_tracker.version_string,
        }


# ---------------------------------------------------------------------------
# Module-level singleton (lazily configured from settings)
# ---------------------------------------------------------------------------


def _build_poller() -> RegistryPoller:
    from app.core.config import settings

    bundle_url = getattr(
        settings,
        "policy_registry_bundle_url",
        _DEFAULT_BUNDLE_URL,
    )
    poll_interval_s = getattr(
        settings,
        "policy_poll_interval_s",
        _DEFAULT_POLL_INTERVAL_S,
    )
    tenant_id = getattr(settings, "policy_tenant_id", "global")
    bundle_name = getattr(settings, "policy_bundle_name", "core_enforcement")

    return RegistryPoller(
        bundle_url=bundle_url,
        poll_interval_s=poll_interval_s,
        tenant_id=tenant_id,
        bundle_name=bundle_name,
    )


class _LazyPoller:
    """Lazy singleton; ``reconfigure()`` resets the instance."""

    _instance: RegistryPoller | None = None

    def _get(self) -> RegistryPoller:
        if self._instance is None:
            self._instance = _build_poller()
        return self._instance

    async def start(self) -> None:
        await self._get().start()

    async def stop(self) -> None:
        await self._get().stop()

    @property
    def stats(self) -> dict[str, Any]:
        return self._get().stats

    def reconfigure(self) -> None:
        self._instance = None


registry_poller = _LazyPoller()
