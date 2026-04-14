"""Kill Switch Isolated API Port — Sprint 50 (APEP-398).

Serves the kill switch activate/deactivate/status endpoints on a
separate port (default 8890) so that the kill switch remains accessible
even when the main API port (8888) is blocked by enterprise firewalls.

This is a minimal FastAPI app with no middleware, authentication, or
other dependencies — it must be as lightweight and reliable as possible
to serve as an emergency control.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.models.kill_switch import (
    KillSwitchActivateRequest,
    KillSwitchDeactivateRequest,
    KillSwitchSource,
    KillSwitchStatus,
)

logger = logging.getLogger(__name__)

# Default isolated port
KILL_SWITCH_PORT = 8890


def create_kill_switch_app() -> FastAPI:
    """Create a minimal FastAPI app for the isolated kill switch port.

    No middleware, no auth — the kill switch must always be reachable.
    Security is ensured by:
    - Network-level access control (bind to localhost or VPN)
    - The fact that kill switch only denies (cannot ALLOW)
    - Audit logging of all activations
    """
    ks_app = FastAPI(
        title="AgentPEP Kill Switch",
        description="Emergency deny-all kill switch (isolated port)",
        version="1.0.0",
    )

    @ks_app.post("/activate", response_model=KillSwitchStatus)
    async def activate(request: KillSwitchActivateRequest) -> KillSwitchStatus:
        """Emergency kill switch activation."""
        from app.services.kill_switch import kill_switch_service

        return await kill_switch_service.activate(
            source=KillSwitchSource.API_ENDPOINT,
            reason=request.reason,
            activated_by=request.activated_by,
        )

    @ks_app.post("/deactivate", response_model=KillSwitchStatus)
    async def deactivate(request: KillSwitchDeactivateRequest) -> KillSwitchStatus:
        """Deactivate the kill switch."""
        from app.services.kill_switch import kill_switch_service

        return await kill_switch_service.deactivate(
            source=KillSwitchSource.API_ENDPOINT,
            reason=request.reason,
            deactivated_by=request.deactivated_by,
        )

    @ks_app.get("/status", response_model=KillSwitchStatus)
    async def status() -> KillSwitchStatus:
        """Get kill switch status."""
        from app.services.kill_switch import kill_switch_service

        return kill_switch_service.get_status()

    @ks_app.get("/health")
    async def health() -> dict:
        """Health check for the isolated kill switch port."""
        from app.services.kill_switch import kill_switch_service

        return {
            "status": "ok",
            "kill_switch_activated": kill_switch_service.is_activated,
        }

    return ks_app


async def start_kill_switch_server(
    host: str = "127.0.0.1",
    port: int = KILL_SWITCH_PORT,
) -> asyncio.Task:  # type: ignore[type-arg]
    """Start the isolated kill switch server as a background task.

    Binds to localhost by default for security — only same-host
    processes can reach the emergency port.
    """
    try:
        import uvicorn

        ks_app = create_kill_switch_app()
        config = uvicorn.Config(
            app=ks_app,
            host=host,
            port=port,
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(config)
        task = asyncio.ensure_future(server.serve())
        logger.info(
            "Kill switch isolated port started — %s:%d",
            host,
            port,
        )
        return task
    except ImportError:
        logger.warning(
            "uvicorn not available — kill switch isolated port disabled"
        )
        raise
    except Exception:
        logger.exception("Failed to start kill switch isolated port")
        raise
