"""Per-session scan mode configuration — Sprint 56 (APEP-444).

Allows sessions to override the default CIS scan mode on a per-session
basis.  Each session can be configured with a specific scan mode (STRICT,
STANDARD, LENIENT) that takes precedence over the global default.

The configuration is stored in MongoDB and cached in memory for fast
lookups during the hot path.  The YOLO mode detector (APEP-445) can
auto-escalate a session to STRICT mode when YOLO mode is detected.

Usage::

    from app.services.session_scan_config import session_scan_config

    # Set session to STRICT mode
    await session_scan_config.set_mode("sess-123", "STRICT", reason="YOLO detected")

    # Resolve effective scan mode for a session
    mode = await session_scan_config.resolve_mode("sess-123", requested="STANDARD")
    # → "STRICT" (session override wins)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from app.services.scan_mode_router import CISScanMode

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SessionScanConfig(BaseModel):
    """Per-session scan mode configuration stored in MongoDB."""

    config_id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str = Field(..., description="Session this config applies to")
    scan_mode: str = Field(default="STANDARD", description="STRICT, STANDARD, or LENIENT")
    reason: str = Field(default="", description="Why the mode was set (e.g. 'YOLO detected')")
    set_by: str = Field(default="system", description="Who set this config: system, admin, yolo_detector")
    risk_multiplier: float = Field(default=1.0, ge=0.1, le=10.0, description="Risk score multiplier for this session")
    locked: bool = Field(default=False, description="If True, mode cannot be downgraded")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class SessionScanConfigResponse(BaseModel):
    """API response for session scan config operations."""

    session_id: str
    effective_mode: str
    risk_multiplier: float = 1.0
    locked: bool = False
    reason: str = ""
    set_by: str = "default"


class SessionScanConfigListResponse(BaseModel):
    """API response for listing session scan configs."""

    configs: list[SessionScanConfig] = Field(default_factory=list)
    total: int = 0


# ---------------------------------------------------------------------------
# Mode priority (STRICT > STANDARD > LENIENT)
# ---------------------------------------------------------------------------

_MODE_PRIORITY: dict[str, int] = {
    "STRICT": 3,
    "STANDARD": 2,
    "LENIENT": 1,
}


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

SCAN_CONFIG_COLLECTION = "session_scan_configs"


class SessionScanConfigService:
    """Manages per-session scan mode configuration (APEP-444).

    Provides a simple API for setting, querying, and resolving the
    effective scan mode for a session.  When a session is locked to
    STRICT (e.g. by the YOLO detector), no downgrade is permitted.
    """

    def __init__(self) -> None:
        self._cache: dict[str, SessionScanConfig] = {}

    async def set_mode(
        self,
        session_id: str,
        scan_mode: str,
        *,
        reason: str = "",
        set_by: str = "system",
        risk_multiplier: float = 1.0,
        lock: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> SessionScanConfig:
        """Set or update the scan mode for a session.

        If the session is already locked and the new mode would be a
        downgrade, the operation is rejected silently (existing config returned).
        """
        # Validate scan mode
        try:
            CISScanMode(scan_mode)
        except ValueError:
            scan_mode = "STRICT"

        existing = self._cache.get(session_id)

        # Prevent downgrade on locked sessions
        if existing and existing.locked:
            existing_prio = _MODE_PRIORITY.get(existing.scan_mode, 0)
            new_prio = _MODE_PRIORITY.get(scan_mode, 0)
            if new_prio < existing_prio:
                logger.info(
                    "Rejecting scan mode downgrade for locked session %s: %s → %s",
                    session_id,
                    existing.scan_mode,
                    scan_mode,
                )
                return existing

        config = SessionScanConfig(
            session_id=session_id,
            scan_mode=scan_mode,
            reason=reason,
            set_by=set_by,
            risk_multiplier=risk_multiplier,
            locked=lock or (existing.locked if existing else False),
            metadata=metadata or {},
        )

        # Persist to MongoDB
        try:
            from app.db import mongodb as db_module

            db = db_module.get_database()
            await db[SCAN_CONFIG_COLLECTION].update_one(
                {"session_id": session_id},
                {"$set": config.model_dump(mode="json")},
                upsert=True,
            )
        except Exception:
            logger.warning(
                "Failed to persist session scan config for %s",
                session_id,
                exc_info=True,
            )

        # Update cache
        self._cache[session_id] = config
        return config

    async def get_config(self, session_id: str) -> SessionScanConfig | None:
        """Get the scan config for a session (cache-first, then DB)."""
        if session_id in self._cache:
            return self._cache[session_id]

        try:
            from app.db import mongodb as db_module

            db = db_module.get_database()
            doc = await db[SCAN_CONFIG_COLLECTION].find_one(
                {"session_id": session_id}, {"_id": 0}
            )
            if doc:
                config = SessionScanConfig.model_validate(doc)
                self._cache[session_id] = config
                return config
        except Exception:
            logger.warning(
                "Failed to load session scan config for %s",
                session_id,
                exc_info=True,
            )
        return None

    async def resolve_mode(
        self,
        session_id: str | None,
        requested: str = "STANDARD",
    ) -> str:
        """Resolve the effective scan mode for a session.

        Priority: session override (if higher) > requested mode.
        If the session has a locked STRICT override, that always wins.
        """
        if not session_id:
            return requested

        config = await self.get_config(session_id)
        if not config:
            return requested

        # Use whichever is more restrictive
        config_prio = _MODE_PRIORITY.get(config.scan_mode, 0)
        requested_prio = _MODE_PRIORITY.get(requested, 0)

        if config_prio >= requested_prio:
            return config.scan_mode
        return requested

    async def get_risk_multiplier(self, session_id: str | None) -> float:
        """Get the risk multiplier for a session (default 1.0)."""
        if not session_id:
            return 1.0
        config = await self.get_config(session_id)
        return config.risk_multiplier if config else 1.0

    async def list_configs(
        self,
        limit: int = 100,
        locked_only: bool = False,
    ) -> SessionScanConfigListResponse:
        """List all active session scan configs."""
        try:
            from app.db import mongodb as db_module

            db = db_module.get_database()
            query: dict = {}
            if locked_only:
                query["locked"] = True

            cursor = (
                db[SCAN_CONFIG_COLLECTION]
                .find(query, {"_id": 0})
                .sort("updated_at", -1)
                .limit(limit)
            )
            configs = [SessionScanConfig.model_validate(doc) async for doc in cursor]
            total = await db[SCAN_CONFIG_COLLECTION].count_documents(query)
            return SessionScanConfigListResponse(configs=configs, total=total)
        except Exception:
            logger.warning("Failed to list session scan configs", exc_info=True)
            return SessionScanConfigListResponse()

    async def remove_config(self, session_id: str) -> bool:
        """Remove the scan config for a session."""
        self._cache.pop(session_id, None)
        try:
            from app.db import mongodb as db_module

            db = db_module.get_database()
            result = await db[SCAN_CONFIG_COLLECTION].delete_one(
                {"session_id": session_id}
            )
            return result.deleted_count > 0
        except Exception:
            logger.warning(
                "Failed to remove session scan config for %s",
                session_id,
                exc_info=True,
            )
            return False

    def clear_cache(self) -> None:
        """Clear the in-memory cache (for testing)."""
        self._cache.clear()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

session_scan_config = SessionScanConfigService()
