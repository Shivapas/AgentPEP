"""TenantIsolationGuard — enforces multi-tenancy data isolation.

Sprint 36 — APEP-290: Ensures that tenants cannot access data belonging
to other tenants. Validates tenant boundaries on every data access and
logs violations for security auditing.
"""

from __future__ import annotations

import logging
from typing import Any

from app.db import mongodb as db_module
from app.models.sprint36 import (
    TenantIsolationConfig,
    TenantIsolationViolation,
)

logger = logging.getLogger(__name__)


class TenantIsolationGuard:
    """Enforce data isolation between tenants.

    Validates that data access respects tenant boundaries. In STRICT mode,
    no cross-tenant access is allowed. In SHARED mode, only peer tenants
    in the allowed list can read data.
    """

    # In-memory cache of tenant configs for fast lookups
    _config_cache: dict[str, TenantIsolationConfig] = {}

    async def get_config(self, tenant_id: str) -> TenantIsolationConfig | None:
        """Get tenant isolation config, with in-memory caching."""
        if tenant_id in self._config_cache:
            return self._config_cache[tenant_id]

        db = db_module.get_database()
        doc = await db[db_module.TENANT_ISOLATION_CONFIGS].find_one(
            {"tenant_id": tenant_id}
        )
        if doc:
            config = TenantIsolationConfig(**doc)
            self._config_cache[tenant_id] = config
            return config
        return None

    async def set_config(self, config: TenantIsolationConfig) -> TenantIsolationConfig:
        """Create or update a tenant isolation config."""
        db = db_module.get_database()
        collection = db[db_module.TENANT_ISOLATION_CONFIGS]

        await collection.update_one(
            {"tenant_id": config.tenant_id},
            {"$set": config.model_dump(mode="json")},
            upsert=True,
        )
        self._config_cache[config.tenant_id] = config
        logger.info(
            "tenant_config_updated tenant_id=%s boundary=%s",
            config.tenant_id,
            config.data_boundary,
        )
        return config

    async def check_access(
        self,
        source_tenant_id: str,
        target_tenant_id: str,
        resource_type: str = "session",
        resource_id: str = "",
    ) -> tuple[bool, str]:
        """Check if a tenant can access another tenant's data.

        Args:
            source_tenant_id: Tenant requesting access.
            target_tenant_id: Tenant owning the data.
            resource_type: Type of resource being accessed.
            resource_id: Specific resource ID.

        Returns:
            Tuple of (allowed: bool, reason: str).
        """
        # Same tenant always allowed
        if source_tenant_id == target_tenant_id:
            return True, "Same tenant"

        # Default tenant has no restrictions
        if source_tenant_id == "default" or target_tenant_id == "default":
            return True, "Default tenant bypass"

        source_config = await self.get_config(source_tenant_id)
        target_config = await self.get_config(target_tenant_id)

        # If no config exists, default to strict isolation
        if not source_config or not target_config:
            await self._log_violation(
                source_tenant_id,
                target_tenant_id,
                resource_type,
                resource_id,
                "No tenant isolation config — defaulting to STRICT",
            )
            return False, "No tenant isolation config — cross-tenant access denied"

        # STRICT mode: no cross-tenant access
        if source_config.data_boundary == "STRICT":
            await self._log_violation(
                source_tenant_id,
                target_tenant_id,
                resource_type,
                resource_id,
                "STRICT isolation — cross-tenant access blocked",
            )
            return False, "STRICT isolation — cross-tenant access denied"

        # SHARED mode: check peer tenant allowlist
        if source_config.data_boundary == "SHARED":
            if target_tenant_id in source_config.allowed_peer_tenants:
                return True, f"SHARED access allowed to peer tenant {target_tenant_id}"
            await self._log_violation(
                source_tenant_id,
                target_tenant_id,
                resource_type,
                resource_id,
                f"SHARED isolation — {target_tenant_id} not in allowed peers",
            )
            return False, f"SHARED isolation — {target_tenant_id} not in allowed peers"

        await self._log_violation(
            source_tenant_id,
            target_tenant_id,
            resource_type,
            resource_id,
            f"Unknown data_boundary: {source_config.data_boundary}",
        )
        return False, "Unknown data boundary configuration"

    async def _log_violation(
        self,
        source_tenant_id: str,
        target_tenant_id: str,
        resource_type: str,
        resource_id: str,
        detail: str,
    ) -> None:
        """Log a tenant isolation violation."""
        violation = TenantIsolationViolation(
            source_tenant_id=source_tenant_id,
            target_tenant_id=target_tenant_id,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=detail,
            blocked=True,
        )

        db = db_module.get_database()
        await db[db_module.TENANT_ISOLATION_VIOLATIONS].insert_one(
            violation.model_dump(mode="json")
        )

        # Emit Prometheus metric
        try:
            from app.core.observability import TENANT_ISOLATION_VIOLATIONS as VIOLATIONS_METRIC

            VIOLATIONS_METRIC.labels(
                source_tenant=source_tenant_id,
                resource_type=resource_type,
            ).inc()
        except Exception:
            pass

        logger.warning(
            "tenant_isolation_violation source=%s target=%s resource=%s detail=%s",
            source_tenant_id,
            target_tenant_id,
            resource_type,
            detail,
        )

    async def get_violations(
        self,
        tenant_id: str | None = None,
        limit: int = 100,
    ) -> list[TenantIsolationViolation]:
        """Query tenant isolation violations."""
        db = db_module.get_database()
        collection = db[db_module.TENANT_ISOLATION_VIOLATIONS]

        query: dict[str, Any] = {}
        if tenant_id:
            query["$or"] = [
                {"source_tenant_id": tenant_id},
                {"target_tenant_id": tenant_id},
            ]

        cursor = collection.find(query).sort("detected_at", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [TenantIsolationViolation(**doc) for doc in docs]

    def invalidate_cache(self, tenant_id: str | None = None) -> None:
        """Clear the config cache for a tenant or all tenants."""
        if tenant_id:
            self._config_cache.pop(tenant_id, None)
        else:
            self._config_cache.clear()


# Module-level singleton
tenant_isolation_guard = TenantIsolationGuard()
