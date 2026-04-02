"""RoleResolver — walks the AgentRole hierarchy DAG and computes effective permissions.

APEP-021: Resolves all ancestor roles via BFS, merges allowed/denied tool patterns,
and computes the most restrictive max_risk_threshold across the lineage.
"""

import logging
from collections import deque

from app.db import mongodb as db_module
from app.models.policy import AgentRole

logger = logging.getLogger(__name__)


class EffectivePermissions:
    """Computed permission set for an agent after role hierarchy resolution."""

    __slots__ = ("roles", "allowed_tools", "denied_tools", "max_risk_threshold")

    def __init__(
        self,
        roles: list[str],
        allowed_tools: list[str],
        denied_tools: list[str],
        max_risk_threshold: float,
    ):
        self.roles = roles
        self.allowed_tools = allowed_tools
        self.denied_tools = denied_tools
        self.max_risk_threshold = max_risk_threshold


class RoleResolver:
    """Resolves the full role hierarchy for an agent and computes effective permissions."""

    async def resolve_roles(self, agent_id: str) -> list[str]:
        """Return all role_ids for an agent, including inherited roles.

        Walks the role hierarchy DAG via BFS from the agent's direct roles
        through all parent_roles. Returns deduplicated list preserving discovery order.
        """
        db = db_module.get_database()

        # Look up agent profile to get direct roles
        profile = await db[db_module.AGENT_PROFILES].find_one(
            {"agent_id": agent_id, "enabled": True}
        )
        if not profile or not profile.get("roles"):
            return ["default"]

        direct_roles: list[str] = profile["roles"]
        all_roles = await self._walk_hierarchy(direct_roles)
        return all_roles if all_roles else ["default"]

    async def resolve_effective_permissions(self, agent_id: str) -> EffectivePermissions:
        """Compute the effective permission set by merging all roles in the hierarchy."""
        db = db_module.get_database()

        # Get all role_ids (direct + inherited)
        role_ids = await self.resolve_roles(agent_id)

        # Fetch all role documents
        cursor = db[db_module.AGENT_ROLES].find(
            {"role_id": {"$in": role_ids}, "enabled": True}
        )
        role_docs = await cursor.to_list(length=500)
        roles_by_id = {doc["role_id"]: AgentRole(**doc) for doc in role_docs}

        # Merge permissions: union of allowed_tools, union of denied_tools,
        # most restrictive (lowest) max_risk_threshold
        allowed_tools: list[str] = []
        denied_tools: list[str] = []
        max_risk = 1.0

        seen_allowed: set[str] = set()
        seen_denied: set[str] = set()

        for role_id in role_ids:
            role = roles_by_id.get(role_id)
            if role is None:
                continue
            for pattern in role.allowed_tools:
                if pattern not in seen_allowed:
                    seen_allowed.add(pattern)
                    allowed_tools.append(pattern)
            for pattern in role.denied_tools:
                if pattern not in seen_denied:
                    seen_denied.add(pattern)
                    denied_tools.append(pattern)
            if role.max_risk_threshold < max_risk:
                max_risk = role.max_risk_threshold

        return EffectivePermissions(
            roles=role_ids,
            allowed_tools=allowed_tools,
            denied_tools=denied_tools,
            max_risk_threshold=max_risk,
        )

    async def _walk_hierarchy(self, start_roles: list[str]) -> list[str]:
        """BFS walk of the role hierarchy DAG. Returns all reachable role_ids."""
        db = db_module.get_database()
        visited: set[str] = set()
        result: list[str] = []
        queue: deque[str] = deque(start_roles)

        while queue:
            role_id = queue.popleft()
            if role_id in visited:
                continue
            visited.add(role_id)
            result.append(role_id)

            # Fetch parent roles
            role_doc = await db[db_module.AGENT_ROLES].find_one(
                {"role_id": role_id, "enabled": True}
            )
            if role_doc and role_doc.get("parent_roles"):
                for parent_id in role_doc["parent_roles"]:
                    if parent_id not in visited:
                        queue.append(parent_id)

        return result


# Module-level singleton
role_resolver = RoleResolver()
