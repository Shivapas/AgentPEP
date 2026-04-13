"""DataClassificationEngine — data classification enforcement for tool calls.

Sprint 31 — APEP-246: Classification hierarchy enforcement.
Sprint 31 — APEP-247: Data boundary enforcement (user → team → organisation).
Sprint 31 — APEP-248: Clearance-level checking (agent roles → max classification).
"""

from __future__ import annotations

import fnmatch
import logging

from app.db import mongodb as db_module
from app.models.data_classification import (
    DataBoundary,
    DataClassification,
    DataClassificationRule,
    boundary_gte,
    classification_gte,
)

logger = logging.getLogger(__name__)

# MongoDB collection for classification rules
DATA_CLASSIFICATION_RULES = "data_classification_rules"


class DataClassificationEngine:
    """Enforces data classification hierarchy and boundary restrictions.

    Workflow:
    1. Look up the tool's classification rule (by tool_pattern glob match).
    2. If no rule exists, the tool has no classification requirement → allow.
    3. Resolve the agent's clearance level from its roles.
    4. Check clearance: agent clearance must be >= tool's required classification.
    5. Check boundary: agent boundary must be >= tool's required boundary scope.
    """

    async def get_tool_classification(
        self, tool_name: str
    ) -> DataClassificationRule | None:
        """Find the classification rule matching a tool name.

        Uses glob-based matching against ``tool_pattern``. Returns the
        first enabled rule that matches, sorted by most specific pattern
        first (longest pattern wins).
        """
        db = db_module.get_database()
        cursor = db[DATA_CLASSIFICATION_RULES].find({"enabled": True})
        rules = await cursor.to_list(length=500)

        matches: list[DataClassificationRule] = []
        for doc in rules:
            doc.pop("_id", None)
            rule = DataClassificationRule(**doc)
            if fnmatch.fnmatch(tool_name, rule.tool_pattern):
                matches.append(rule)

        if not matches:
            return None

        # Return the most specific match (longest pattern)
        matches.sort(key=lambda r: len(r.tool_pattern), reverse=True)
        return matches[0]

    async def get_agent_clearance(self, agent_roles: list[str]) -> str:
        """Resolve the maximum clearance level across all agent roles.

        Returns the highest clearance level from any of the agent's roles.
        Defaults to ``"PUBLIC"`` if no roles have a clearance level set.
        """
        from app.models.data_classification import CLASSIFICATION_LEVEL

        db = db_module.get_database()
        cursor = db[db_module.AGENT_ROLES].find(
            {"role_id": {"$in": agent_roles}, "enabled": True}
        )
        role_docs = await cursor.to_list(length=100)

        max_clearance = DataClassification.PUBLIC
        max_level = 0

        for doc in role_docs:
            clearance = doc.get("clearance_level", "PUBLIC")
            level = CLASSIFICATION_LEVEL.get(
                DataClassification(clearance)
                if clearance in DataClassification.__members__
                else DataClassification.PUBLIC,
                0,
            )
            if level > max_level:
                max_level = level
                max_clearance = DataClassification(clearance)

        return max_clearance.value

    async def get_agent_boundary(self, agent_roles: list[str]) -> str:
        """Resolve the maximum boundary scope across all agent roles.

        Returns the broadest boundary from any of the agent's roles.
        Defaults to ``"USER_ONLY"`` if no roles have a boundary set.
        """
        from app.models.data_classification import BOUNDARY_LEVEL

        db = db_module.get_database()
        cursor = db[db_module.AGENT_ROLES].find(
            {"role_id": {"$in": agent_roles}, "enabled": True}
        )
        role_docs = await cursor.to_list(length=100)

        max_boundary = DataBoundary.USER_ONLY
        max_level = 0

        for doc in role_docs:
            boundary = doc.get("data_boundary", "USER_ONLY")
            level = BOUNDARY_LEVEL.get(
                DataBoundary(boundary)
                if boundary in DataBoundary.__members__
                else DataBoundary.USER_ONLY,
                0,
            )
            if level > max_level:
                max_level = level
                max_boundary = DataBoundary(boundary)

        return max_boundary.value

    async def enforce(
        self,
        agent_roles: list[str],
        tool_name: str,
        agent_id: str,
    ) -> tuple[bool, str]:
        """Check both clearance and boundary for a tool call.

        Returns ``(allowed, reason)``.
        - ``allowed=True`` if the agent has sufficient clearance and boundary scope.
        - ``allowed=False`` with a descriptive reason if blocked.
        """
        # Look up classification requirement for this tool
        rule = await self.get_tool_classification(tool_name)
        if rule is None:
            # No classification requirement → allow
            return True, ""

        # Check clearance level (APEP-248)
        agent_clearance = await self.get_agent_clearance(agent_roles)
        if not classification_gte(agent_clearance, rule.classification.value):
            return False, (
                f"Data classification check failed: agent clearance={agent_clearance} "
                f"is insufficient for tool '{tool_name}' requiring "
                f"classification={rule.classification.value}"
            )

        # Check boundary scope (APEP-247)
        agent_boundary = await self.get_agent_boundary(agent_roles)
        if not boundary_gte(agent_boundary, rule.boundary.value):
            return False, (
                f"Data boundary check failed: agent boundary={agent_boundary} "
                f"is insufficient for tool '{tool_name}' requiring "
                f"boundary={rule.boundary.value}"
            )

        return True, ""


# Module-level singleton
data_classification_engine = DataClassificationEngine()
