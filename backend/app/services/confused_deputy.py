"""Confused-Deputy Detector — delegation chain authority validation.

Sprint 7: APEP-055 through APEP-059.

Validates that every hop in an agent delegation chain has proper authority,
enforces configurable chain depth limits, detects implicit delegation via
shared workspace writes, and emits SECURITY_ALERT events on violations.
"""

import fnmatch
import logging
from datetime import datetime
from uuid import UUID

from app.db import mongodb as db_module
from app.models.policy import (
    DelegationHop,
    SecurityAlertEvent,
    SecurityAlertType,
)

logger = logging.getLogger(__name__)

# Collection name for security alerts
SECURITY_ALERTS = "security_alerts"

# Default max chain depth
DEFAULT_MAX_CHAIN_DEPTH = 5


# ---------------------------------------------------------------------------
# APEP-055: DelegationChainWalker
# ---------------------------------------------------------------------------


class DelegationChainWalker:
    """Traverses an agent-to-agent delegation chain from tool call to origin.

    Walks the hop list in order (origin → current) and yields each hop
    along with the accumulated granted-tool set at that point.
    """

    @staticmethod
    def walk(hops: list[DelegationHop]) -> list[tuple[int, DelegationHop]]:
        """Return enumerated (depth, hop) pairs for the chain."""
        return list(enumerate(hops))

    @staticmethod
    def get_agent_ids(hops: list[DelegationHop]) -> list[str]:
        """Extract ordered list of agent IDs from the delegation chain."""
        return [hop.agent_id for hop in hops]

    @staticmethod
    def get_granted_tools_at_hop(hops: list[DelegationHop], depth: int) -> list[str]:
        """Return the granted_tools at a specific hop depth."""
        if 0 <= depth < len(hops):
            return hops[depth].granted_tools
        return []

    @staticmethod
    def find_authority_source(hops: list[DelegationHop], agent_id: str) -> str | None:
        """Find the authority_source for a given agent in the chain."""
        for hop in hops:
            if hop.agent_id == agent_id:
                return hop.authority_source
        return None


# ---------------------------------------------------------------------------
# APEP-056: AuthorityValidator
# ---------------------------------------------------------------------------


class AuthorityValidator:
    """Per-hop authority check: ensures the originating user granted each
    action in the chain.

    Each hop's granted_tools must be a subset of (or matched by) the previous
    hop's granted_tools. The first hop is validated against the agent's profile
    allowed_tools from the database.
    """

    async def validate_chain(
        self,
        hops: list[DelegationHop],
        tool_name: str,
    ) -> tuple[bool, str]:
        """Validate the full delegation chain for a specific tool call.

        Returns (is_valid, reason).
        """
        if not hops:
            return True, "No delegation chain — direct call"

        # Validate first hop has authority from user/role
        first_hop = hops[0]
        origin_valid = await self._validate_origin(first_hop)
        if not origin_valid:
            return False, (
                f"Origin agent '{first_hop.agent_id}' lacks authority "
                f"from source '{first_hop.authority_source}'"
            )

        # Walk the chain: each hop's granted_tools must be allowed by the previous hop
        for i in range(1, len(hops)):
            parent_hop = hops[i - 1]
            current_hop = hops[i]

            if not self._tools_subset(current_hop.granted_tools, parent_hop.granted_tools):
                return False, (
                    f"Hop {i}: agent '{current_hop.agent_id}' granted tools "
                    f"{current_hop.granted_tools} exceed parent "
                    f"'{parent_hop.agent_id}' grants {parent_hop.granted_tools}"
                )

        # Verify the final agent in the chain is allowed to call the requested tool
        last_hop = hops[-1]
        if last_hop.granted_tools and not self._tool_matches_grants(
            tool_name, last_hop.granted_tools
        ):
            return False, (
                f"Tool '{tool_name}' not in granted tools "
                f"{last_hop.granted_tools} for agent '{last_hop.agent_id}'"
            )

        return True, "Delegation chain authority validated"

    async def _validate_origin(self, hop: DelegationHop) -> bool:
        """Check that the origin hop has legitimate authority."""
        if hop.authority_source == "user":
            return True

        if hop.authority_source.startswith("role:"):
            role_id = hop.authority_source.split(":", 1)[1]
            db = db_module.get_database()
            role_doc = await db[db_module.AGENT_ROLES].find_one(
                {"role_id": role_id, "enabled": True}
            )
            return role_doc is not None

        if hop.authority_source.startswith("agent:"):
            # Agent-sourced authority: the delegating agent must exist
            agent_id = hop.authority_source.split(":", 1)[1]
            db = db_module.get_database()
            profile = await db[db_module.AGENT_PROFILES].find_one(
                {"agent_id": agent_id, "enabled": True}
            )
            return profile is not None

        return False

    @staticmethod
    def _tools_subset(child_tools: list[str], parent_tools: list[str]) -> bool:
        """Check that every pattern in child_tools is covered by at least one parent pattern."""
        if not child_tools:
            return True
        if not parent_tools:
            # Parent grants nothing → child can't have grants
            return False

        for child_pattern in child_tools:
            matched = False
            for parent_pattern in parent_tools:
                # Direct match or parent glob covers child
                if child_pattern == parent_pattern or fnmatch.fnmatch(
                    child_pattern, parent_pattern
                ):
                    matched = True
                    break
            if not matched:
                return False
        return True

    @staticmethod
    def _tool_matches_grants(tool_name: str, granted_tools: list[str]) -> bool:
        """Check if a specific tool name matches any of the granted tool patterns."""
        for pattern in granted_tools:
            if fnmatch.fnmatch(tool_name, pattern):
                return True
        return False


# ---------------------------------------------------------------------------
# APEP-057: Chain Depth Limit Enforcement
# ---------------------------------------------------------------------------


class ChainDepthEnforcer:
    """Enforces configurable maximum delegation chain depth."""

    def __init__(self, default_max_depth: int = DEFAULT_MAX_CHAIN_DEPTH):
        self._default_max_depth = default_max_depth

    async def check_depth(
        self,
        hops: list[DelegationHop],
        agent_id: str | None = None,
    ) -> tuple[bool, str]:
        """Check if the delegation chain exceeds the maximum allowed depth.

        Uses the agent's profile max_delegation_depth if available,
        otherwise falls back to the default.

        Returns (is_within_limit, reason).
        """
        max_depth = self._default_max_depth

        if agent_id:
            db = db_module.get_database()
            profile = await db[db_module.AGENT_PROFILES].find_one(
                {"agent_id": agent_id, "enabled": True}
            )
            if profile and "max_delegation_depth" in profile:
                max_depth = profile["max_delegation_depth"]

        depth = len(hops)
        if depth > max_depth:
            return False, (
                f"Delegation chain depth {depth} exceeds maximum {max_depth} "
                f"for agent '{agent_id or 'unknown'}'"
            )

        return True, f"Chain depth {depth} within limit {max_depth}"


# ---------------------------------------------------------------------------
# APEP-058: Implicit Delegation Detection
# ---------------------------------------------------------------------------


class ImplicitDelegationDetector:
    """Detects implicit delegation: when a shared workspace write by one agent
    triggers a downstream agent action without explicit delegation.

    Checks for patterns where:
    1. Agent A writes to a shared resource (workspace, file, queue)
    2. Agent B reads from the same resource and acts on it
    3. No explicit delegation chain links A → B
    """

    # Tool patterns that indicate workspace writes
    WRITE_PATTERNS: list[str] = [
        "*write*", "*create*", "*update*", "*put*", "*post*",
        "*upload*", "*save*", "*modify*", "*append*", "*insert*",
    ]

    # Tool patterns that indicate workspace reads
    READ_PATTERNS: list[str] = [
        "*read*", "*get*", "*fetch*", "*list*", "*download*", "*load*",
    ]

    async def detect(
        self,
        session_id: str,
        agent_id: str,
        tool_name: str,
        delegation_hops: list[DelegationHop],
    ) -> tuple[bool, str]:
        """Detect if this tool call is an implicit delegation.

        Looks for recent writes by other agents in the same session that
        could be triggering this agent's action without explicit delegation.

        Returns (is_implicit, detail).
        """
        if delegation_hops:
            # Explicit delegation chain exists — not implicit
            return False, "Explicit delegation chain present"

        # Check if this is a read/action that might be triggered by another agent's write
        if not self._is_action_tool(tool_name):
            return False, "Tool is not an action that could be implicitly delegated"

        # Look for recent writes by other agents in this session
        db = db_module.get_database()
        recent_writes = await db[db_module.AUDIT_DECISIONS].find(
            {
                "session_id": session_id,
                "agent_id": {"$ne": agent_id},
                "decision": "ALLOW",
            }
        ).sort("timestamp", -1).to_list(length=20)

        for write_record in recent_writes:
            other_tool = write_record.get("tool_name", "")
            if self._is_write_tool(other_tool):
                other_agent = write_record.get("agent_id", "unknown")
                return True, (
                    f"Possible implicit delegation: agent '{other_agent}' wrote via "
                    f"'{other_tool}' before agent '{agent_id}' invoked '{tool_name}' "
                    f"with no explicit delegation chain"
                )

        return False, "No implicit delegation detected"

    @staticmethod
    def _is_write_tool(tool_name: str) -> bool:
        tool_lower = tool_name.lower()
        for pattern in ImplicitDelegationDetector.WRITE_PATTERNS:
            if fnmatch.fnmatch(tool_lower, pattern):
                return True
        return False

    @staticmethod
    def _is_action_tool(tool_name: str) -> bool:
        """Check if a tool name matches action patterns (writes or non-read actions)."""
        tool_lower = tool_name.lower()
        # A tool is an action if it's a write OR not obviously a read-only tool
        for pattern in ImplicitDelegationDetector.WRITE_PATTERNS:
            if fnmatch.fnmatch(tool_lower, pattern):
                return True
        # Also flag tools that don't match read patterns (unknown tools could be actions)
        for pattern in ImplicitDelegationDetector.READ_PATTERNS:
            if fnmatch.fnmatch(tool_lower, pattern):
                return False
        # Unknown tools are treated as potential actions
        return True


# ---------------------------------------------------------------------------
# APEP-059: SecurityAlertEmitter
# ---------------------------------------------------------------------------


class SecurityAlertEmitter:
    """Emits SECURITY_ALERT events to MongoDB and logs when delegation
    violations are detected."""

    def __init__(self) -> None:
        self._buffer: list[SecurityAlertEvent] = []

    async def emit(self, alert: SecurityAlertEvent) -> None:
        """Persist a security alert event to MongoDB and log it."""
        logger.warning(
            "SECURITY_ALERT [%s] session=%s agent=%s tool=%s: %s",
            alert.alert_type.value,
            alert.session_id,
            alert.agent_id,
            alert.tool_name,
            alert.detail,
        )
        self._buffer.append(alert)

        db = db_module.get_database()
        try:
            await db[SECURITY_ALERTS].insert_one(alert.model_dump(mode="json"))
        except Exception:
            logger.exception("Failed to persist security alert %s", alert.alert_id)

    async def get_alerts(
        self,
        session_id: str | None = None,
        alert_type: SecurityAlertType | None = None,
        limit: int = 100,
    ) -> list[SecurityAlertEvent]:
        """Query security alerts from MongoDB."""
        db = db_module.get_database()
        query: dict = {}
        if session_id:
            query["session_id"] = session_id
        if alert_type:
            query["alert_type"] = alert_type.value

        cursor = db[SECURITY_ALERTS].find(query).sort("timestamp", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [SecurityAlertEvent(**doc) for doc in docs]

    def clear(self) -> None:
        """Clear the in-memory buffer (for testing)."""
        self._buffer.clear()

    @property
    def buffer(self) -> list[SecurityAlertEvent]:
        return list(self._buffer)


# ---------------------------------------------------------------------------
# APEP-060: ConfusedDeputyDetector (orchestrator)
# ---------------------------------------------------------------------------


class ConfusedDeputyDetector:
    """Orchestrates all delegation chain checks and produces a decision override
    or security alert when violations are found.

    Integrates:
    - DelegationChainWalker (APEP-055)
    - AuthorityValidator (APEP-056)
    - ChainDepthEnforcer (APEP-057)
    - ImplicitDelegationDetector (APEP-058)
    - SecurityAlertEmitter (APEP-059)
    """

    def __init__(
        self,
        max_chain_depth: int = DEFAULT_MAX_CHAIN_DEPTH,
    ) -> None:
        self.walker = DelegationChainWalker()
        self.authority_validator = AuthorityValidator()
        self.depth_enforcer = ChainDepthEnforcer(default_max_depth=max_chain_depth)
        self.implicit_detector = ImplicitDelegationDetector()
        self.alert_emitter = SecurityAlertEmitter()

    async def evaluate(
        self,
        session_id: str,
        agent_id: str,
        tool_name: str,
        delegation_hops: list[DelegationHop],
    ) -> tuple[bool, str]:
        """Run all confused-deputy checks.

        Returns (is_allowed, reason). If is_allowed is False, the tool call
        should be denied and the reason explains the violation.
        """
        chain_agents = self.walker.get_agent_ids(delegation_hops)

        # 1. Chain depth check (APEP-057)
        depth_ok, depth_reason = await self.depth_enforcer.check_depth(
            delegation_hops, agent_id
        )
        if not depth_ok:
            await self.alert_emitter.emit(
                SecurityAlertEvent(
                    alert_type=SecurityAlertType.CHAIN_DEPTH_EXCEEDED,
                    session_id=session_id,
                    agent_id=agent_id,
                    delegation_chain=chain_agents,
                    tool_name=tool_name,
                    detail=depth_reason,
                    severity="HIGH",
                )
            )
            return False, depth_reason

        # 2. Authority validation (APEP-056)
        auth_ok, auth_reason = await self.authority_validator.validate_chain(
            delegation_hops, tool_name
        )
        if not auth_ok:
            alert_type = SecurityAlertType.AUTHORITY_VIOLATION
            # Detect privilege escalation: child claims more tools than parent
            if "exceed parent" in auth_reason:
                alert_type = SecurityAlertType.PRIVILEGE_ESCALATION

            await self.alert_emitter.emit(
                SecurityAlertEvent(
                    alert_type=alert_type,
                    session_id=session_id,
                    agent_id=agent_id,
                    delegation_chain=chain_agents,
                    tool_name=tool_name,
                    detail=auth_reason,
                    severity="CRITICAL" if alert_type == SecurityAlertType.PRIVILEGE_ESCALATION else "HIGH",
                )
            )
            return False, auth_reason

        # 3. Implicit delegation detection (APEP-058)
        is_implicit, implicit_detail = await self.implicit_detector.detect(
            session_id, agent_id, tool_name, delegation_hops
        )
        if is_implicit:
            await self.alert_emitter.emit(
                SecurityAlertEvent(
                    alert_type=SecurityAlertType.IMPLICIT_DELEGATION,
                    session_id=session_id,
                    agent_id=agent_id,
                    delegation_chain=chain_agents,
                    tool_name=tool_name,
                    detail=implicit_detail,
                    severity="MEDIUM",
                )
            )
            # Implicit delegation is a warning — escalate rather than deny
            return False, f"ESCALATE: {implicit_detail}"

        return True, "Delegation chain validated"


# Module-level singletons
delegation_chain_walker = DelegationChainWalker()
authority_validator = AuthorityValidator()
chain_depth_enforcer = ChainDepthEnforcer()
implicit_delegation_detector = ImplicitDelegationDetector()
security_alert_emitter = SecurityAlertEmitter()
confused_deputy_detector = ConfusedDeputyDetector()
