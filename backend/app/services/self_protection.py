"""Agent-Initiated Policy Modification Self-Protection — Sprint 55 (APEP-440).

Implements guards that prevent agents from modifying security policies
through their own API keys.  Two guard layers:

  1. **CLI Guard (TTY Check):** Policy modification commands must
     originate from an interactive TTY terminal, blocking automated
     agent-initiated modifications.

  2. **Hook Guard:** Blocks ToolTrust "allow" commands and AgentPEP
     policy modification operations when the caller is identified as
     an agent (via API key type or caller metadata).

Self-protection events are audited and can trigger escalations.
The target is 0 agent-initiated policy modifications succeed when
using an agent API key (APEP-442 adversarial tests).
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime

from app.db import mongodb as db_module
from app.models.camel_seq import (
    SelfProtectionAction,
    SelfProtectionCheckRequest,
    SelfProtectionCheckResponse,
    SelfProtectionEvent,
)

logger = logging.getLogger(__name__)

# MongoDB collection for self-protection events
SELF_PROTECTION_EVENTS_COLLECTION = "self_protection_events"

# Operations that require human-only access
_PROTECTED_OPERATIONS: set[str] = {
    "policy.create",
    "policy.update",
    "policy.delete",
    "rule.create",
    "rule.update",
    "rule.delete",
    "role.create",
    "role.update",
    "role.delete",
    "config.modify",
    "config.security.modify",
    "allowlist.modify",
    "self_protection.disable",
    "kill_switch.deactivate",
}

# ToolTrust allow commands that agents must not execute
_BLOCKED_COMMAND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"tooltrust\s+allow", re.IGNORECASE),
    re.compile(r"agentpep\s+policy\s+(create|update|delete|modify)", re.IGNORECASE),
    re.compile(r"agentpep\s+rule\s+(create|update|delete)", re.IGNORECASE),
    re.compile(r"agentpep\s+config\s+set", re.IGNORECASE),
    re.compile(r"agentpep\s+allowlist\s+(add|remove|clear)", re.IGNORECASE),
]


class SelfProtectionGuard:
    """Guards against agent-initiated policy modification (APEP-440).

    Evaluates whether a caller (human or agent) is allowed to perform
    a given operation.  Agents are blocked from policy-modifying operations.
    """

    def check(
        self,
        request: SelfProtectionCheckRequest,
    ) -> SelfProtectionCheckResponse:
        """Check whether the operation is allowed by self-protection guards.

        Args:
            request: The check request with caller info and operation.

        Returns:
            SelfProtectionCheckResponse with allow/block decision.
        """
        # Guard 1: CLI TTY Check
        # If the operation is policy-modifying and not from a TTY, block
        if (
            request.operation in _PROTECTED_OPERATIONS
            and request.caller_type == "agent"
        ):
            return SelfProtectionCheckResponse(
                allowed=False,
                action=SelfProtectionAction.BLOCK,
                reason=(
                    f"Agent-initiated policy modification blocked: "
                    f"operation '{request.operation}' requires human authorization"
                ),
                guard_name="agent_policy_guard",
            )

        # Guard 2: API key type check
        # Agent API keys cannot modify policies
        if (
            request.caller_type == "api_key"
            and request.operation in _PROTECTED_OPERATIONS
            and not request.is_tty
        ):
            return SelfProtectionCheckResponse(
                allowed=False,
                action=SelfProtectionAction.BLOCK,
                reason=(
                    f"Non-TTY API key cannot modify policies: "
                    f"operation '{request.operation}' blocked"
                ),
                guard_name="tty_policy_guard",
            )

        # Guard 3: Human callers can modify policies from TTY
        if request.caller_type == "human" and request.is_tty:
            return SelfProtectionCheckResponse(
                allowed=True,
                action=SelfProtectionAction.AUDIT,
                reason="Human-initiated policy modification from TTY allowed",
                guard_name="human_tty_guard",
            )

        # Guard 4: Human callers from non-TTY get a warning
        if (
            request.caller_type == "human"
            and not request.is_tty
            and request.operation in _PROTECTED_OPERATIONS
        ):
            return SelfProtectionCheckResponse(
                allowed=True,
                action=SelfProtectionAction.WARN,
                reason=(
                    "Policy modification from non-TTY session: "
                    "operation allowed but audited with warning"
                ),
                guard_name="human_non_tty_guard",
            )

        # Default: allow non-protected operations
        return SelfProtectionCheckResponse(
            allowed=True,
            action=SelfProtectionAction.AUDIT,
            reason="Operation not subject to self-protection",
            guard_name="default_allow",
        )

    def check_command(self, command: str, caller_type: str) -> SelfProtectionCheckResponse:
        """Check whether a CLI/hook command is blocked by self-protection.

        Args:
            command: The command string being executed.
            caller_type: Type of caller ('human', 'agent').

        Returns:
            SelfProtectionCheckResponse.
        """
        if caller_type == "agent":
            for pattern in _BLOCKED_COMMAND_PATTERNS:
                if pattern.search(command):
                    return SelfProtectionCheckResponse(
                        allowed=False,
                        action=SelfProtectionAction.BLOCK,
                        reason=(
                            f"Agent-initiated command blocked by hook guard: "
                            f"'{command}' matches blocked pattern"
                        ),
                        guard_name="hook_command_guard",
                    )

        return SelfProtectionCheckResponse(
            allowed=True,
            action=SelfProtectionAction.AUDIT,
            reason="Command not blocked by self-protection",
            guard_name="hook_default_allow",
        )

    async def audit_event(
        self,
        request: SelfProtectionCheckRequest,
        response: SelfProtectionCheckResponse,
    ) -> SelfProtectionEvent:
        """Record a self-protection audit event."""
        event = SelfProtectionEvent(
            caller_type=request.caller_type,
            operation=request.operation,
            target_resource=request.target_resource,
            action_taken=response.action,
            guard_name=response.guard_name,
            detail=response.reason,
        )

        try:
            db = db_module.get_database()
            await db[SELF_PROTECTION_EVENTS_COLLECTION].insert_one(
                event.model_dump(mode="json")
            )
        except Exception:
            logger.warning(
                "Failed to record self-protection event",
                exc_info=True,
            )

        if not response.allowed:
            logger.warning(
                "Self-protection guard blocked: caller=%s op=%s guard=%s",
                request.caller_type,
                request.operation,
                response.guard_name,
            )

        return event

    async def get_events(
        self,
        limit: int = 50,
        blocked_only: bool = False,
    ) -> list[SelfProtectionEvent]:
        """Retrieve self-protection audit events."""
        try:
            db = db_module.get_database()
            filt: dict = {}
            if blocked_only:
                filt["action_taken"] = SelfProtectionAction.BLOCK.value
            cursor = (
                db[SELF_PROTECTION_EVENTS_COLLECTION]
                .find(filt, {"_id": 0})
                .sort("timestamp", -1)
                .limit(limit)
            )
            events: list[SelfProtectionEvent] = []
            async for doc in cursor:
                events.append(SelfProtectionEvent.model_validate(doc))
            return events
        except Exception:
            logger.warning(
                "Failed to fetch self-protection events",
                exc_info=True,
            )
            return []


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

self_protection_guard = SelfProtectionGuard()
