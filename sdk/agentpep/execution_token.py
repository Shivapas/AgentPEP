"""Execution token validation for the AgentPEP SDK.

Sprint 29 — APEP-232: SDK validates execution tokens before tool execution
to ensure that only authorized tool calls with valid, unconsumed tokens
are executed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ExecutionTokenInfo:
    """Parsed information from an execution token."""

    decision_id: str
    session_id: str
    agent_id: str
    tool_name: str


class ExecutionTokenValidator:
    """Client-side execution token validation.

    Ensures that a tool execution is backed by a valid execution token
    from the server. Tracks consumed tokens to prevent replay.
    """

    def __init__(self) -> None:
        self._consumed: set[str] = set()

    def validate_and_consume(
        self,
        token: str | None,
        *,
        expected_tool_name: str,
        expected_agent_id: str,
    ) -> bool:
        """Validate an execution token and mark it as consumed.

        Args:
            token: The execution token from the PolicyDecisionResponse.
            expected_tool_name: The tool name that should be authorized.
            expected_agent_id: The agent ID that should be authorized.

        Returns:
            True if the token is valid and was successfully consumed.
        """
        if token is None:
            logger.warning("No execution token provided for tool=%s", expected_tool_name)
            return False

        # Check if already consumed
        if token in self._consumed:
            logger.warning(
                "Execution token already consumed for tool=%s agent=%s",
                expected_tool_name,
                expected_agent_id,
            )
            return False

        # Parse and validate token structure
        parts = token.split("|")
        if len(parts) != 9:
            logger.warning("Invalid execution token format")
            return False

        token_agent_id = parts[3]
        token_tool_name = parts[4]

        # Verify token is bound to the correct tool and agent
        if token_tool_name != expected_tool_name:
            logger.warning(
                "Execution token tool mismatch: expected=%s, got=%s",
                expected_tool_name,
                token_tool_name,
            )
            return False

        if token_agent_id != expected_agent_id:
            logger.warning(
                "Execution token agent mismatch: expected=%s, got=%s",
                expected_agent_id,
                token_agent_id,
            )
            return False

        # Mark as consumed
        self._consumed.add(token)

        # Prune to prevent unbounded growth (keep last 10000 tokens)
        if len(self._consumed) > 10000:
            # Remove oldest entries (set doesn't maintain order, so clear half)
            to_remove = list(self._consumed)[:5000]
            for item in to_remove:
                self._consumed.discard(item)

        return True

    def reset(self) -> None:
        """Reset consumed tokens (for testing)."""
        self._consumed.clear()


# Module-level singleton
execution_token_validator = ExecutionTokenValidator()
