"""ExecutionTokenManager — single-use cryptographic tokens per ALLOW decision.

Sprint 29 — APEP-231: Generates single-use cryptographic tokens tied to a
specific authorization decision. Each token can only be consumed once,
preventing replay attacks and ensuring that tool execution can only proceed
with a valid, unconsumed authorization token.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Token format version
_TOKEN_VERSION = "v1"

# Default TTL: 5 minutes
_DEFAULT_TTL_SECONDS = 300


@dataclass
class TokenPayload:
    """Decoded payload from a validated execution token."""

    decision_id: str
    session_id: str
    agent_id: str
    tool_name: str
    issued_at: float
    expires_at: float


class ExecutionTokenManager:
    """Generates and validates single-use cryptographic execution tokens.

    Each ALLOW decision produces a token that must be presented before
    tool execution. Tokens are:
    - Cryptographically signed with HMAC-SHA256
    - Single-use (invalidated on first consumption)
    - Time-limited (configurable TTL)
    - Bound to a specific decision_id, session_id, agent_id, and tool_name
    """

    def __init__(
        self,
        secret_key: bytes | None = None,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._secret_key = secret_key or os.urandom(32)
        self._ttl_seconds = ttl_seconds
        self._consumed: dict[str, float] = {}  # token_hash -> consumed_at
        self._lock = asyncio.Lock()

    def generate(
        self,
        *,
        decision_id: str,
        session_id: str,
        agent_id: str,
        tool_name: str,
    ) -> str:
        """Generate a single-use execution token for an ALLOW decision.

        Args:
            decision_id: The unique ID of the authorization decision.
            session_id: The session that produced the decision.
            agent_id: The agent authorized to execute.
            tool_name: The tool authorized for execution.

        Returns:
            A URL-safe token string.
        """
        issued_at = time.time()
        expires_at = issued_at + self._ttl_seconds

        # Build the payload to sign
        payload_str = (
            f"{_TOKEN_VERSION}|{decision_id}|{session_id}|{agent_id}|"
            f"{tool_name}|{issued_at}|{expires_at}"
        )

        # Generate a random nonce for uniqueness
        nonce = os.urandom(16).hex()
        payload_with_nonce = f"{payload_str}|{nonce}"

        # HMAC-SHA256 signature
        signature = hmac.new(
            self._secret_key,
            payload_with_nonce.encode(),
            hashlib.sha256,
        ).hexdigest()

        return f"{payload_with_nonce}|{signature}"

    async def validate_and_consume(self, token: str) -> TokenPayload | None:
        """Validate an execution token and consume it (single-use).

        Args:
            token: The execution token to validate.

        Returns:
            TokenPayload if valid and unconsumed, None otherwise.
        """
        parts = token.split("|")
        if len(parts) != 9:
            logger.warning("Invalid token format: wrong number of parts")
            return None

        version = parts[0]
        if version != _TOKEN_VERSION:
            logger.warning("Invalid token version: %s", version)
            return None

        decision_id = parts[1]
        session_id = parts[2]
        agent_id = parts[3]
        tool_name = parts[4]

        try:
            issued_at = float(parts[5])
            expires_at = float(parts[6])
        except ValueError:
            logger.warning("Invalid token timestamps")
            return None

        nonce = parts[7]
        provided_signature = parts[8]

        # Check expiry
        if time.time() > expires_at:
            logger.warning("Execution token expired for decision %s", decision_id)
            return None

        # Recompute and verify HMAC signature
        payload_with_nonce = (
            f"{version}|{decision_id}|{session_id}|{agent_id}|"
            f"{tool_name}|{issued_at}|{expires_at}|{nonce}"
        )
        expected_signature = hmac.new(
            self._secret_key,
            payload_with_nonce.encode(),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(provided_signature, expected_signature):
            logger.warning("Invalid token signature for decision %s", decision_id)
            return None

        # Check single-use: hash the token for storage
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        async with self._lock:
            if token_hash in self._consumed:
                logger.warning(
                    "Execution token already consumed for decision %s", decision_id
                )
                return None

            # Mark as consumed
            self._consumed[token_hash] = time.time()

            # Prune expired consumed tokens to prevent unbounded growth
            self._prune_expired()

        return TokenPayload(
            decision_id=decision_id,
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def _prune_expired(self) -> None:
        """Remove consumed token records older than 2x TTL."""
        cutoff = time.time() - (self._ttl_seconds * 2)
        expired_keys = [k for k, v in self._consumed.items() if v < cutoff]
        for key in expired_keys:
            del self._consumed[key]

    def reset(self) -> None:
        """Reset internal state (for testing)."""
        self._consumed.clear()


# Module-level singleton
execution_token_manager = ExecutionTokenManager()
