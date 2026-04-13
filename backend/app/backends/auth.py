"""AuthProvider ABC — pluggable authentication interface for AgentPEP.

Sprint 29 — APEP-227: Abstract base class for authentication providers with
methods: authenticate, validate_token, get_roles.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from fastapi import Request


@dataclass
class AuthResult:
    """Result of an authentication attempt."""

    authenticated: bool
    identity: str = ""
    tenant_id: str = "default"
    roles: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    error_code: str = ""
    error_message: str = ""


@dataclass
class TokenInfo:
    """Information extracted from a validated token."""

    subject: str
    tenant_id: str = "default"
    roles: list[str] = field(default_factory=list)
    expires_at: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class AuthProvider(ABC):
    """Abstract base class for AgentPEP authentication providers.

    Implementations handle specific authentication mechanisms (API keys,
    mTLS certificates, OAuth2/OIDC, SAML, etc.).
    """

    @abstractmethod
    async def authenticate(self, request: Request) -> AuthResult:
        """Authenticate an incoming request.

        Examines request headers, certificates, or other credentials
        to establish the caller's identity.

        Args:
            request: The incoming FastAPI/Starlette request.

        Returns:
            AuthResult with authentication outcome and identity details.
        """

    @abstractmethod
    async def validate_token(self, token: str) -> TokenInfo | None:
        """Validate a bearer or API token.

        Args:
            token: The token string to validate.

        Returns:
            TokenInfo if the token is valid, None otherwise.
        """

    @abstractmethod
    async def get_roles(self, identity: str) -> list[str]:
        """Retrieve roles for an authenticated identity.

        Args:
            identity: The authenticated identity (e.g. API key name,
                      certificate DN, user ID).

        Returns:
            List of role identifiers associated with the identity.
        """
