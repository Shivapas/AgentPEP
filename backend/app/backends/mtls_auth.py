"""MTLSAuthProvider — mTLS certificate authentication.

Sprint 29 — APEP-228: Refactors the existing mTLS middleware as an
AuthProvider implementation.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request

from app.backends.auth import AuthProvider, AuthResult, TokenInfo

logger = logging.getLogger(__name__)


class MTLSAuthProvider(AuthProvider):
    """Authenticates requests via client TLS certificates.

    Expects the reverse proxy (nginx/envoy) to pass client cert info
    via X-Client-Cert-DN and X-Client-Cert-Verified headers.
    """

    def __init__(self, role_mapping: dict[str, list[str]] | None = None) -> None:
        self._role_mapping: dict[str, list[str]] = role_mapping or {}

    async def authenticate(self, request: Request) -> AuthResult:
        cert_verified = request.headers.get("X-Client-Cert-Verified")
        cert_dn = request.headers.get("X-Client-Cert-DN", "")

        if cert_verified != "SUCCESS":
            return AuthResult(
                authenticated=False,
                error_code="MTLS_REQUIRED",
                error_message="Valid client certificate required",
            )

        roles = self._role_mapping.get(cert_dn, [])

        return AuthResult(
            authenticated=True,
            identity=cert_dn,
            roles=roles,
            metadata={"client_cert_dn": cert_dn},
        )

    async def validate_token(self, token: str) -> TokenInfo | None:
        # mTLS does not use bearer tokens; return None
        return None

    async def get_roles(self, identity: str) -> list[str]:
        return self._role_mapping.get(identity, [])
