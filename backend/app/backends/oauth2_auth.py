"""OAuth2OIDCAuthProvider — OAuth2/OIDC authentication via JWT validation.

Sprint 31 — APEP-241: Implements JWT validation with JWKS discovery,
role mapping from configurable claim paths, and automatic key rotation.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
from fastapi import Request
from jose import JWTError, jwt

from app.backends.auth import AuthProvider, AuthResult, TokenInfo

logger = logging.getLogger(__name__)


def _extract_claim(claims: dict[str, Any], path: str) -> Any:
    """Extract a value from nested claims using dot-separated path.

    Example: ``_extract_claim({"realm_access": {"roles": ["admin"]}}, "realm_access.roles")``
    returns ``["admin"]``.
    """
    parts = path.split(".")
    current: Any = claims
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


class OAuth2OIDCAuthProvider(AuthProvider):
    """Authenticates requests via OAuth2/OIDC JWT Bearer tokens.

    Features:
    - JWKS endpoint discovery from .well-known/openid-configuration
    - JWT signature validation (RS256, ES256)
    - Issuer and audience validation
    - Role extraction from configurable claim paths
    - Token expiry enforcement
    - Cached JWKS with automatic refresh on key-ID miss
    """

    def __init__(
        self,
        issuer_url: str,
        audience: str,
        role_claim_path: str = "realm_access.roles",
        allowed_algorithms: list[str] | None = None,
        jwks_refresh_interval_s: int = 3600,
        tenant_claim: str = "tenant_id",
    ) -> None:
        self._issuer_url = issuer_url.rstrip("/")
        self._audience = audience
        self._role_claim_path = role_claim_path
        self._allowed_algorithms = allowed_algorithms or ["RS256", "ES256"]
        self._jwks_refresh_interval_s = jwks_refresh_interval_s
        self._tenant_claim = tenant_claim

        # Cached JWKS state
        self._jwks: dict[str, Any] = {}
        self._jwks_keys_by_kid: dict[str, dict[str, Any]] = {}
        self._jwks_last_fetched: float = 0.0
        self._jwks_uri: str = ""

    # --- JWKS Discovery ---

    async def _discover_jwks_uri(self) -> str:
        """Fetch JWKS URI from the OpenID Connect discovery endpoint."""
        if self._jwks_uri:
            return self._jwks_uri

        discovery_url = f"{self._issuer_url}/.well-known/openid-configuration"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(discovery_url)
            resp.raise_for_status()
            config = resp.json()
            self._jwks_uri = config.get("jwks_uri", "")
            if not self._jwks_uri:
                raise ValueError(f"No jwks_uri in discovery document at {discovery_url}")
            return self._jwks_uri

    async def _fetch_jwks(self) -> None:
        """Fetch the JWKS key set from the IdP."""
        jwks_uri = await self._discover_jwks_uri()
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(jwks_uri)
            resp.raise_for_status()
            self._jwks = resp.json()
            self._jwks_keys_by_kid = {
                key["kid"]: key for key in self._jwks.get("keys", []) if "kid" in key
            }
            self._jwks_last_fetched = time.monotonic()
            logger.info(
                "JWKS fetched: %d keys from %s",
                len(self._jwks_keys_by_kid),
                jwks_uri,
            )

    async def _get_signing_key(self, kid: str) -> dict[str, Any]:
        """Get a signing key by kid, refreshing JWKS if needed."""
        now = time.monotonic()
        cache_stale = (now - self._jwks_last_fetched) > self._jwks_refresh_interval_s

        # Try cached first
        if kid in self._jwks_keys_by_kid and not cache_stale:
            return self._jwks_keys_by_kid[kid]

        # Refresh on cache miss or staleness
        await self._fetch_jwks()

        if kid not in self._jwks_keys_by_kid:
            raise ValueError(f"Key ID '{kid}' not found in JWKS after refresh")

        return self._jwks_keys_by_kid[kid]

    # --- Token Validation ---

    async def _decode_token(self, token: str) -> dict[str, Any]:
        """Decode and validate a JWT token against the JWKS."""
        # Extract the kid from the unverified header
        try:
            unverified_header = jwt.get_unverified_header(token)
        except JWTError as exc:
            raise ValueError(f"Invalid JWT header: {exc}") from exc

        kid = unverified_header.get("kid")
        if not kid:
            raise ValueError("JWT header missing 'kid' claim")

        alg = unverified_header.get("alg", "")
        if alg not in self._allowed_algorithms:
            raise ValueError(
                f"JWT algorithm '{alg}' not in allowed: {self._allowed_algorithms}"
            )

        # Get the signing key
        key_data = await self._get_signing_key(kid)

        # Decode and validate
        claims = jwt.decode(
            token,
            key_data,
            algorithms=self._allowed_algorithms,
            audience=self._audience,
            issuer=self._issuer_url,
            options={
                "verify_aud": bool(self._audience),
                "verify_iss": bool(self._issuer_url),
                "verify_exp": True,
                "verify_iat": True,
            },
        )
        return claims

    # --- AuthProvider interface ---

    async def authenticate(self, request: Request) -> AuthResult:
        """Authenticate via Bearer token in Authorization header."""
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return AuthResult(
                authenticated=False,
                error_code="MISSING_BEARER_TOKEN",
                error_message="Authorization header with Bearer token is required",
            )

        token = auth_header[len("Bearer "):]

        try:
            claims = await self._decode_token(token)
        except ValueError as exc:
            return AuthResult(
                authenticated=False,
                error_code="INVALID_TOKEN",
                error_message=str(exc),
            )
        except JWTError as exc:
            return AuthResult(
                authenticated=False,
                error_code="JWT_VALIDATION_FAILED",
                error_message=f"JWT validation failed: {exc}",
            )
        except httpx.HTTPError as exc:
            return AuthResult(
                authenticated=False,
                error_code="JWKS_FETCH_FAILED",
                error_message=f"Failed to fetch JWKS: {exc}",
            )

        # Extract identity (subject)
        subject = claims.get("sub", "")
        if not subject:
            return AuthResult(
                authenticated=False,
                error_code="MISSING_SUBJECT",
                error_message="JWT missing 'sub' claim",
            )

        # Extract roles from configurable claim path
        roles = _extract_claim(claims, self._role_claim_path)
        if roles is None:
            roles = []
        elif isinstance(roles, str):
            roles = [roles]
        elif not isinstance(roles, list):
            roles = []

        # Extract tenant
        tenant_id = claims.get(self._tenant_claim, "default")

        return AuthResult(
            authenticated=True,
            identity=subject,
            tenant_id=str(tenant_id),
            roles=roles,
            metadata={
                "auth_method": "oauth2_oidc",
                "issuer": claims.get("iss", ""),
                "token_exp": claims.get("exp"),
                "claims": {
                    k: v
                    for k, v in claims.items()
                    if k in ("sub", "iss", "aud", "exp", "iat", "jti", "email", "name")
                },
            },
        )

    async def validate_token(self, token: str) -> TokenInfo | None:
        """Validate a bearer token and return extracted info."""
        try:
            claims = await self._decode_token(token)
        except (ValueError, JWTError, httpx.HTTPError):
            return None

        subject = claims.get("sub", "")
        roles = _extract_claim(claims, self._role_claim_path)
        if roles is None:
            roles = []
        elif isinstance(roles, str):
            roles = [roles]
        elif not isinstance(roles, list):
            roles = []

        return TokenInfo(
            subject=subject,
            tenant_id=claims.get(self._tenant_claim, "default"),
            roles=roles,
            expires_at=claims.get("exp"),
            metadata={"issuer": claims.get("iss", "")},
        )

    async def get_roles(self, identity: str) -> list[str]:
        """Roles are extracted at authentication time; cannot look up by identity alone."""
        return []
