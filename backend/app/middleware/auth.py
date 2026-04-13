"""API key authentication, mTLS certificate validation, and auth registry middleware.

Sprint 31 — APEP-243: Added AuthRegistryMiddleware that delegates authentication
to the pluggable auth provider registry with per-tenant fallback chains.
"""

import hashlib
import secrets

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from app.core.config import settings
from app.db import mongodb as db_module

# Collection for storing API keys
API_KEYS = "api_keys"

# Paths that do not require authentication
PUBLIC_PATHS = {
    "/health", "/ready", "/metrics", "/docs", "/openapi.json", "/redoc",
    "/v1/console/login", "/v1/console/refresh", "/v1/console/seed",
}


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Validates X-API-Key header and attaches tenant context to request state.

    API key records in MongoDB:
    {
        "key": "apk_...",
        "tenant_id": "tenant-abc",
        "name": "My Integration",
        "enabled": true
    }
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if not settings.auth_enabled:
            request.state.tenant_id = "default"
            return await call_next(request)

        # Skip auth for public endpoints
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        api_key = request.headers.get("X-API-Key")
        if not api_key:
            return JSONResponse(
                status_code=401,
                content={
                    "error": {
                        "code": "MISSING_API_KEY",
                        "message": "X-API-Key header is required",
                    }
                },
            )

        # Look up key by hash to avoid storing/comparing plaintext keys
        db = db_module.get_database()
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        key_record = await db[API_KEYS].find_one({"key_hash": key_hash, "enabled": True})

        # Fall back to plaintext lookup for backward compatibility during migration
        if key_record is None:
            key_record = await db[API_KEYS].find_one({"key": api_key, "enabled": True})
            if key_record is not None:
                # Use constant-time comparison for plaintext keys
                stored_key = key_record.get("key", "")
                if not secrets.compare_digest(stored_key, api_key):
                    key_record = None

        if key_record is None:
            return JSONResponse(
                status_code=401,
                content={
                    "error": {
                        "code": "INVALID_API_KEY",
                        "message": "Invalid or disabled API key",
                    }
                },
            )

        # Attach tenant context to request state for downstream handlers
        request.state.tenant_id = key_record.get("tenant_id", "default")
        request.state.api_key_name = key_record.get("name", "")

        return await call_next(request)


class MTLSMiddleware(BaseHTTPMiddleware):
    """Validates client TLS certificates when mTLS is enabled.

    Expects the reverse proxy (nginx/envoy) to pass client cert info
    via the X-Client-Cert-DN and X-Client-Cert-Verified headers.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if not settings.mtls_enabled:
            return await call_next(request)

        # Skip mTLS for public endpoints
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        cert_verified = request.headers.get("X-Client-Cert-Verified")
        cert_dn = request.headers.get("X-Client-Cert-DN")

        if cert_verified != "SUCCESS":
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "code": "MTLS_REQUIRED",
                        "message": "Valid client certificate required",
                    }
                },
            )

        # Attach client identity to request state
        request.state.client_cert_dn = cert_dn or ""

        return await call_next(request)


class AuthRegistryMiddleware(BaseHTTPMiddleware):
    """Delegates authentication to the pluggable auth provider registry.

    Sprint 31 — APEP-243: When the auth registry has providers configured,
    this middleware tries the tenant's provider chain.  On success it
    attaches tenant context and roles to ``request.state``.  Falls back
    gracefully when the registry is empty (no-op).
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        from app.backends.auth_registry import auth_registry

        # Skip if no providers are registered (legacy API-key/mTLS middleware handles auth)
        if not auth_registry.list_providers():
            return await call_next(request)

        # Skip auth for public endpoints
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        result = await auth_registry.authenticate(request)

        if not result.authenticated:
            return JSONResponse(
                status_code=401,
                content={
                    "error": {
                        "code": result.error_code or "AUTH_FAILED",
                        "message": result.error_message or "Authentication failed",
                    }
                },
            )

        # Attach auth context to request state
        request.state.tenant_id = result.tenant_id
        request.state.auth_identity = result.identity
        request.state.auth_roles = result.roles
        request.state.auth_provider_metadata = result.metadata

        return await call_next(request)
