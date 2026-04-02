"""API key authentication and mTLS certificate validation middleware."""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from app.core.config import settings
from app.db import mongodb as db_module

# Collection for storing API keys
API_KEYS = "api_keys"

# Paths that do not require authentication
PUBLIC_PATHS = {"/health", "/ready", "/metrics", "/docs", "/openapi.json", "/redoc"}


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

        # Look up key in MongoDB
        db = db_module.get_database()
        key_record = await db[API_KEYS].find_one({"key": api_key, "enabled": True})

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
