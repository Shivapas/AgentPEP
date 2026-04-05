"""OWASP Top 10 security middleware and rate limiting — APEP-193, APEP-195.

Provides:
- SecurityHeadersMiddleware: Sets OWASP-recommended HTTP security headers
  (XSS protection, CSRF via SameSite, content-type sniffing, clickjacking,
  CSP, HSTS, referrer policy).
- RateLimitMiddleware: Per-IP sliding window rate limiting for API endpoints.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
import threading
from collections import defaultdict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# APEP-193: OWASP Top 10 Security Headers
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds OWASP-recommended security headers to every response.

    Mitigations:
    - XSS: Content-Security-Policy, X-Content-Type-Options, X-XSS-Protection
    - Clickjacking: X-Frame-Options
    - CSRF: SameSite cookie attribute enforcement
    - Transport: Strict-Transport-Security (HSTS)
    - Information leakage: Referrer-Policy, Permissions-Policy
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)

        # XSS mitigations
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        # Clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Transport security
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        # Information leakage
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # Remove server identification header
        if "Server" in response.headers:
            del response.headers["Server"]

        # CSRF: Set CSRF token cookie for browser-based console.
        # Only set the cookie if not already present to prevent an attacker
        # from forcing a fresh token on every GET request (CSRF bypass vector).
        if request.url.path.startswith("/v1/") and request.method in ("GET", "HEAD"):
            existing_csrf = request.cookies.get("agentpep_csrf")
            if not existing_csrf:
                csrf_token = secrets.token_hex(32)
                response.set_cookie(
                    key="agentpep_csrf",
                    value=csrf_token,
                    httponly=False,  # JS needs to read it
                    samesite="strict",
                    secure=True,
                    max_age=3600,
                )

        return response


# ---------------------------------------------------------------------------
# APEP-193: CSRF validation for state-changing requests
# ---------------------------------------------------------------------------


class CSRFMiddleware(BaseHTTPMiddleware):
    """Validates CSRF token on state-changing requests from the Policy Console.

    The token must be sent as X-CSRF-Token header and must match the
    agentpep_csrf cookie.  API-key-authenticated requests are exempt
    (machine-to-machine traffic).
    """

    EXEMPT_PATHS = {"/health", "/ready", "/metrics", "/docs", "/openapi.json", "/redoc"}
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip for safe methods
        if request.method in self.SAFE_METHODS:
            return await call_next(request)

        # Skip for API-key-authenticated requests (machine traffic)
        if request.headers.get("X-API-Key"):
            return await call_next(request)

        # Skip exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        cookie_token = request.cookies.get("agentpep_csrf")
        header_token = request.headers.get("X-CSRF-Token")

        if cookie_token and header_token and cookie_token == header_token:
            return await call_next(request)

        # If no CSRF cookie is set yet (first request), allow through
        # to let the SecurityHeaders middleware set the initial token
        if not cookie_token:
            return await call_next(request)

        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": "CSRF_VALIDATION_FAILED",
                    "message": "CSRF token missing or invalid",
                }
            },
        )


# ---------------------------------------------------------------------------
# APEP-195: Rate Limiting
# ---------------------------------------------------------------------------


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP sliding window rate limiter for Policy Console API endpoints.

    Default: 100 requests per 60-second window per IP.  Configurable via
    constructor parameters.

    The /v1/intercept endpoint uses a higher limit (1000/60s) since it's
    the hot path for policy evaluation.
    """

    def __init__(
        self,
        app,  # type: ignore[no-untyped-def]
        default_limit: int = 100,
        default_window_s: int = 60,
        intercept_limit: int = 1000,
    ) -> None:
        super().__init__(app)
        self._default_limit = default_limit
        self._default_window_s = default_window_s
        self._intercept_limit = intercept_limit
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    EXEMPT_PATHS = {"/health", "/ready", "/metrics"}

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        path = request.url.path

        # Higher limit for intercept endpoint (hot path)
        limit = self._intercept_limit if path == "/v1/intercept" else self._default_limit
        window = self._default_window_s

        bucket_key = f"{client_ip}:{path}"
        now = time.monotonic()

        with self._lock:
            # Evict expired entries
            timestamps = self._requests[bucket_key]
            cutoff = now - window
            self._requests[bucket_key] = [
                ts for ts in timestamps if ts > cutoff
            ]
            timestamps = self._requests[bucket_key]

            if len(timestamps) >= limit:
                retry_after = int(window - (now - timestamps[0])) + 1
                logger.warning(
                    "Rate limit exceeded for %s on %s (%d/%d in %ds)",
                    client_ip,
                    path,
                    len(timestamps),
                    limit,
                    window,
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": {
                            "code": "RATE_LIMIT_EXCEEDED",
                            "message": f"Rate limit exceeded. Try again in {retry_after}s.",
                        }
                    },
                    headers={"Retry-After": str(retry_after)},
                )

            timestamps.append(now)

        response = await call_next(request)

        # Add rate limit headers
        remaining = limit - len(self._requests.get(bucket_key, []))
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"] = str(int(now + window))

        return response

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract client IP, respecting X-Forwarded-For behind a reverse proxy."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        client = request.client
        return client.host if client else "unknown"
