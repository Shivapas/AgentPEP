"""AgentPEP FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from app.api.v1.audit import router as audit_router
from app.api.v1.health import router as health_router
from app.api.v1.intercept import router as intercept_router
from app.api.v1.taint import router as taint_router
from app.core.config import settings
from app.core.observability import get_metrics_app, setup_tracing
from app.db.mongodb import close_client, init_collections
from app.middleware.auth import APIKeyAuthMiddleware, MTLSMiddleware
from app.middleware.security import (
    CSRFMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)

logger = logging.getLogger(__name__)

_grpc_server = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle."""
    global _grpc_server

    await init_collections()

    # Start gRPC server if enabled
    if settings.grpc_enabled:
        try:
            from app.grpc_service import start_grpc_server

            _grpc_server = await start_grpc_server(settings.grpc_port)
        except ImportError:
            logger.warning(
                "gRPC dependencies not installed — skipping gRPC server. "
                "Install grpcio and grpcio-reflection to enable."
            )

    yield

    # Shutdown gRPC server
    if _grpc_server is not None:
        await _grpc_server.stop(grace=5)

    await close_client()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Deterministic Authorization Engine for AI Agent Systems",
    lifespan=lifespan,
)

# Middleware (order matters — outermost runs first)
# APEP-195: Rate limiting (outermost — reject early before auth overhead)
app.add_middleware(RateLimitMiddleware, default_limit=100, intercept_limit=1000)
# APEP-193: Security headers (XSS, clickjacking, HSTS, CSP)
app.add_middleware(SecurityHeadersMiddleware)
# APEP-193: CSRF protection for browser-based Policy Console
app.add_middleware(CSRFMiddleware)
# Auth middleware
app.add_middleware(APIKeyAuthMiddleware)
app.add_middleware(MTLSMiddleware)

# Routers
app.include_router(health_router)
app.include_router(intercept_router)
app.include_router(taint_router)
app.include_router(audit_router)

# Observability
if settings.metrics_enabled:
    metrics_app = get_metrics_app()
    app.mount("/metrics", metrics_app)

setup_tracing(app)
