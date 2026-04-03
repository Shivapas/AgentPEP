"""AgentPEP FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from app.api.v1.audit import router as audit_router
from app.api.v1.escalation import router as escalation_router
from app.api.v1.health import router as health_router
from app.api.v1.intercept import router as intercept_router
from app.api.v1.taint import router as taint_router
from app.core.config import settings
from app.core.observability import get_metrics_app, setup_tracing
from app.db.mongodb import close_client, init_collections
from app.middleware.auth import APIKeyAuthMiddleware, MTLSMiddleware
from app.services.audit_logger import audit_logger
from app.services.kafka_producer import kafka_producer

logger = logging.getLogger(__name__)

_grpc_server = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle."""
    global _grpc_server

    await init_collections()

    # Initialize audit logger (resume hash chain from DB)
    await audit_logger.initialize()

    # Start Kafka producer if enabled
    await kafka_producer.start()

    # Wire up escalation WebSocket broadcast callback (Sprint 9)
    from app.services.escalation_manager import escalation_manager
    from app.services.escalation_ws import escalation_ws_manager
    from app.models.policy import NotificationConfig

    escalation_manager.set_websocket_callback(escalation_ws_manager.broadcast_ticket)

    # Configure escalation notifications from env
    if settings.escalation_email_webhook_url or settings.escalation_slack_webhook_url:
        escalation_manager.set_notification_config(
            NotificationConfig(
                email_webhook_url=settings.escalation_email_webhook_url or None,
                slack_webhook_url=settings.escalation_slack_webhook_url or None,
                slack_channel=settings.escalation_slack_channel or None,
            )
        )

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

    # Shutdown Kafka producer
    await kafka_producer.stop()

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

# Middleware (order matters: mTLS first, then API key)
app.add_middleware(APIKeyAuthMiddleware)
app.add_middleware(MTLSMiddleware)

# Routers
app.include_router(health_router)
app.include_router(intercept_router)
app.include_router(taint_router)
app.include_router(audit_router)
app.include_router(escalation_router)

# Observability
if settings.metrics_enabled:
    metrics_app = get_metrics_app()
    app.mount("/metrics", metrics_app)

setup_tracing(app)
