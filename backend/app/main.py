"""AgentPEP FastAPI application entry point.

Sprint 23: starts async audit log writer (APEP-184) and optional Redis
cache (APEP-181) during application lifespan.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from app.api.v1.agents import router as agents_router
from app.api.v1.audit import router as audit_router
from app.api.v1.console_auth import router as console_auth_router
from app.api.v1.console_dashboard import router as console_dashboard_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.escalation import router as escalation_router
from app.api.v1.compliance import router as compliance_router
from app.api.v1.audit import router as audit_router
from app.api.v1.health import router as health_router
from app.api.v1.intercept import router as intercept_router
from app.api.v1.mcp import router as mcp_router
from app.api.v1.simulate import router as simulate_router
from app.api.v1.taint import router as taint_router
from app.core.config import settings
from app.core.observability import get_metrics_app, setup_tracing
from app.db.mongodb import close_client, init_collections
from app.middleware.auth import APIKeyAuthMiddleware, MTLSMiddleware
from app.services.audit_logger import audit_logger
from app.services.kafka_producer import kafka_producer
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

    # Initialize audit logger (resume hash chain from DB)
    await audit_logger.initialize()

    # Start Kafka producer if enabled
    await kafka_producer.start()

    # Wire up escalation WebSocket broadcast callback (Sprint 9)
    from app.services.escalation_manager import escalation_manager
    from app.services.escalation_ws import escalation_ws_manager
    from app.models.policy import EscalationState, NotificationConfig

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
    # Start report scheduler if enabled (APEP-177)
    if settings.report_scheduler_enabled:
        from app.services.compliance.report_scheduler import report_scheduler

        await report_scheduler.start()
    # Sprint 23 (APEP-181): Initialise Redis policy cache
    from app.services.rule_cache import rule_cache

    await rule_cache.init_redis()

    # Sprint 23 (APEP-184): Start async audit log writer
    from app.services.policy_evaluator import audit_log_writer

    audit_log_writer.start()

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
    # Shutdown report scheduler
    if settings.report_scheduler_enabled:
        from app.services.compliance.report_scheduler import report_scheduler

        await report_scheduler.stop()

    # Shutdown gRPC server
    if _grpc_server is not None:
        await _grpc_server.stop(grace=5)

    # Sprint 23: Drain audit log writer
    audit_log_writer.stop()
    await audit_log_writer.flush_pending()

    # Sprint 23: Close Redis
    await rule_cache.close_redis()

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
app.include_router(agents_router)
app.include_router(health_router)
app.include_router(intercept_router)
app.include_router(simulate_router)
app.include_router(taint_router)
app.include_router(audit_router)
<<<<<<< HEAD
app.include_router(escalation_router)
app.include_router(mcp_router)
app.include_router(console_auth_router)
app.include_router(console_dashboard_router)
app.include_router(dashboard_router)
app.include_router(compliance_router)
=======
>>>>>>> origin/claude/implement-sprint-24-SmFQK

# Observability
if settings.metrics_enabled:
    metrics_app = get_metrics_app()
    app.mount("/metrics", metrics_app)

setup_tracing(app)
