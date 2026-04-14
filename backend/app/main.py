"""AgentPEP FastAPI application entry point.

Sprint 23: starts async audit log writer (APEP-184) and optional Redis
cache (APEP-181) during application lifespan.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.agents import router as agents_router
from app.api.v1.audit import router as audit_router
from app.api.v1.compliance import router as compliance_router
from app.api.v1.console import router as console_router
from app.api.v1.console_auth import router as console_auth_router
from app.api.v1.console_dashboard import router as console_dashboard_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.escalation import router as escalation_router
from app.api.v1.escalation_v1 import router as escalation_v1_router
from app.api.v1.health import router as health_router
from app.api.v1.intercept import router as intercept_router
from app.api.v1.mcp import router as mcp_router
from app.api.v1.policy import router as policy_router
from app.api.v1.simulate import router as simulate_router
from app.api.v1.taint import router as taint_router
from app.api.v1.memory import router as memory_router
from app.api.v1.plans import router as plans_router
from app.api.v1.scope import router as scope_router
from app.api.v1.scope_simulator import router as scope_simulator_router
from app.api.v1.sprint36 import router as sprint36_router
from app.core.config import settings
from app.core.observability import get_metrics_app, setup_tracing
from app.core.structured_logging import configure_logging, get_logger
from app.db.mongodb import close_client, init_collections
from app.middleware.auth import APIKeyAuthMiddleware, AuthRegistryMiddleware, MTLSMiddleware
from app.middleware.security import (
    CSRFMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from app.services.audit_logger import audit_logger
from app.services.kafka_producer import kafka_producer

# Configure structured JSON logging before anything else (APEP-209)
configure_logging()
logger = get_logger(__name__)

_grpc_server = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle."""
    global _grpc_server

    logger.info("app_startup", host=settings.host, port=settings.port)
    await init_collections()

    # Initialize audit logger (resume hash chain from DB)
    await audit_logger.initialize()

    # Start Kafka producer if enabled
    await kafka_producer.start()

    # Wire up escalation WebSocket broadcast callback (Sprint 9)
    from app.models.policy import NotificationConfig
    from app.services.escalation_manager import escalation_manager
    from app.services.escalation_ws import escalation_ws_manager

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

    # Sprint 31 (APEP-244): Initialize Redis storage backend
    if settings.redis_storage_enabled:
        from app.backends.redis_storage import RedisStorageBackend

        _redis_storage = RedisStorageBackend(
            redis_url=settings.redis_storage_url or settings.redis_url,
            key_prefix=settings.redis_storage_key_prefix,
            default_ttl_s=settings.redis_storage_default_ttl_s,
        )
        await _redis_storage.initialize()
        logger.info("redis_storage_initialized")

    # Sprint 31 (APEP-245): Initialize Redis rate limiter
    if settings.redis_rate_limiter_enabled:
        from app.services.redis_rate_limiter import redis_rate_limiter

        await redis_rate_limiter.initialize()
        logger.info("redis_rate_limiter_initialized")

    # Sprint 32 (APEP-250): Initialize CloudWatch audit backend
    _cloudwatch_audit = None
    if settings.cloudwatch_audit_enabled:
        from app.backends.cloudwatch_audit import CloudWatchAuditBackend

        _cloudwatch_audit = CloudWatchAuditBackend()
        await _cloudwatch_audit.initialize()
        logger.info("cloudwatch_audit_initialized")

    # Sprint 32 (APEP-251): Initialize Datadog audit backend
    _datadog_audit = None
    if settings.datadog_audit_enabled:
        from app.backends.datadog_audit import DatadogAuditBackend

        _datadog_audit = DatadogAuditBackend()
        await _datadog_audit.initialize()
        logger.info("datadog_audit_initialized")

    # Sprint 32 (APEP-252): Initialize Loki audit backend
    _loki_audit = None
    if settings.loki_audit_enabled:
        from app.backends.loki_audit import LokiAuditBackend

        _loki_audit = LokiAuditBackend()
        await _loki_audit.initialize()
        logger.info("loki_audit_initialized")

    # Sprint 39 (APEP-309): Initialize per-receipt Ed25519 signing
    if settings.per_receipt_signing_enabled:
        import base64 as _receipt_b64

        per_receipt_key = (
            _receipt_b64.urlsafe_b64decode(settings.per_receipt_signing_key)
            if settings.per_receipt_signing_key
            else None
        )
        audit_logger.configure_receipt_signing(private_key=per_receipt_key)
        logger.info("per_receipt_signing_initialized")

    # Sprint 32 (APEP-256): Initialize receipt signer
    if settings.receipt_signing_enabled:
        import base64

        import app.services.receipt_signer as receipt_signer_module

        key_bytes = (
            base64.urlsafe_b64decode(settings.receipt_signing_key)
            if settings.receipt_signing_key
            else None
        )
        receipt_signer_module.receipt_signer = receipt_signer_module.ReceiptSigner(
            signing_method=settings.receipt_signing_method,
            private_key=key_bytes,
            key_id=settings.receipt_key_id,
        )
        logger.info(
            "receipt_signer_initialized",
            method=receipt_signer_module.receipt_signer.method,
            key_id=settings.receipt_key_id,
        )

    # Sprint 32 (APEP-254/255): Initialize notification channel registry
    from app.backends.notification_registry import notification_registry

    if settings.pagerduty_enabled:
        from app.backends.pagerduty_channel import PagerDutyChannel

        _pd_channel = PagerDutyChannel()
        await _pd_channel.initialize()
        notification_registry.register("pagerduty", _pd_channel)
        logger.info("pagerduty_channel_initialized")

    if settings.teams_enabled:
        from app.backends.teams_channel import MicrosoftTeamsChannel

        _teams_channel = MicrosoftTeamsChannel()
        await _teams_channel.initialize()
        notification_registry.register("teams", _teams_channel)
        logger.info("teams_channel_initialized")

    # Sprint 31 (APEP-243): Initialize auth provider registry
    from app.backends.auth_registry import auth_registry
    from app.backends.apikey_auth import APIKeyAuthProvider
    from app.backends.mongodb_storage import MongoDBStorageBackend

    _storage = MongoDBStorageBackend()
    auth_registry.register("apikey", APIKeyAuthProvider(_storage))

    if settings.mtls_enabled:
        from app.backends.mtls_auth import MTLSAuthProvider

        auth_registry.register("mtls", MTLSAuthProvider())

    if settings.oauth2_enabled:
        from app.backends.oauth2_auth import OAuth2OIDCAuthProvider

        auth_registry.register(
            "oauth2",
            OAuth2OIDCAuthProvider(
                issuer_url=settings.oauth2_issuer_url,
                audience=settings.oauth2_audience,
                role_claim_path=settings.oauth2_role_claim_path,
                allowed_algorithms=settings.oauth2_allowed_algorithms,
                jwks_refresh_interval_s=settings.oauth2_jwks_refresh_interval_s,
            ),
        )

    if settings.saml_enabled:
        from app.backends.saml_auth import SAMLAuthProvider

        auth_registry.register(
            "saml",
            SAMLAuthProvider(
                idp_metadata_url=settings.saml_idp_metadata_url,
                sp_entity_id=settings.saml_sp_entity_id,
                sp_acs_url=settings.saml_sp_acs_url,
                role_attribute=settings.saml_role_attribute,
                certificate_path=settings.saml_certificate_path,
            ),
        )

    auth_registry.set_default_chain(settings.auth_provider_default_chain)
    auth_registry.configure_tenant_chains(settings.auth_provider_tenant_chains)

    # Sprint 37 (APEP-293): Initialize plan signer
    if settings.mission_plan_enabled:
        import base64 as _plan_b64

        import app.services.plan_signer as plan_signer_module

        plan_key_bytes = (
            _plan_b64.urlsafe_b64decode(settings.mission_plan_signing_key)
            if settings.mission_plan_signing_key
            else None
        )
        plan_signer_module.plan_signer = plan_signer_module.PlanSigner(
            signing_method=settings.mission_plan_signing_method,
            private_key=plan_key_bytes,
            key_id=settings.mission_plan_key_id,
        )
        logger.info(
            "plan_signer_initialized",
            method=plan_signer_module.plan_signer.method,
            key_id=settings.mission_plan_key_id,
        )

    # Sprint 37 (APEP-298): Start plan expiry background job
    if settings.mission_plan_expiry_job_enabled:
        from app.services.mission_plan_service import plan_expiry_job

        plan_expiry_job._interval_s = settings.mission_plan_expiry_interval_s
        plan_expiry_job.start()
        logger.info("plan_expiry_job_started")

    # Sprint 23 (APEP-184): Start async audit log writer
    from app.services.policy_evaluator import audit_log_writer

    audit_log_writer.start()

    # Start gRPC server if enabled
    if settings.grpc_enabled:
        try:
            from app.grpc_service import start_grpc_server

            _grpc_server = await start_grpc_server(settings.grpc_port)
            logger.info("grpc_started", port=settings.grpc_port)
        except ImportError:
            logger.warning(
                "grpc_unavailable",
                detail="gRPC dependencies not installed — skipping gRPC server.",
            )

    yield

    # Sprint 37: Stop plan expiry job
    if settings.mission_plan_expiry_job_enabled:
        from app.services.mission_plan_service import plan_expiry_job

        plan_expiry_job.stop()

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

    # Sprint 31: Close Redis rate limiter
    if settings.redis_rate_limiter_enabled:
        from app.services.redis_rate_limiter import redis_rate_limiter

        await redis_rate_limiter.close()

    # Sprint 23: Close Redis
    await rule_cache.close_redis()

    # Sprint 32: Reset notification channel registry
    notification_registry.reset()

    # Sprint 32: Close cloud audit backends
    if _cloudwatch_audit is not None:
        await _cloudwatch_audit.close()
    if _datadog_audit is not None:
        await _datadog_audit.close()
    if _loki_audit is not None:
        await _loki_audit.close()

    # Sprint 31: Reset auth registry
    auth_registry.reset()

    await close_client()
    logger.info("app_shutdown")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Deterministic Authorization Engine for AI Agent Systems",
    lifespan=lifespan,
)

# Middleware (order matters — outermost runs first, innermost runs last)
# Starlette processes middleware in reverse order of add_middleware calls:
# the LAST added runs FIRST (outermost).
# Desired order: Rate Limit -> Security Headers -> CORS -> Auth -> CSRF
# So we add in reverse: CSRF first (innermost), then Auth, CORS,
# Headers, Rate Limit last (outermost)

# Auth middleware (innermost — runs after rate limit, headers, and CORS)
app.add_middleware(MTLSMiddleware)
app.add_middleware(APIKeyAuthMiddleware)
# Sprint 31 (APEP-243): Auth registry middleware — tries pluggable providers
app.add_middleware(AuthRegistryMiddleware)
# APEP-193: CSRF protection (runs after auth so API-key exemption works)
app.add_middleware(CSRFMiddleware)
# CORS middleware (APEP-215 friction #6)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# APEP-193: Security headers (XSS, clickjacking, HSTS, CSP)
app.add_middleware(SecurityHeadersMiddleware)
# APEP-195: Rate limiting (outermost — reject early before auth overhead)
app.add_middleware(RateLimitMiddleware, default_limit=100, intercept_limit=1000)

# Routers
app.include_router(agents_router)
app.include_router(audit_router)
app.include_router(compliance_router)
app.include_router(console_router)
app.include_router(console_auth_router)
app.include_router(console_dashboard_router)
app.include_router(dashboard_router)
app.include_router(escalation_router)
app.include_router(escalation_v1_router)
app.include_router(health_router)
app.include_router(intercept_router)
app.include_router(mcp_router)
app.include_router(policy_router)
app.include_router(simulate_router)
app.include_router(taint_router)
app.include_router(memory_router)
app.include_router(plans_router)
app.include_router(scope_router)
app.include_router(scope_simulator_router)
app.include_router(sprint36_router)

# Observability
if settings.metrics_enabled:
    metrics_app = get_metrics_app()
    app.mount("/metrics", metrics_app)

setup_tracing(app)
