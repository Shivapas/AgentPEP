"""AgentPEP FastAPI application entry point."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from app.api.v1.health import router as health_router
from app.api.v1.intercept import router as intercept_router
from app.core.config import settings
from app.core.observability import get_metrics_app, setup_tracing
from app.db.mongodb import close_client, init_collections


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle."""
    await init_collections()
    yield
    await close_client()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Deterministic Authorization Engine for AI Agent Systems",
    lifespan=lifespan,
)

# Routers
app.include_router(health_router)
app.include_router(intercept_router)

# Observability
if settings.metrics_enabled:
    metrics_app = get_metrics_app()
    app.mount("/metrics", metrics_app)

setup_tracing(app)
