"""Health and readiness check endpoints."""

from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import settings
from app.db.mongodb import get_database

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    version: str


class ReadinessResponse(BaseModel):
    status: str
    mongodb: str


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=settings.app_version)


@router.get("/ready", response_model=ReadinessResponse)
async def readiness() -> ReadinessResponse:
    try:
        db = get_database()
        await db.command("ping")
        mongo_status = "connected"
    except Exception:
        mongo_status = "unavailable"

    status = "ok" if mongo_status == "connected" else "degraded"
    return ReadinessResponse(status=status, mongodb=mongo_status)
