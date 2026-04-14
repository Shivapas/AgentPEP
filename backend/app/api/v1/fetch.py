"""GET /v1/fetch — Fetch proxy endpoint.

Sprint 46 — APEP-364: Exposes a REST endpoint that proxies HTTP GET requests
through the full security scanning pipeline: URL validation, response
normalization, injection scanning, DLP scanning, auto-taint, and configurable
response actions.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query

from app.models.fetch_proxy import (
    FetchProxyResponse,
    ResponseActionConfig,
    ResponseActionRule,
    ResponseAction,
)
from app.services.fetch_proxy import fetch_proxy_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["fetch"])


@router.get("/fetch", response_model=FetchProxyResponse)
async def fetch_proxy(
    url: str = Query(..., description="URL to fetch"),
    session_id: str | None = Query(default=None, description="Session for taint propagation"),
    agent_id: str | None = Query(default=None, description="Agent context"),
    scan_response: bool = Query(default=True, description="Run injection + DLP scan on response"),
    max_bytes: int = Query(
        default=1_048_576,
        ge=0,
        le=10_485_760,
        description="Max response body size in bytes",
    ),
) -> FetchProxyResponse:
    """Fetch a URL through the AgentPEP security proxy.

    Validates the URL, fetches the content, and runs:
    - 6-pass Unicode normalization (APEP-365)
    - Multi-pass injection scanning (APEP-366)
    - DLP scan on response body (APEP-368)
    - Auto-taint QUARANTINE on injection detection (APEP-367)
    - Configurable response actions (APEP-369)

    Returns the (possibly sanitized/blocked) response with full scan results.
    """
    return await fetch_proxy_service.fetch(
        url=url,
        session_id=session_id,
        agent_id=agent_id,
        scan_response=scan_response,
        max_bytes=max_bytes,
    )


@router.post("/fetch/actions", response_model=dict)
async def update_response_actions(config: ResponseActionConfig) -> dict:
    """Update the configurable response action rules (APEP-369).

    Replaces the current action configuration with the provided rules.
    """
    fetch_proxy_service._action_config = config
    return {
        "status": "ok",
        "default_action": config.default_action.value,
        "rule_count": len(config.rules),
    }


@router.get("/fetch/actions", response_model=ResponseActionConfig)
async def get_response_actions() -> ResponseActionConfig:
    """Get the current response action configuration (APEP-369)."""
    return fetch_proxy_service._action_config
