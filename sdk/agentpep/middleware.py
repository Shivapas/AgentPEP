"""FastAPI middleware integration for AgentPEP (APEP-032).

Intercepts incoming FastAPI requests and evaluates them against the AgentPEP
policy engine before the route handler executes.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from agentpep.client import AgentPEPClient
from agentpep.models import PolicyDecision

logger = logging.getLogger(__name__)


class AgentPEPMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware that enforces AgentPEP policy on requests.

    The middleware extracts ``agent_id`` and ``session_id`` from request headers
    (``X-Agent-Id``, ``X-Session-Id``) and uses the request path as the tool name.
    If the policy decision is not ALLOW, it returns a 403 response.

    Args:
        app: The ASGI application.
        client: An ``AgentPEPClient`` instance.
        agent_id_header: Header name for the agent ID (default ``X-Agent-Id``).
        session_id_header: Header name for the session ID (default ``X-Session-Id``).
        exclude_paths: Set of paths to skip policy evaluation (e.g., ``/health``).
        tool_name_fn: Optional callable to derive the tool name from the request.
            Defaults to using the request path.

    Example::

        from fastapi import FastAPI
        from agentpep import AgentPEPClient
        from agentpep.middleware import AgentPEPMiddleware

        app = FastAPI()
        client = AgentPEPClient(base_url="http://localhost:8000", api_key="key")
        app.add_middleware(
            AgentPEPMiddleware,
            client=client,
            exclude_paths={"/health", "/ready", "/metrics"},
        )
    """

    def __init__(
        self,
        app: Any,
        client: AgentPEPClient,
        agent_id_header: str = "X-Agent-Id",
        session_id_header: str = "X-Session-Id",
        exclude_paths: set[str] | None = None,
        tool_name_fn: Callable[[Request], str] | None = None,
    ) -> None:
        super().__init__(app)
        self.client = client
        self.agent_id_header = agent_id_header
        self.session_id_header = session_id_header
        self.exclude_paths = exclude_paths or set()
        self.tool_name_fn = tool_name_fn or (lambda r: r.url.path)

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        agent_id = request.headers.get(self.agent_id_header)
        if not agent_id:
            return await call_next(request)

        session_id = request.headers.get(self.session_id_header, "default")
        tool_name = self.tool_name_fn(request)

        try:
            response = await self.client.evaluate(
                agent_id=agent_id,
                tool_name=tool_name,
                session_id=session_id,
            )
        except Exception:
            logger.exception("AgentPEP evaluation failed")
            if self.client.fail_open:
                return await call_next(request)
            return JSONResponse(
                status_code=503,
                content={"detail": "Policy evaluation unavailable"},
            )

        if response.decision in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            return await call_next(request)

        return JSONResponse(
            status_code=403,
            content={
                "detail": f"Policy {response.decision.value}: {response.reason}",
                "decision": response.decision.value,
            },
        )
