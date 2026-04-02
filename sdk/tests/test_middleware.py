"""Tests for FastAPI middleware integration (APEP-032, APEP-036)."""

import pytest
import httpx
import respx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agentpep.client import AgentPEPClient
from agentpep.middleware import AgentPEPMiddleware


MOCK_ALLOW = {
    "request_id": "00000000-0000-0000-0000-000000000001",
    "decision": "ALLOW",
    "reason": "Allowed",
    "latency_ms": 1,
}

MOCK_DENY = {
    "request_id": "00000000-0000-0000-0000-000000000002",
    "decision": "DENY",
    "reason": "Denied by policy",
    "latency_ms": 1,
}


async def hello(request: Request) -> JSONResponse:
    return JSONResponse({"message": "hello"})


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def create_app(client: AgentPEPClient) -> Starlette:
    app = Starlette(
        routes=[
            Route("/hello", hello),
            Route("/health", health),
        ],
    )
    app.add_middleware(
        AgentPEPMiddleware,
        client=client,
        exclude_paths={"/health"},
    )
    return app


@pytest.fixture
def agentpep_client() -> AgentPEPClient:
    return AgentPEPClient(base_url="http://agentpep:8000")


class TestMiddleware:
    @respx.mock
    def test_allowed_request(self, agentpep_client: AgentPEPClient) -> None:
        respx.post("http://agentpep:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_ALLOW)
        )
        app = create_app(agentpep_client)
        test_client = TestClient(app)

        resp = test_client.get("/hello", headers={"X-Agent-Id": "agent-1"})
        assert resp.status_code == 200
        assert resp.json()["message"] == "hello"

    @respx.mock
    def test_denied_request(self, agentpep_client: AgentPEPClient) -> None:
        respx.post("http://agentpep:8000/v1/intercept").mock(
            return_value=httpx.Response(200, json=MOCK_DENY)
        )
        app = create_app(agentpep_client)
        test_client = TestClient(app)

        resp = test_client.get("/hello", headers={"X-Agent-Id": "agent-1"})
        assert resp.status_code == 403
        assert resp.json()["decision"] == "DENY"

    def test_excluded_path_bypasses_policy(self, agentpep_client: AgentPEPClient) -> None:
        """Excluded paths should not trigger policy evaluation."""
        app = create_app(agentpep_client)
        test_client = TestClient(app)

        # /health is excluded — no intercept call needed
        resp = test_client.get("/health", headers={"X-Agent-Id": "agent-1"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_no_agent_id_header_passes_through(self, agentpep_client: AgentPEPClient) -> None:
        """Requests without X-Agent-Id should pass through without policy check."""
        app = create_app(agentpep_client)
        test_client = TestClient(app)

        resp = test_client.get("/hello")
        assert resp.status_code == 200
