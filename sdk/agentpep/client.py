"""AgentPEPClient — async and sync client wrapping the Intercept API (APEP-030)."""

from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

import httpx

from agentpep.exceptions import (
    AgentPEPConnectionError,
    AgentPEPTimeoutError,
    PolicyDeniedError,
)
from agentpep.models import (
    PolicyDecision,
    PolicyDecisionResponse,
    TaintLevel,
    TaintNodeResponse,
    TaintSource,
    ToolCallRequest,
)

logger = logging.getLogger(__name__)


class AgentPEPClient:
    """Client for the AgentPEP Intercept API.

    Supports both async and sync usage patterns. The async methods (``evaluate``,
    ``enforce``) are the primary interface. Sync wrappers (``evaluate_sync``,
    ``enforce_sync``) run the event loop internally for non-async callers.

    Args:
        base_url: AgentPEP server URL (e.g. ``http://localhost:8000``).
        api_key: Optional API key for authentication (sent as ``X-API-Key``).
        timeout: Request timeout in seconds (default 5.0).
        fail_open: If True, allow tool call when the server is unreachable (default False).
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str | None = None,
        timeout: float = 5.0,
        fail_open: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.fail_open = fail_open
        self._async_client: httpx.AsyncClient | None = None
        self._sync_client: httpx.Client | None = None

    # --- Async interface ---

    def _get_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    async def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_client is None or self._async_client.is_closed:
            self._async_client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._get_headers(),
                timeout=self.timeout,
            )
        return self._async_client

    async def evaluate(
        self,
        *,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        session_id: str = "default",
        delegation_chain: list[str] | None = None,
        dry_run: bool = False,
    ) -> PolicyDecisionResponse:
        """Evaluate a tool call against the policy engine (async).

        Returns the full PolicyDecisionResponse from the server.
        """
        request = ToolCallRequest(
            request_id=uuid4(),
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=tool_args or {},
            delegation_chain=delegation_chain or [],
            dry_run=dry_run,
        )

        try:
            client = await self._get_async_client()
            resp = await client.post(
                "/v1/intercept",
                json=request.model_dump(mode="json"),
            )
            resp.raise_for_status()
            return PolicyDecisionResponse.model_validate(resp.json())

        except httpx.TimeoutException as exc:
            if self.fail_open:
                logger.warning("AgentPEP timeout — fail_open=True, allowing tool call")
                return PolicyDecisionResponse(
                    request_id=request.request_id,
                    decision=PolicyDecision.ALLOW,
                    reason="AgentPEP timeout — fail_open mode",
                )
            raise AgentPEPTimeoutError(f"Request timed out: {exc}") from exc

        except httpx.ConnectError as exc:
            if self.fail_open:
                logger.warning("AgentPEP unreachable — fail_open=True, allowing tool call")
                return PolicyDecisionResponse(
                    request_id=request.request_id,
                    decision=PolicyDecision.ALLOW,
                    reason="AgentPEP unreachable — fail_open mode",
                )
            raise AgentPEPConnectionError(f"Cannot connect to AgentPEP: {exc}") from exc

    async def enforce(
        self,
        *,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        session_id: str = "default",
        delegation_chain: list[str] | None = None,
    ) -> PolicyDecisionResponse:
        """Evaluate and enforce: raises PolicyDeniedError if not ALLOW/DRY_RUN."""
        response = await self.evaluate(
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
            session_id=session_id,
            delegation_chain=delegation_chain,
        )
        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=tool_name,
                reason=response.reason,
                decision=response.decision.value,
            )
        return response

    # --- Taint labelling (APEP-041/042) ---

    async def label_taint(
        self,
        *,
        session_id: str = "default",
        source: TaintSource,
        value: str | None = None,
        taint_level: TaintLevel | None = None,
    ) -> TaintNodeResponse:
        """Label external data with a taint source (APEP-041).

        Sources WEB, EMAIL, TOOL_OUTPUT, and AGENT_MSG are automatically
        classified as UNTRUSTED unless overridden (APEP-042).
        """
        payload: dict[str, Any] = {
            "session_id": session_id,
            "source": source.value,
        }
        if value is not None:
            payload["value"] = value
        if taint_level is not None:
            payload["taint_level"] = taint_level.value

        client = await self._get_async_client()
        resp = await client.post("/v1/taint/label", json=payload)
        resp.raise_for_status()
        return TaintNodeResponse.model_validate(resp.json())

    async def propagate_taint(
        self,
        *,
        session_id: str = "default",
        parent_node_ids: list[str],
        source: TaintSource,
        value: str | None = None,
    ) -> TaintNodeResponse:
        """Propagate taint from parent nodes to a new output node."""
        payload: dict[str, Any] = {
            "session_id": session_id,
            "parent_node_ids": parent_node_ids,
            "source": source.value,
        }
        if value is not None:
            payload["value"] = value

        client = await self._get_async_client()
        resp = await client.post("/v1/taint/propagate", json=payload)
        resp.raise_for_status()
        return TaintNodeResponse.model_validate(resp.json())

    async def aclose(self) -> None:
        """Close the underlying async HTTP client."""
        if self._async_client and not self._async_client.is_closed:
            await self._async_client.aclose()

    # --- Sync interface ---

    def _get_sync_client(self) -> httpx.Client:
        if self._sync_client is None or self._sync_client.is_closed:
            self._sync_client = httpx.Client(
                base_url=self.base_url,
                headers=self._get_headers(),
                timeout=self.timeout,
            )
        return self._sync_client

    def evaluate_sync(
        self,
        *,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        session_id: str = "default",
        delegation_chain: list[str] | None = None,
        dry_run: bool = False,
    ) -> PolicyDecisionResponse:
        """Evaluate a tool call against the policy engine (sync)."""
        request = ToolCallRequest(
            request_id=uuid4(),
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=tool_args or {},
            delegation_chain=delegation_chain or [],
            dry_run=dry_run,
        )

        try:
            client = self._get_sync_client()
            resp = client.post(
                "/v1/intercept",
                json=request.model_dump(mode="json"),
            )
            resp.raise_for_status()
            return PolicyDecisionResponse.model_validate(resp.json())

        except httpx.TimeoutException as exc:
            if self.fail_open:
                logger.warning("AgentPEP timeout — fail_open=True, allowing tool call")
                return PolicyDecisionResponse(
                    request_id=request.request_id,
                    decision=PolicyDecision.ALLOW,
                    reason="AgentPEP timeout — fail_open mode",
                )
            raise AgentPEPTimeoutError(f"Request timed out: {exc}") from exc

        except httpx.ConnectError as exc:
            if self.fail_open:
                logger.warning("AgentPEP unreachable — fail_open=True, allowing tool call")
                return PolicyDecisionResponse(
                    request_id=request.request_id,
                    decision=PolicyDecision.ALLOW,
                    reason="AgentPEP unreachable — fail_open mode",
                )
            raise AgentPEPConnectionError(f"Cannot connect to AgentPEP: {exc}") from exc

    def enforce_sync(
        self,
        *,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        session_id: str = "default",
        delegation_chain: list[str] | None = None,
    ) -> PolicyDecisionResponse:
        """Evaluate and enforce synchronously: raises PolicyDeniedError if not ALLOW/DRY_RUN."""
        response = self.evaluate_sync(
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
            session_id=session_id,
            delegation_chain=delegation_chain,
        )
        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=tool_name,
                reason=response.reason,
                decision=response.decision.value,
            )
        return response

    def label_taint_sync(
        self,
        *,
        session_id: str = "default",
        source: TaintSource,
        value: str | None = None,
        taint_level: TaintLevel | None = None,
    ) -> TaintNodeResponse:
        """Label external data with a taint source (sync)."""
        payload: dict[str, Any] = {
            "session_id": session_id,
            "source": source.value,
        }
        if value is not None:
            payload["value"] = value
        if taint_level is not None:
            payload["taint_level"] = taint_level.value

        client = self._get_sync_client()
        resp = client.post("/v1/taint/label", json=payload)
        resp.raise_for_status()
        return TaintNodeResponse.model_validate(resp.json())

    def propagate_taint_sync(
        self,
        *,
        session_id: str = "default",
        parent_node_ids: list[str],
        source: TaintSource,
        value: str | None = None,
    ) -> TaintNodeResponse:
        """Propagate taint from parent nodes to a new output node (sync)."""
        payload: dict[str, Any] = {
            "session_id": session_id,
            "parent_node_ids": parent_node_ids,
            "source": source.value,
        }
        if value is not None:
            payload["value"] = value

        client = self._get_sync_client()
        resp = client.post("/v1/taint/propagate", json=payload)
        resp.raise_for_status()
        return TaintNodeResponse.model_validate(resp.json())

    def close(self) -> None:
        """Close the underlying sync HTTP client."""
        if self._sync_client and not self._sync_client.is_closed:
            self._sync_client.close()
