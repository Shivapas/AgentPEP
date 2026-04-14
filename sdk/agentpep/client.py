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
from agentpep.execution_token import execution_token_validator
from agentpep.tamper_detection import tamper_detector

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
            # APEP-190: Record successful intercept for tamper detection
            tamper_detector.record_intercept(tool_name, agent_id)
            return PolicyDecisionResponse.model_validate(resp.json())

        except httpx.TimeoutException as exc:
            if self.fail_open:
                logger.warning("AgentPEP timeout — fail_open=True, allowing tool call")
                tamper_detector.record_intercept(tool_name, agent_id)
                return PolicyDecisionResponse(
                    request_id=request.request_id,
                    decision=PolicyDecision.ALLOW,
                    reason="AgentPEP timeout — fail_open mode",
                )
            raise AgentPEPTimeoutError(f"Request timed out: {exc}") from exc

        except httpx.ConnectError as exc:
            if self.fail_open:
                logger.warning("AgentPEP unreachable — fail_open=True, allowing tool call")
                tamper_detector.record_intercept(tool_name, agent_id)
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
        # APEP-232: Validate execution token before allowing tool execution
        if response.execution_token is not None:
            execution_token_validator.validate_and_consume(
                response.execution_token,
                expected_tool_name=tool_name,
                expected_agent_id=agent_id,
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

    async def health_check(self) -> dict[str, str]:
        """Check server health. Returns {"status": "ok", "version": "..."}.

        Raises AgentPEPConnectionError if the server is unreachable.
        """
        try:
            client = await self._get_async_client()
            resp = await client.get("/health")
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]
        except httpx.ConnectError as exc:
            raise AgentPEPConnectionError(f"Cannot connect to AgentPEP: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise AgentPEPTimeoutError(f"Health check timed out: {exc}") from exc

    # --- Sprint 46 (APEP-370): Fetch safe ---

    async def fetch_safe(
        self,
        *,
        url: str,
        session_id: str | None = None,
        agent_id: str | None = None,
        scan_response: bool = True,
        max_bytes: int = 1_048_576,
    ) -> "FetchSafeResponse":
        """Fetch a URL through the AgentPEP security proxy (APEP-370).

        The server validates the URL, fetches the content, and runs:
        - 6-pass Unicode normalization
        - Multi-pass injection scanning
        - DLP scan on response body
        - Auto-taint QUARANTINE on injection detection

        Returns a FetchSafeResponse with the (possibly sanitized) body
        and all scan results.

        Raises AgentPEPConnectionError if the server is unreachable.
        Raises AgentPEPTimeoutError on timeout.
        """
        from agentpep.models import FetchSafeResponse

        params: dict[str, Any] = {"url": url, "scan_response": scan_response, "max_bytes": max_bytes}
        if session_id is not None:
            params["session_id"] = session_id
        if agent_id is not None:
            params["agent_id"] = agent_id

        try:
            client = await self._get_async_client()
            resp = await client.get("/v1/fetch", params=params)
            resp.raise_for_status()
            data = resp.json()
            # Map server response to SDK model
            injection_scan = data.get("injection_scan") or {}
            return FetchSafeResponse(
                fetch_id=data.get("fetch_id"),
                url=data.get("url", url),
                status=data.get("status", "ALLOWED"),
                http_status=data.get("http_status", 0),
                content_type=data.get("content_type", ""),
                body=data.get("body", ""),
                body_length=data.get("body_length", 0),
                truncated=data.get("truncated", False),
                injection_detected=injection_scan.get("injection_detected", False),
                injection_finding_count=injection_scan.get("total_findings", 0),
                injection_highest_severity=injection_scan.get("highest_severity", "INFO"),
                dlp_findings_count=data.get("dlp_findings_count", 0),
                dlp_blocked=data.get("dlp_blocked", False),
                taint_applied=data.get("taint_applied"),
                taint_node_id=data.get("taint_node_id"),
                action_taken=data.get("action_taken", "ALLOW"),
                latency_ms=data.get("latency_ms", 0),
            )
        except httpx.ConnectError as exc:
            raise AgentPEPConnectionError(f"Cannot connect to AgentPEP: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise AgentPEPTimeoutError(f"fetch_safe timed out: {exc}") from exc

    def fetch_safe_sync(
        self,
        *,
        url: str,
        session_id: str | None = None,
        agent_id: str | None = None,
        scan_response: bool = True,
        max_bytes: int = 1_048_576,
    ) -> "FetchSafeResponse":
        """Fetch a URL through the AgentPEP security proxy (sync wrapper).

        See ``fetch_safe`` for details.
        """
        from agentpep.models import FetchSafeResponse

        params: dict[str, Any] = {"url": url, "scan_response": scan_response, "max_bytes": max_bytes}
        if session_id is not None:
            params["session_id"] = session_id
        if agent_id is not None:
            params["agent_id"] = agent_id

        try:
            client = self._get_sync_client()
            resp = client.get("/v1/fetch", params=params)
            resp.raise_for_status()
            data = resp.json()
            injection_scan = data.get("injection_scan") or {}
            return FetchSafeResponse(
                fetch_id=data.get("fetch_id"),
                url=data.get("url", url),
                status=data.get("status", "ALLOWED"),
                http_status=data.get("http_status", 0),
                content_type=data.get("content_type", ""),
                body=data.get("body", ""),
                body_length=data.get("body_length", 0),
                truncated=data.get("truncated", False),
                injection_detected=injection_scan.get("injection_detected", False),
                injection_finding_count=injection_scan.get("total_findings", 0),
                injection_highest_severity=injection_scan.get("highest_severity", "INFO"),
                dlp_findings_count=data.get("dlp_findings_count", 0),
                dlp_blocked=data.get("dlp_blocked", False),
                taint_applied=data.get("taint_applied"),
                taint_node_id=data.get("taint_node_id"),
                action_taken=data.get("action_taken", "ALLOW"),
                latency_ms=data.get("latency_ms", 0),
            )
        except httpx.ConnectError as exc:
            raise AgentPEPConnectionError(f"Cannot connect to AgentPEP: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise AgentPEPTimeoutError(f"fetch_safe timed out: {exc}") from exc

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
            # APEP-190: Record successful intercept for tamper detection
            tamper_detector.record_intercept(tool_name, agent_id)
            return PolicyDecisionResponse.model_validate(resp.json())

        except httpx.TimeoutException as exc:
            if self.fail_open:
                logger.warning("AgentPEP timeout — fail_open=True, allowing tool call")
                tamper_detector.record_intercept(tool_name, agent_id)
                return PolicyDecisionResponse(
                    request_id=request.request_id,
                    decision=PolicyDecision.ALLOW,
                    reason="AgentPEP timeout — fail_open mode",
                )
            raise AgentPEPTimeoutError(f"Request timed out: {exc}") from exc

        except httpx.ConnectError as exc:
            if self.fail_open:
                logger.warning("AgentPEP unreachable — fail_open=True, allowing tool call")
                tamper_detector.record_intercept(tool_name, agent_id)
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
        # APEP-232: Validate execution token before allowing tool execution
        if response.execution_token is not None:
            execution_token_validator.validate_and_consume(
                response.execution_token,
                expected_tool_name=tool_name,
                expected_agent_id=agent_id,
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

    def health_check_sync(self) -> dict[str, str]:
        """Check server health (sync). Returns {"status": "ok", "version": "..."}.

        Raises AgentPEPConnectionError if the server is unreachable.
        """
        try:
            client = self._get_sync_client()
            resp = client.get("/health")
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]
        except httpx.ConnectError as exc:
            raise AgentPEPConnectionError(f"Cannot connect to AgentPEP: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise AgentPEPTimeoutError(f"Health check timed out: {exc}") from exc

    # --- Sprint 54 (APEP-434): CIS scan helper ---

    async def cis_scan(
        self,
        path_or_text: str,
        *,
        session_id: str | None = None,
        scan_mode: str = "STRICT",
        tiers: list[int] | None = None,
    ) -> dict[str, Any]:
        """Scan a file path or text content through the CIS pipeline (APEP-434).

        Automatically detects whether *path_or_text* is a file path or inline
        text and calls the appropriate endpoint:
          - File path → POST /v1/cis/scan-file
          - Text content → POST /v1/cis/scan-text

        Args:
            path_or_text: A filesystem path or raw text to scan.
            session_id: Optional session ID for taint propagation.
            scan_mode: CIS scan mode (STRICT, STANDARD, LENIENT).
            tiers: Tiers to run (default [0, 1]).

        Returns:
            The scan result dict from the server.
        """
        import os

        effective_tiers = tiers if tiers is not None else [0, 1]

        # Heuristic: if it looks like a path (contains os.sep or /) treat as file.
        is_path = os.sep in path_or_text or "/" in path_or_text

        try:
            client = await self._get_async_client()

            if is_path:
                payload: dict[str, Any] = {
                    "file_path": path_or_text,
                    "scan_mode": scan_mode,
                    "tiers": effective_tiers,
                }
                if session_id:
                    payload["session_id"] = session_id
                resp = await client.post("/v1/cis/scan-file", json=payload)
            else:
                payload = {
                    "text": path_or_text,
                    "scan_mode": scan_mode,
                    "tiers": effective_tiers,
                }
                if session_id:
                    payload["session_id"] = session_id
                resp = await client.post("/v1/cis/scan-text", json=payload)

            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]

        except httpx.ConnectError as exc:
            if self.fail_open:
                logger.warning("AgentPEP unreachable — cis_scan fail_open, returning clean")
                return {"allowed": True, "findings": [], "fail_open": True}
            raise AgentPEPConnectionError(f"Cannot connect to AgentPEP: {exc}") from exc
        except httpx.TimeoutException as exc:
            if self.fail_open:
                logger.warning("AgentPEP timeout — cis_scan fail_open, returning clean")
                return {"allowed": True, "findings": [], "fail_open": True}
            raise AgentPEPTimeoutError(f"cis_scan timed out: {exc}") from exc

    def cis_scan_sync(
        self,
        path_or_text: str,
        *,
        session_id: str | None = None,
        scan_mode: str = "STRICT",
        tiers: list[int] | None = None,
    ) -> dict[str, Any]:
        """Scan a file path or text content through the CIS pipeline (sync).

        See ``cis_scan`` for details.
        """
        import os

        effective_tiers = tiers if tiers is not None else [0, 1]
        is_path = os.sep in path_or_text or "/" in path_or_text

        try:
            client = self._get_sync_client()

            if is_path:
                payload: dict[str, Any] = {
                    "file_path": path_or_text,
                    "scan_mode": scan_mode,
                    "tiers": effective_tiers,
                }
                if session_id:
                    payload["session_id"] = session_id
                resp = client.post("/v1/cis/scan-file", json=payload)
            else:
                payload = {
                    "text": path_or_text,
                    "scan_mode": scan_mode,
                    "tiers": effective_tiers,
                }
                if session_id:
                    payload["session_id"] = session_id
                resp = client.post("/v1/cis/scan-text", json=payload)

            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]

        except httpx.ConnectError as exc:
            if self.fail_open:
                logger.warning("AgentPEP unreachable — cis_scan_sync fail_open, returning clean")
                return {"allowed": True, "findings": [], "fail_open": True}
            raise AgentPEPConnectionError(f"Cannot connect to AgentPEP: {exc}") from exc
        except httpx.TimeoutException as exc:
            if self.fail_open:
                logger.warning("AgentPEP timeout — cis_scan_sync fail_open, returning clean")
                return {"allowed": True, "findings": [], "fail_open": True}
            raise AgentPEPTimeoutError(f"cis_scan_sync timed out: {exc}") from exc

    def close(self) -> None:
        """Close the underlying sync HTTP client."""
        if self._sync_client and not self._sync_client.is_closed:
            self._sync_client.close()
