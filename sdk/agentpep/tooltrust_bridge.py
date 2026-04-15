"""ToolTrust → AgentPEP Intercept Bridge SDK/CLI — Sprint 55 (APEP-438.c).

SDK wrapper and CLI commands for bridging ToolTrust Layer 3 PreToolUse
scan verdicts into the AgentPEP Intercept pipeline.

Usage as SDK::

    from agentpep.tooltrust_bridge import ToolTrustBridgeClient

    async with ToolTrustBridgeClient(base_url="http://localhost:8000") as bridge:
        result = await bridge.submit_verdict(
            session_id="sess-123",
            tool_name="file.write",
            verdict="SUSPICIOUS",
            verdict_details="Possible data exfiltration pattern detected",
        )
        print(result.taint_applied)  # "UNTRUSTED"

Usage as CLI::

    python -m agentpep.tooltrust_bridge \\
        --session-id sess-123 \\
        --tool-name file.write \\
        --verdict MALICIOUS \\
        --base-url http://localhost:8000
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class BridgeResult:
    """Result of a ToolTrust bridge verdict submission."""

    __slots__ = (
        "accepted", "taint_applied", "intercept_decision",
        "bridge_latency_ms", "detail",
    )

    def __init__(self, data: dict[str, Any]) -> None:
        self.accepted: bool = data.get("accepted", False)
        self.taint_applied: str | None = data.get("taint_applied")
        self.intercept_decision: str | None = data.get("intercept_decision")
        self.bridge_latency_ms: int = data.get("bridge_latency_ms", 0)
        self.detail: str = data.get("detail", "")

    def __repr__(self) -> str:
        return (
            f"BridgeResult(accepted={self.accepted}, "
            f"taint={self.taint_applied!r}, "
            f"decision={self.intercept_decision!r}, "
            f"latency_ms={self.bridge_latency_ms})"
        )


class ToolTrustBridgeClient:
    """SDK client for ToolTrust → AgentPEP Intercept bridge (APEP-438.c).

    Submits ToolTrust Layer 3 PreToolUse verdicts to the AgentPEP
    bridge endpoint and retrieves bridge events.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._http: httpx.AsyncClient | None = None

    async def __aenter__(self) -> ToolTrustBridgeClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Release HTTP resources."""
        if self._http and not self._http.is_closed:
            await self._http.aclose()

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self._api_key:
                headers["X-API-Key"] = self._api_key
            self._http = httpx.AsyncClient(
                base_url=self._base_url,
                headers=headers,
                timeout=self._timeout,
            )
        return self._http

    async def submit_verdict(
        self,
        *,
        session_id: str,
        tool_name: str,
        verdict: str,
        agent_id: str = "",
        tool_args: dict | None = None,
        verdict_details: str = "",
        findings: list[dict] | None = None,
        scan_latency_ms: int = 0,
        layer: int = 3,
        trust_cache_hit: bool = False,
    ) -> BridgeResult:
        """Submit a ToolTrust verdict to the AgentPEP bridge.

        Args:
            session_id: Session ID for the tool call.
            tool_name: Tool being invoked.
            verdict: ToolTrust verdict level (CLEAN, SUSPICIOUS, MALICIOUS).
            agent_id: Agent performing the tool call.
            tool_args: Tool arguments (optional).
            verdict_details: Human-readable verdict explanation.
            findings: Detailed scan findings from ToolTrust.
            scan_latency_ms: ToolTrust scan latency.
            layer: ToolTrust layer number (default 3).
            trust_cache_hit: Whether trust cache was used.

        Returns:
            BridgeResult with taint and decision info.
        """
        http = await self._get_http()
        payload = {
            "session_id": session_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "tool_args": tool_args or {},
            "verdict": verdict,
            "verdict_details": verdict_details,
            "findings": findings or [],
            "scan_latency_ms": scan_latency_ms,
            "layer": layer,
            "trust_cache_hit": trust_cache_hit,
        }

        resp = await http.post("/v1/sprint55/bridge/tooltrust", json=payload)
        resp.raise_for_status()
        return BridgeResult(resp.json())

    async def get_events(
        self,
        session_id: str,
        limit: int = 50,
    ) -> list[dict]:
        """Retrieve bridge events for a session.

        Args:
            session_id: Session to query.
            limit: Maximum number of events to return.

        Returns:
            List of bridge event dicts.
        """
        http = await self._get_http()
        resp = await http.get(
            "/v1/sprint55/bridge/tooltrust/events",
            params={"session_id": session_id, "limit": limit},
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


async def _cli_main(args: argparse.Namespace) -> int:
    """CLI implementation."""
    async with ToolTrustBridgeClient(
        base_url=args.base_url,
        api_key=args.api_key,
        timeout=args.timeout,
    ) as bridge:
        result = await bridge.submit_verdict(
            session_id=args.session_id,
            tool_name=args.tool_name,
            verdict=args.verdict,
            agent_id=args.agent_id or "",
            verdict_details=args.details or "",
            layer=args.layer,
        )

        print(f"Accepted:  {result.accepted}")
        print(f"Taint:     {result.taint_applied or 'none'}")
        print(f"Decision:  {result.intercept_decision or 'none'}")
        print(f"Latency:   {result.bridge_latency_ms}ms")
        print(f"Detail:    {result.detail}")

        return 0 if result.accepted else 1


def main() -> None:
    """CLI entry point for ToolTrust bridge."""
    parser = argparse.ArgumentParser(
        description="Submit ToolTrust Layer 3 verdicts to AgentPEP Intercept bridge"
    )
    parser.add_argument("--session-id", required=True, help="Session ID")
    parser.add_argument("--tool-name", required=True, help="Tool being invoked")
    parser.add_argument(
        "--verdict",
        required=True,
        choices=["CLEAN", "SUSPICIOUS", "MALICIOUS"],
        help="ToolTrust scan verdict",
    )
    parser.add_argument("--agent-id", default="", help="Agent ID")
    parser.add_argument("--details", default="", help="Verdict details")
    parser.add_argument("--layer", type=int, default=3, help="ToolTrust layer number")
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="AgentPEP server URL",
    )
    parser.add_argument("--api-key", default=None, help="API key for authentication")
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="Request timeout in seconds"
    )

    args = parser.parse_args()
    sys.exit(asyncio.run(_cli_main(args)))


if __name__ == "__main__":
    main()
