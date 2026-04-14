"""Forward Proxy Pipeline Integration — Sprint 47.

APEP-372.e: Integrate CONNECT tunnel handler into the PolicyEvaluator pipeline.
APEP-373.d: Integrate forward proxy DLP scan into enforcement pipeline.
APEP-375.e: Integrate TLS interception into enforcement pipeline.
APEP-378.d: Integrate WebSocket frame scanning into enforcement pipeline.

This module wires Sprint 47 components together:
  - ConnectTunnelHandler uses HostnameBlocker and ForwardProxyDLPScanner.
  - WebSocketProxy uses WebSocketFrameScanner and HostnameBlocker.
  - Both emit Kafka events for the agentpep.network topic.
  - TLS interception is initialized when the forward proxy starts.
  - DLP findings from proxy traffic contribute to session risk scores
    and taint propagation through the existing PolicyEvaluator pipeline.
"""

from __future__ import annotations

import logging
from typing import Any

from app.models.network_scan import (
    NetworkEvent,
    NetworkEventType,
    ScanSeverity,
)

logger = logging.getLogger(__name__)


class ForwardProxyPipeline:
    """Wires Sprint 47 proxy components into the AgentPEP enforcement pipeline.

    Responsibilities:
      1. Initialize service dependencies (hostname blocker, DLP scanners).
      2. Wire up Kafka event emission for proxy events.
      3. Propagate DLP findings to session taint graphs.
      4. Provide a unified interface for proxy lifecycle management.
    """

    def __init__(self) -> None:
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize all Sprint 47 proxy services and wire dependencies."""
        if self._initialized:
            return

        from app.services.connect_tunnel import connect_tunnel_handler
        from app.services.forward_proxy_dlp import forward_proxy_dlp_scanner
        from app.services.hostname_blocker import hostname_blocker
        from app.services.websocket_frame_scanner import websocket_frame_scanner
        from app.services.websocket_proxy import websocket_proxy

        # Wire hostname blocker into tunnel handler and websocket proxy
        connect_tunnel_handler.set_hostname_checker(hostname_blocker)
        websocket_proxy.set_hostname_checker(hostname_blocker)

        # Wire DLP scanner into tunnel handler
        connect_tunnel_handler.set_dlp_scanner(forward_proxy_dlp_scanner)

        # Wire frame scanner into websocket proxy
        websocket_proxy.set_frame_scanner(websocket_frame_scanner)

        # Wire Kafka producer if available
        try:
            from app.services.kafka_producer import kafka_producer

            connect_tunnel_handler.set_kafka_producer(kafka_producer)
            websocket_proxy.set_kafka_producer(kafka_producer)
        except Exception:
            logger.warning("Kafka producer not available for proxy events")

        # Load hostname blocklist from DB
        try:
            await hostname_blocker.load_from_db()
        except Exception:
            logger.warning("Failed to load proxy hostname blocklist from DB")

        self._initialized = True
        logger.info("forward_proxy_pipeline_initialized")

    async def start_tunnel_server(self) -> None:
        """Start the CONNECT tunnel server."""
        if not self._initialized:
            await self.initialize()

        from app.services.connect_tunnel import connect_tunnel_handler

        await connect_tunnel_handler.start()

    async def stop(self) -> None:
        """Stop all proxy services."""
        from app.services.connect_tunnel import connect_tunnel_handler

        await connect_tunnel_handler.stop()
        logger.info("forward_proxy_pipeline_stopped")

    def propagate_dlp_findings_to_taint(
        self,
        session_id: str,
        agent_id: str,
        findings: list[Any],
    ) -> list[str]:
        """Propagate DLP findings from proxy traffic to the session taint graph.

        This bridges proxy-layer DLP findings with the existing taint
        propagation system in the PolicyEvaluator pipeline.

        Returns list of taint flags applied.
        """
        if not findings or not session_id:
            return []

        taint_flags: list[str] = []

        try:
            from app.models.policy import TaintLevel, TaintSource
            from app.services.taint_graph import session_graph_manager

            graph = session_graph_manager.get_session(session_id)
            if graph is None:
                graph = session_graph_manager.create_session(session_id)

            # Determine taint level from finding severity
            has_critical = any(
                getattr(f, "severity", None) in ("CRITICAL", ScanSeverity.CRITICAL)
                for f in findings
            )
            has_high = any(
                getattr(f, "severity", None) in ("HIGH", ScanSeverity.HIGH)
                for f in findings
            )

            if has_critical:
                taint_level = TaintLevel.QUARANTINE
            elif has_high:
                taint_level = TaintLevel.UNTRUSTED
            else:
                return taint_flags

            node = graph.add_node(
                source=TaintSource.TOOL_OUTPUT,
                taint_level=taint_level,
                agent_id=agent_id,
            )
            taint_flags.append(taint_level.value)

            logger.info(
                "proxy_dlp_taint_applied",
                session_id=session_id,
                agent_id=agent_id,
                taint_level=taint_level.value,
                finding_count=len(findings),
            )

        except Exception:
            logger.exception("Failed to propagate proxy DLP findings to taint")

        return taint_flags

    def create_proxy_network_event(
        self,
        *,
        event_type: NetworkEventType,
        scanner: str,
        session_id: str | None = None,
        agent_id: str | None = None,
        finding_rule_id: str = "",
        severity: ScanSeverity = ScanSeverity.MEDIUM,
        url: str | None = None,
        blocked: bool = False,
    ) -> NetworkEvent:
        """Create a standardized NetworkEvent for proxy-related activity."""
        return NetworkEvent(
            session_id=session_id,
            agent_id=agent_id,
            event_type=event_type,
            scanner=scanner,
            finding_rule_id=finding_rule_id,
            severity=severity,
            url=url,
            blocked=blocked,
        )

    @property
    def is_initialized(self) -> bool:
        return self._initialized


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

forward_proxy_pipeline = ForwardProxyPipeline()
