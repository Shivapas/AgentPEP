"""Fetch Proxy Service — secured HTTP fetch with response scanning.

Sprint 46 — APEP-364/365/366/367/368/369: Implements the fetch proxy that:
  1. Validates the URL through the 11-layer URLScanner (Sprint 44)
  2. Fetches the response via httpx.AsyncClient
  3. Runs the 6-pass ResponseNormalizer (APEP-365)
  4. Runs the ResponseInjectionScanner (APEP-366)
  5. Runs DLP scan on the response body (APEP-368)
  6. Auto-taints QUARANTINE on injection detection (APEP-367)
  7. Applies configurable response actions (APEP-369)
  8. Publishes Kafka events for observability

Thread-safe at the service level; each request creates its own state.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.models.fetch_proxy import (
    FetchEvent,
    FetchEventType,
    FetchProxyResponse,
    FetchStatus,
    InjectionScanResult,
    NormalizationResult,
    ResponseAction,
    ResponseActionConfig,
    ResponseActionRule,
)
from app.models.network_scan import ScanSeverity
from app.models.policy import TaintLevel, TaintSource
from app.services.network_dlp_scanner import network_dlp_scanner
from app.services.response_injection_scanner import response_injection_scanner
from app.services.response_normalizer import response_normalizer
from app.services.url_scanner import url_scanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default response action configuration (APEP-369)
# ---------------------------------------------------------------------------

_DEFAULT_ACTION_CONFIG = ResponseActionConfig(
    default_action=ResponseAction.ALLOW,
    rules=[
        ResponseActionRule(
            rule_id="RA-001",
            name="Block on critical injection",
            min_severity="CRITICAL",
            min_findings=1,
            action=ResponseAction.BLOCK,
            enabled=True,
        ),
        ResponseActionRule(
            rule_id="RA-002",
            name="Quarantine on high injection",
            min_severity="HIGH",
            min_findings=1,
            action=ResponseAction.QUARANTINE,
            enabled=True,
        ),
        ResponseActionRule(
            rule_id="RA-003",
            name="Log medium injection",
            min_severity="MEDIUM",
            min_findings=2,
            action=ResponseAction.LOG_ONLY,
            enabled=True,
        ),
    ],
)

_SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


# ---------------------------------------------------------------------------
# FetchProxyService
# ---------------------------------------------------------------------------


class FetchProxyService:
    """Secured HTTP fetch proxy with response scanning.

    Orchestrates URL validation, HTTP fetch, normalization, injection
    scanning, DLP scanning, auto-taint, and configurable response actions.
    """

    def __init__(
        self,
        action_config: ResponseActionConfig | None = None,
        fetch_timeout: float = 30.0,
        max_body_bytes: int = 1_048_576,
    ) -> None:
        self._action_config = action_config or _DEFAULT_ACTION_CONFIG
        self._fetch_timeout = fetch_timeout
        self._max_body_bytes = max_body_bytes

    async def fetch(
        self,
        *,
        url: str,
        session_id: str | None = None,
        agent_id: str | None = None,
        scan_response: bool = True,
        max_bytes: int | None = None,
    ) -> FetchProxyResponse:
        """Execute a proxied HTTP GET with full security scanning pipeline.

        Returns a FetchProxyResponse with scan results, taint info, and
        the (possibly sanitized) response body.
        """
        start = time.monotonic()
        effective_max_bytes = max_bytes or self._max_body_bytes

        # Step 1: URL validation through 11-layer scanner
        url_result = url_scanner.scan(url)
        if url_result.blocked:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return FetchProxyResponse(
                url=url,
                status=FetchStatus.BLOCKED,
                http_status=0,
                body="",
                body_length=0,
                action_taken=ResponseAction.BLOCK,
                latency_ms=elapsed_ms,
            )

        # Step 2: HTTP GET request
        try:
            body, http_status, content_type, truncated = await self._do_fetch(
                url, effective_max_bytes
            )
        except httpx.TimeoutException:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return FetchProxyResponse(
                url=url,
                status=FetchStatus.BLOCKED,
                http_status=0,
                body="",
                body_length=0,
                action_taken=ResponseAction.BLOCK,
                latency_ms=elapsed_ms,
            )
        except httpx.HTTPError as exc:
            logger.warning("Fetch proxy HTTP error for %s: %s", url, exc)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return FetchProxyResponse(
                url=url,
                status=FetchStatus.BLOCKED,
                http_status=0,
                body="",
                body_length=0,
                action_taken=ResponseAction.BLOCK,
                latency_ms=elapsed_ms,
            )

        # If scanning is disabled, return raw response
        if not scan_response:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return FetchProxyResponse(
                url=url,
                status=FetchStatus.ALLOWED,
                http_status=http_status,
                content_type=content_type,
                body=body,
                body_length=len(body),
                truncated=truncated,
                action_taken=ResponseAction.ALLOW,
                latency_ms=elapsed_ms,
            )

        # Step 3: 6-pass Unicode normalization (APEP-365)
        norm_result = response_normalizer.normalize(body)

        # Step 4: Response injection scanning (APEP-366)
        injection_result = response_injection_scanner.scan(
            raw_text=body,
            normalized_text=norm_result.normalized_text,
        )

        # Step 5: DLP scan on response body (APEP-368)
        dlp_findings = network_dlp_scanner.scan_text(body)
        dlp_blocked = network_dlp_scanner.has_dlp_findings(dlp_findings)

        # Step 6: Auto-taint on injection detection (APEP-367)
        taint_applied: str | None = None
        taint_node_id: str | None = None
        if session_id and (injection_result.injection_detected or dlp_blocked):
            taint_applied, taint_node_id = self._apply_auto_taint(
                session_id=session_id,
                agent_id=agent_id,
                injection_result=injection_result,
                dlp_blocked=dlp_blocked,
                url=url,
            )

        # Step 7: Determine response action (APEP-369)
        action = self._determine_action(injection_result, dlp_blocked)

        # Apply action to response body
        final_body = body
        final_status = FetchStatus.ALLOWED
        if action == ResponseAction.BLOCK:
            final_body = ""
            final_status = FetchStatus.BLOCKED
        elif action == ResponseAction.QUARANTINE:
            final_status = FetchStatus.QUARANTINED
        elif action == ResponseAction.SANITIZE:
            final_body = norm_result.normalized_text
            final_status = FetchStatus.SANITIZED
        elif action == ResponseAction.REDACT:
            final_body = self._redact_findings(body, injection_result)
            final_status = FetchStatus.SANITIZED

        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Step 8: Publish Kafka event (fire and forget)
        self._publish_event(
            url=url,
            session_id=session_id,
            agent_id=agent_id,
            http_status=http_status,
            injection_result=injection_result,
            dlp_count=len(dlp_findings),
            action=action,
            taint_applied=taint_applied,
            latency_ms=elapsed_ms,
        )

        return FetchProxyResponse(
            url=url,
            status=final_status,
            http_status=http_status,
            content_type=content_type,
            body=final_body,
            body_length=len(final_body),
            truncated=truncated,
            normalization=norm_result,
            injection_scan=injection_result,
            dlp_findings_count=len(dlp_findings),
            dlp_blocked=dlp_blocked,
            taint_applied=taint_applied,
            taint_node_id=taint_node_id,
            action_taken=action,
            latency_ms=elapsed_ms,
        )

    # --- Internal helpers ---

    async def _do_fetch(
        self, url: str, max_bytes: int
    ) -> tuple[str, int, str, bool]:
        """Execute HTTP GET and return (body, status, content_type, truncated)."""
        async with httpx.AsyncClient(
            timeout=self._fetch_timeout,
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            resp = await client.get(url)
            content_type = resp.headers.get("content-type", "")
            raw_bytes = resp.content
            truncated = len(raw_bytes) > max_bytes
            if truncated:
                raw_bytes = raw_bytes[:max_bytes]
            body = raw_bytes.decode("utf-8", errors="replace")
            return body, resp.status_code, content_type, truncated

    def _apply_auto_taint(
        self,
        *,
        session_id: str,
        agent_id: str | None,
        injection_result: InjectionScanResult,
        dlp_blocked: bool,
        url: str,
    ) -> tuple[str | None, str | None]:
        """Apply auto-taint to session graph on injection/DLP detection (APEP-367).

        Returns (taint_level, node_id) or (None, None) on failure.
        """
        try:
            from app.services.taint_graph import session_graph_manager

            graph = session_graph_manager.get_or_create(session_id)

            # Determine taint level
            if injection_result.injection_detected and injection_result.highest_severity in (
                "CRITICAL",
                "HIGH",
            ):
                taint_level = TaintLevel.QUARANTINE
            elif dlp_blocked:
                taint_level = TaintLevel.QUARANTINE
            else:
                taint_level = TaintLevel.UNTRUSTED

            # Build descriptive value for the taint node
            finding_ids = [f.signature_id for f in injection_result.findings[:5]]
            value = f"fetch_proxy:{url[:100]}|findings:{','.join(finding_ids)}"

            node = graph.add_node(
                value=value,
                taint_level=taint_level,
                source=TaintSource.WEB,
            )

            return taint_level.value, str(node.node_id)

        except Exception:
            logger.exception("Failed to apply auto-taint for fetch proxy session=%s", session_id)
            return None, None

    def _determine_action(
        self,
        injection_result: InjectionScanResult,
        dlp_blocked: bool,
    ) -> ResponseAction:
        """Determine the response action based on findings and config (APEP-369)."""
        if not injection_result.injection_detected and not dlp_blocked:
            return self._action_config.default_action

        # DLP findings always block
        if dlp_blocked:
            return ResponseAction.BLOCK

        # Check injection findings against action rules
        highest_severity = injection_result.highest_severity
        finding_count = injection_result.total_findings

        for rule in self._action_config.rules:
            if not rule.enabled:
                continue
            rule_sev_val = _SEVERITY_ORDER.get(rule.min_severity, 0)
            finding_sev_val = _SEVERITY_ORDER.get(highest_severity, 0)
            if finding_sev_val >= rule_sev_val and finding_count >= rule.min_findings:
                return rule.action

        return self._action_config.default_action

    def _redact_findings(
        self, body: str, injection_result: InjectionScanResult
    ) -> str:
        """Redact matched text from body based on injection findings."""
        result = body
        for finding in injection_result.findings:
            if finding.matched_text and finding.matched_text in result:
                result = result.replace(
                    finding.matched_text,
                    "[REDACTED:INJECTION]",
                )
        return result

    def _publish_event(
        self,
        *,
        url: str,
        session_id: str | None,
        agent_id: str | None,
        http_status: int,
        injection_result: InjectionScanResult,
        dlp_count: int,
        action: ResponseAction,
        taint_applied: str | None,
        latency_ms: int,
    ) -> None:
        """Publish a Kafka fetch event (best-effort, non-blocking)."""
        try:
            from app.services.kafka_producer import kafka_producer

            if not kafka_producer.is_running:
                return

            event_type = FetchEventType.FETCH_ALLOWED
            if action == ResponseAction.BLOCK:
                event_type = FetchEventType.FETCH_BLOCKED
            elif injection_result.injection_detected:
                event_type = FetchEventType.INJECTION_DETECTED
            elif dlp_count > 0:
                event_type = FetchEventType.DLP_HIT
            elif taint_applied == TaintLevel.QUARANTINE:
                event_type = FetchEventType.QUARANTINE_APPLIED

            event = FetchEvent(
                session_id=session_id,
                agent_id=agent_id,
                event_type=event_type,
                url=url[:500],
                http_status=http_status,
                injection_detected=injection_result.injection_detected,
                injection_finding_count=injection_result.total_findings,
                dlp_finding_count=dlp_count,
                action_taken=action,
                taint_applied=taint_applied,
                latency_ms=latency_ms,
            )

            import asyncio

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(
                    kafka_producer.publish_network_event(event.model_dump(mode="json"))
                )
            except RuntimeError:
                pass  # No running event loop — skip Kafka publish

        except Exception:
            logger.debug("Failed to publish fetch proxy Kafka event", exc_info=True)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

fetch_proxy_service = FetchProxyService()
