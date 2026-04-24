"""PDP client — policy evaluation entry point with FAIL_CLOSED timeout.

Wires together:
  - ComplexityBudgetChecker (FEATURE-03, S-E02) — pre-evaluation gate
  - EvalTimeoutGuard (FEATURE-03, S-E02)        — hard timeout → DENY
  - OPAEngine (FEATURE-01, S-E04)               — Rego evaluation
  - PDPResponseParser (FEATURE-01, S-E04)        — typed decision
  - EnforcementLog (FEATURE-01, S-E04)           — per-evaluation audit entry

FAIL_CLOSED paths:
  1. Complexity budget exceeded → DENY (no OPA call made)
  2. OPA evaluation timeout    → DENY
  3. OPA evaluation error      → DENY
  4. Parser error              → DENY

Sprint S-E04 (E04-T04)
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from app.core.structured_logging import get_logger
from app.enforcement.complexity_budget import complexity_checker
from app.enforcement.eval_timeout import EvalTimeoutGuard
from app.pdp.enforcement_log import EnforcementLogEntry, enforcement_log
from app.pdp.engine import OPAEngine, _engine as _opa_engine
from app.pdp.request_builder import AuthorizationRequest, request_builder
from app.pdp.response_parser import (
    DENY_COMPLEXITY,
    DENY_EVALUATION_ERROR,
    DENY_TIMEOUT,
    PDPDecision,
    PDPResponse,
    response_parser,
)
from app.policy.bundle_version import bundle_version_tracker

logger = get_logger(__name__)

# Default OPA query entrypoint (matches stub bundle package path)
_DEFAULT_QUERY = "data.agentpep.core.allow"


class PDPClient:
    """Policy Decision Point client.

    Async-safe: ``decide`` may be awaited from async contexts.
    Sync-safe: ``decide_sync`` is a blocking wrapper for non-async call sites.

    Usage::

        result = await pdp_client.decide(
            tool_name="bash",
            tool_args={"command": "ls /tmp"},
            agent_id="agent-abc",
            session_id="session-xyz",
        )
        if result.response.is_deny:
            raise PermissionError(result.response.reason_code)
    """

    def __init__(
        self,
        engine: OPAEngine | None = None,
        timeout_s: float | None = None,
        rego_modules: dict[str, bytes] | None = None,
        query: str = _DEFAULT_QUERY,
    ) -> None:
        """
        Args:
            engine:      OPA engine (defaults to the module-level singleton).
            timeout_s:   Per-evaluation timeout in seconds.  None → read from settings.
            rego_modules: Pre-loaded Rego source bytes.  None → uses whatever the
                          policy loader currently holds (via the global registry).
            query:       OPA query string passed to the engine.
        """
        self._engine = engine or _opa_engine
        self._timeout_s = timeout_s
        self._rego_modules: dict[str, bytes] = rego_modules or {}
        self._query = query

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def decide(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        *,
        agent_id: str = "",
        session_id: str = "",
        request_id: str = "",
        taint_level: str = "",
        trust_score: float | None = None,
        principal_chain: list[str] | None = None,
        deployment_tier: str = "",
        blast_radius_score: float | None = None,
    ) -> "PDPClientResult":
        """Evaluate a tool call authorisation request.

        Complexity gate → timeout-guarded OPA evaluation → enforcement log.
        All FAIL_CLOSED paths return a valid PDPClientResult with DENY.
        """
        start = time.monotonic()

        req = request_builder.build(
            tool_name=tool_name,
            tool_args=tool_args,
            agent_id=agent_id,
            session_id=session_id,
            request_id=request_id,
            taint_level=taint_level,
            trust_score=trust_score,
            principal_chain=principal_chain,
            deployment_tier=deployment_tier,
            blast_radius_score=blast_radius_score,
        )

        # Step 1: complexity pre-gate (sync, fast)
        complexity_result = complexity_checker.check(tool_name, tool_args)
        if not complexity_result.allowed:
            latency_ms = (time.monotonic() - start) * 1000
            response = DENY_COMPLEXITY
            entry = self._build_log_entry(req, response, latency_ms, gated=True)
            enforcement_log.record(entry)
            logger.info(
                "pdp_decision",
                decision="DENY",
                reason_code="COMPLEXITY_EXCEEDED",
                tool_name=tool_name,
                agent_id=agent_id,
                latency_ms=round(latency_ms, 2),
                gated=True,
            )
            return PDPClientResult(request=req, response=response, latency_ms=latency_ms)

        # Step 2: OPA evaluation under timeout guard
        guard = EvalTimeoutGuard(timeout_s=self._effective_timeout_s())
        raw, timed_out = await guard.run(
            self._evaluate_async(req)
        )

        latency_ms = (time.monotonic() - start) * 1000

        if timed_out:
            response = DENY_TIMEOUT
        else:
            response = response_parser.parse_or_deny(raw)

        entry = self._build_log_entry(req, response, latency_ms, gated=False)
        enforcement_log.record(entry)

        logger.info(
            "pdp_decision",
            decision=response.decision.value,
            reason_code=response.reason_code.value,
            tool_name=tool_name,
            agent_id=agent_id,
            session_id=session_id,
            bundle_version=req.bundle_version,
            latency_ms=round(latency_ms, 2),
            evaluator=response.evaluator,
        )

        return PDPClientResult(request=req, response=response, latency_ms=latency_ms)

    def decide_sync(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        **kwargs: Any,
    ) -> "PDPClientResult":
        """Blocking wrapper for non-async call sites.

        Reuses a fresh event loop to avoid conflicts with any running loop.
        """
        return asyncio.run(self.decide(tool_name, tool_args, **kwargs))

    def load_bundle(self, rego_modules: dict[str, bytes]) -> None:
        """Replace the active Rego module set.

        Called by the policy loader after a successful bundle fetch+verify.
        Thread-safe: the engine's internal lock protects concurrent evaluations.
        """
        self._rego_modules = rego_modules
        logger.info(
            "pdp_bundle_loaded",
            module_count=len(rego_modules),
            bundle_version=bundle_version_tracker.version_string,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _evaluate_async(self, req: AuthorizationRequest) -> dict[str, Any] | None:
        """Run OPA evaluation in a thread pool to avoid blocking the event loop."""
        loop = asyncio.get_event_loop()
        try:
            raw = await loop.run_in_executor(
                None,
                lambda: self._engine.evaluate(
                    rego_modules=self._rego_modules,
                    input_document=req.to_opa_input(),
                    query=self._query,
                ),
            )
            return raw
        except Exception as exc:
            logger.error("pdp_evaluation_error", error=str(exc), tool_name=req.tool_name)
            return None

    def _effective_timeout_s(self) -> float:
        if self._timeout_s is not None:
            return self._timeout_s
        try:
            from app.core.config import settings
            return settings.pdp_eval_timeout_s
        except AttributeError:
            return 5.0

    @staticmethod
    def _build_log_entry(
        req: AuthorizationRequest,
        response: PDPResponse,
        latency_ms: float,
        gated: bool,
    ) -> EnforcementLogEntry:
        return EnforcementLogEntry(
            request_id=req.request_id,
            agent_id=req.agent_id,
            session_id=req.session_id,
            tool_name=req.tool_name,
            bundle_version=req.bundle_version,
            decision=response.decision.value,
            reason_code=response.reason_code.value,
            latency_ms=round(latency_ms, 3),
            evaluator=response.evaluator,
            gated_by_complexity=gated,
            deployment_tier=req.deployment_tier,
            taint_level=req.taint_level,
            trust_score=req.trust_score,
            blast_radius_score=req.blast_radius_score,
        )


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


class PDPClientResult:
    """Outcome of a single PDP evaluation."""

    __slots__ = ("request", "response", "latency_ms")

    def __init__(
        self,
        request: AuthorizationRequest,
        response: PDPResponse,
        latency_ms: float,
    ) -> None:
        self.request = request
        self.response = response
        self.latency_ms = latency_ms

    @property
    def is_allow(self) -> bool:
        return self.response.decision == PDPDecision.ALLOW

    @property
    def is_deny(self) -> bool:
        return self.response.decision == PDPDecision.DENY

    def __repr__(self) -> str:
        return (
            f"PDPClientResult("
            f"decision={self.response.decision.value!r}, "
            f"reason={self.response.reason_code.value!r}, "
            f"latency_ms={self.latency_ms:.2f})"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------


def _build_client() -> PDPClient:
    return PDPClient()


class _LazyClient:
    _instance: PDPClient | None = None

    def __getattr__(self, name: str) -> Any:
        if self._instance is None:
            self._instance = _build_client()
        return getattr(self._instance, name)

    def reconfigure(self) -> None:
        self._instance = None


pdp_client: Any = _LazyClient()
