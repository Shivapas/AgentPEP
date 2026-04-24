"""Evaluation timeout guard — Evaluation Guarantee Invariant enforcement.

Wraps any async evaluation coroutine with a hard timeout.  On timeout the
guard unconditionally returns DENY.  Unlike the policy evaluator's adaptive
timeout (which supports FAIL_OPEN), this guard has no permissive fallback —
the DENY outcome is hardcoded per the Evaluation Guarantee Invariant.

Sprint S-E02 (E02-T03)
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable, Coroutine, TypeVar

from app.core.structured_logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class EvalTimeoutGuard:
    """Wraps an evaluation coroutine with a hard timeout that DENIES on expiry.

    Usage::

        guard = EvalTimeoutGuard(timeout_s=2.0)
        result, timed_out = await guard.run(my_coroutine(...))
        if timed_out:
            # caller must treat this as DENY
            ...
    """

    def __init__(self, timeout_s: float) -> None:
        if timeout_s <= 0:
            raise ValueError(f"timeout_s must be positive, got {timeout_s}")
        self._timeout_s = timeout_s

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        coro: Coroutine[Any, Any, T],
    ) -> tuple[T | None, bool]:
        """Run *coro* under the configured timeout.

        Returns ``(result, timed_out)``.

        - If the coroutine completes within the deadline, returns
          ``(result, False)``.
        - If it times out, logs a warning and returns ``(None, True)``.
          Callers **must** treat ``timed_out=True`` as a DENY decision
          (Evaluation Guarantee Invariant).
        """
        start = time.monotonic()
        try:
            result = await asyncio.wait_for(coro, timeout=self._timeout_s)
            return result, False
        except TimeoutError:
            elapsed = time.monotonic() - start
            logger.warning(
                "eval_timeout_triggered",
                timeout_s=self._timeout_s,
                elapsed_s=round(elapsed, 4),
                decision="DENY",
                invariant="EvaluationGuarantee",
            )
            emit_timeout_event(
                timeout_s=self._timeout_s,
                elapsed_s=elapsed,
            )
            return None, True

    async def run_or_deny(
        self,
        coro: Coroutine[Any, Any, T],
        deny_factory: Callable[[], T],
    ) -> T:
        """Run *coro*; return ``deny_factory()`` result on timeout.

        Convenience wrapper when the caller wants a ready-to-use deny value
        rather than checking the ``timed_out`` flag manually.
        """
        result, timed_out = await self.run(coro)
        if timed_out:
            return deny_factory()
        assert result is not None
        return result


# ---------------------------------------------------------------------------
# Timeout event — stub (formalised in Sprint S-E07)
# ---------------------------------------------------------------------------


def emit_timeout_event(
    timeout_s: float,
    elapsed_s: float,
    session_id: str = "",
    agent_id: str = "",
    tool_name: str = "",
) -> dict[str, Any]:
    """Emit an EVAL_TIMEOUT event (stub — formalised in S-E07).

    Returns the event dict for testing.
    """
    import time as _time

    event: dict[str, Any] = {
        "class_uid": 4003,
        "class_name": "EVAL_TIMEOUT",
        "category_uid": 4,
        "category_name": "FINDINGS",
        "activity_id": 2,
        "activity_name": "DENY",
        "severity_id": 3,
        "severity": "HIGH",
        "time": int(_time.time() * 1000),
        "metadata": {
            "version": "1.0.0",
            "product": {"name": "AgentPEP", "vendor_name": "TrustFabric"},
            "event_code": "EVAL_TIMEOUT",
        },
        "actor": {"agent_id": agent_id, "session_id": session_id},
        "resources": [{"type": "tool_call", "name": tool_name}],
        "finding_info": {
            "title": "Evaluation timeout — request denied (Evaluation Guarantee Invariant)",
            "timeout_s": timeout_s,
            "elapsed_s": round(elapsed_s, 4),
        },
        "decision": "DENY",
        "evaluation_guarantee_invariant": True,
    }

    logger.info(
        "EVAL_TIMEOUT",
        event_class="EVAL_TIMEOUT",
        session_id=session_id,
        agent_id=agent_id,
        tool_name=tool_name,
        timeout_s=timeout_s,
        elapsed_s=round(elapsed_s, 4),
    )

    return event


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------


def _build_guard() -> EvalTimeoutGuard:
    from app.core.config import settings

    return EvalTimeoutGuard(timeout_s=settings.complexity_budget_eval_timeout_s)


class _LazyGuard:
    _instance: EvalTimeoutGuard | None = None

    async def run(self, coro: Coroutine[Any, Any, T]) -> tuple[T | None, bool]:
        if self._instance is None:
            self._instance = _build_guard()
        return await self._instance.run(coro)

    async def run_or_deny(
        self,
        coro: Coroutine[Any, Any, T],
        deny_factory: Callable[[], T],
    ) -> T:
        if self._instance is None:
            self._instance = _build_guard()
        return await self._instance.run_or_deny(coro, deny_factory)

    def reconfigure(self) -> None:
        self._instance = None


eval_timeout_guard = _LazyGuard()
