"""PostToolUse hook — registration, invocation, and OCSF event emission.

PostToolUse is a named hook type that fires after every tool call completes
(for both ALLOW decisions that resulted in execution and DENY decisions that
blocked execution).  Each invocation:

  1. Runs all registered hook handlers in registration order.
  2. Emits a full OCSF PostToolUse event (signed, with sequence_id).
  3. Publishes the event to the Kafka topic ``agentpep.posttooluse.events``
     within the 500 ms SLA defined in the TrustSOC integration contract.

Hook handlers are async callables that receive a ``PostToolUseContext``.
They are non-blocking — a handler exception is caught and logged but does
not prevent subsequent handlers or event emission.

Usage::

    from app.hooks.post_tool_use import post_tool_use_registry, PostToolUseContext

    # Register a handler
    @post_tool_use_registry.register
    async def my_handler(ctx: PostToolUseContext) -> None:
        ...

    # Invoke from the intercept pipeline after tool execution
    await post_tool_use_registry.invoke(ctx)

Sprint S-E07 (E07-T01)
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from app.core.structured_logging import get_logger
from app.events.post_tool_use_event import (
    OUTCOME_DENIED,
    OUTCOME_ERROR,
    OUTCOME_EXECUTED,
    OUTCOME_TIMEOUT,
    emit_post_tool_use_event,
)

logger = get_logger(__name__)

# Type alias for hook handler functions
PostToolUseHandler = Callable[["PostToolUseContext"], Awaitable[None]]


@dataclass
class PostToolUseContext:
    """Context object passed to every PostToolUse hook handler.

    Attributes:
        request_id:           ToolCallRequest.request_id — sequence_id for event correlation.
        session_id:           Session identifier.
        agent_id:             Agent that invoked the tool.
        tool_name:            Name of the tool.
        tool_outcome:         EXECUTED | DENIED | ERROR | TIMEOUT.
        decision:             Policy decision string (ALLOW, DENY, MODIFY, …).
        risk_score:           Risk score from policy evaluation [0.0, 1.0].
        taint_flags:          Taint flags from the PolicyDecisionResponse.
        matched_rule_id:      Rule that produced the decision (str or None).
        latency_ms:           PreToolUse evaluation latency in milliseconds.
        delegation_chain:     Principal chain from root to current agent.
        tenant_id:            Tenant identifier.
        bundle_version:       AAPM policy bundle version active at decision time.
        tool_result_summary:  Redacted/summarised tool output (EXECUTED only).
        tool_result_error:    Error message when outcome is ERROR.
        pre_decision_time_ms: Epoch ms when the PreToolUse decision was made.
        blast_radius_score:   AAPM blast radius score (null placeholder until S-E08).
        extra:                Extensible bag for handler-specific metadata.
    """

    request_id: str
    session_id: str
    agent_id: str
    tool_name: str
    tool_outcome: str
    decision: str
    risk_score: float = 0.0
    taint_flags: list[str] = field(default_factory=list)
    matched_rule_id: str | None = None
    latency_ms: int = 0
    delegation_chain: list[str] = field(default_factory=list)
    tenant_id: str = "default"
    bundle_version: str = ""
    tool_result_summary: str | None = None
    tool_result_error: str | None = None
    pre_decision_time_ms: int = 0
    blast_radius_score: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_allow(
        cls,
        *,
        request_id: str,
        session_id: str,
        agent_id: str,
        tool_name: str,
        latency_ms: int = 0,
        risk_score: float = 0.0,
        taint_flags: list[str] | None = None,
        matched_rule_id: str | None = None,
        delegation_chain: list[str] | None = None,
        tenant_id: str = "default",
        bundle_version: str = "",
        tool_result_summary: str | None = None,
        pre_decision_time_ms: int = 0,
        blast_radius_score: float | None = None,
    ) -> "PostToolUseContext":
        """Construct a context for an ALLOW decision that resulted in execution."""
        return cls(
            request_id=request_id,
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
            latency_ms=latency_ms,
            risk_score=risk_score,
            taint_flags=taint_flags or [],
            matched_rule_id=matched_rule_id,
            delegation_chain=delegation_chain or [],
            tenant_id=tenant_id,
            bundle_version=bundle_version,
            tool_result_summary=tool_result_summary,
            pre_decision_time_ms=pre_decision_time_ms,
            blast_radius_score=blast_radius_score,
        )

    @classmethod
    def from_deny(
        cls,
        *,
        request_id: str,
        session_id: str,
        agent_id: str,
        tool_name: str,
        latency_ms: int = 0,
        risk_score: float = 0.0,
        taint_flags: list[str] | None = None,
        matched_rule_id: str | None = None,
        delegation_chain: list[str] | None = None,
        tenant_id: str = "default",
        bundle_version: str = "",
        pre_decision_time_ms: int = 0,
        blast_radius_score: float | None = None,
    ) -> "PostToolUseContext":
        """Construct a context for a DENY decision (no tool execution)."""
        return cls(
            request_id=request_id,
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_outcome=OUTCOME_DENIED,
            decision="DENY",
            latency_ms=latency_ms,
            risk_score=risk_score,
            taint_flags=taint_flags or [],
            matched_rule_id=matched_rule_id,
            delegation_chain=delegation_chain or [],
            tenant_id=tenant_id,
            bundle_version=bundle_version,
            pre_decision_time_ms=pre_decision_time_ms,
            blast_radius_score=blast_radius_score,
        )

    @classmethod
    def from_error(
        cls,
        *,
        request_id: str,
        session_id: str,
        agent_id: str,
        tool_name: str,
        error_message: str,
        latency_ms: int = 0,
        risk_score: float = 0.0,
        taint_flags: list[str] | None = None,
        matched_rule_id: str | None = None,
        tenant_id: str = "default",
        bundle_version: str = "",
        blast_radius_score: float | None = None,
    ) -> "PostToolUseContext":
        """Construct a context for an ALLOW decision where the tool raised an error."""
        return cls(
            request_id=request_id,
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_outcome=OUTCOME_ERROR,
            decision="ALLOW",
            latency_ms=latency_ms,
            risk_score=risk_score,
            taint_flags=taint_flags or [],
            matched_rule_id=matched_rule_id,
            tenant_id=tenant_id,
            bundle_version=bundle_version,
            tool_result_error=error_message,
            blast_radius_score=blast_radius_score,
        )


class PostToolUseHookRegistry:
    """Registry that manages PostToolUse hook handlers.

    Thread-safe registration; handlers are invoked in registration order.
    """

    def __init__(self) -> None:
        self._handlers: list[PostToolUseHandler] = []

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, handler: PostToolUseHandler) -> PostToolUseHandler:
        """Register a hook handler.  Can be used as a decorator.

        Returns the handler unchanged so it can also be called with
        ``@post_tool_use_registry.register``.
        """
        self._handlers.append(handler)
        logger.debug("posttooluse_handler_registered", handler=handler.__name__)
        return handler

    def unregister(self, handler: PostToolUseHandler) -> None:
        """Remove a previously registered handler.  No-op if not registered."""
        try:
            self._handlers.remove(handler)
        except ValueError:
            pass

    @property
    def handler_count(self) -> int:
        return len(self._handlers)

    # ------------------------------------------------------------------
    # Invocation
    # ------------------------------------------------------------------

    async def invoke(self, ctx: PostToolUseContext) -> dict[str, Any]:
        """Invoke all registered handlers then emit and publish the OCSF event.

        Handler exceptions are caught and logged — they never suppress the
        OCSF event emission or Kafka publication.

        Returns the emitted OCSF event dict.
        """
        invoke_start = time.monotonic()

        # 1. Run registered handlers
        for handler in self._handlers:
            try:
                await handler(ctx)
            except Exception:
                logger.exception(
                    "posttooluse_handler_error",
                    handler=handler.__name__,
                    tool_name=ctx.tool_name,
                    session_id=ctx.session_id,
                )

        # 2. Emit OCSF event (synchronous build + sign + log)
        event = emit_post_tool_use_event(
            request_id=ctx.request_id,
            session_id=ctx.session_id,
            agent_id=ctx.agent_id,
            tool_name=ctx.tool_name,
            tool_outcome=ctx.tool_outcome,
            decision=ctx.decision,
            risk_score=ctx.risk_score,
            taint_flags=ctx.taint_flags,
            matched_rule_id=ctx.matched_rule_id,
            latency_ms=ctx.latency_ms,
            delegation_chain=ctx.delegation_chain,
            tenant_id=ctx.tenant_id,
            bundle_version=ctx.bundle_version,
            tool_result_summary=ctx.tool_result_summary,
            tool_result_error=ctx.tool_result_error,
            pre_decision_time_ms=ctx.pre_decision_time_ms,
            blast_radius_score=ctx.blast_radius_score,
        )

        # 3. Publish to Kafka (non-blocking — failure never raises)
        await _publish_to_kafka(event)

        elapsed_ms = int((time.monotonic() - invoke_start) * 1000)
        logger.debug(
            "posttooluse_invocation_complete",
            tool_name=ctx.tool_name,
            tool_outcome=ctx.tool_outcome,
            elapsed_ms=elapsed_ms,
            handlers_run=len(self._handlers),
        )

        return event


async def _publish_to_kafka(event: dict[str, Any]) -> None:
    """Publish a PostToolUse event to Kafka.  Failures are logged, never raised."""
    try:
        from app.services.kafka_producer import kafka_producer

        await kafka_producer.publish_posttooluse_event(event)
    except Exception:
        logger.exception(
            "posttooluse_kafka_publish_error",
            event_id=event.get("finding_info", {}).get("uid", ""),
        )


# ---------------------------------------------------------------------------
# Module-level singleton used by the intercept pipeline
# ---------------------------------------------------------------------------

post_tool_use_registry = PostToolUseHookRegistry()
