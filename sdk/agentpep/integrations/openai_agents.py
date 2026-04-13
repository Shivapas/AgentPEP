"""OpenAI Agents SDK integration for AgentPEP (APEP-158, APEP-159, APEP-259).

Provides a pre-execution callback hook that intercepts tool calls made by
OpenAI Agents SDK agents and enforces AgentPEP policy before the tool runs.

Sprint 33 — APEP-259: Execution token validation, receipt attachment,
DEFER/MODIFY decision handling.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from agentpep.exceptions import PolicyDeferredError, PolicyDeniedError
from agentpep.execution_token import execution_token_validator
from agentpep.models import PolicyDecision, PolicyDecisionResponse

logger = logging.getLogger(__name__)

try:
    from agents import Agent, RunContextWrapper, Tool, FunctionTool
    from agents.lifecycle import AgentHooks

    _HAS_OPENAI_AGENTS = True
except ImportError:  # pragma: no cover
    _HAS_OPENAI_AGENTS = False


def _check_openai_agents() -> None:
    if not _HAS_OPENAI_AGENTS:
        raise ImportError(
            "OpenAI Agents SDK integration requires the openai-agents package. "
            "Install with: pip install agentpep-sdk[openai-agents]"
        )


def map_openai_tool_call(
    tool: Any,
    call_args: str | dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Map an OpenAI Agents SDK tool call to AgentPEP (tool_name, tool_args).

    Handles both ``FunctionTool`` (with ``name`` attribute) and generic tools.
    The ``call_args`` may be a JSON string (as returned by the model) or an
    already-parsed dict.

    Args:
        tool: The OpenAI Agents SDK tool instance.
        call_args: The raw arguments from the tool call (JSON string or dict).

    Returns:
        A ``(tool_name, tool_args)`` tuple suitable for ``ToolCallRequest``.
    """
    # Extract tool name
    tool_name: str = getattr(tool, "name", None) or type(tool).__name__

    # Parse arguments
    if isinstance(call_args, str):
        try:
            parsed_args: dict[str, Any] = json.loads(call_args) if call_args else {}
        except (json.JSONDecodeError, TypeError):
            parsed_args = {"raw_input": call_args}
    elif isinstance(call_args, dict):
        parsed_args = call_args
    else:
        parsed_args = {"raw_input": str(call_args)}

    return tool_name, parsed_args


class AgentPEPHooks:
    """OpenAI Agents SDK lifecycle hooks with AgentPEP policy enforcement.

    Implements the ``AgentHooks`` protocol from the OpenAI Agents SDK to
    intercept tool calls before execution.

    Sprint 33 — APEP-259 enhancements:
    - Validates execution tokens on ALLOW decisions
    - Stores receipts for audit trail
    - Handles DEFER decisions (raises ``PolicyDeferredError``)
    - Handles MODIFY decisions (stores modified args for framework use)

    Args:
        client: An ``AgentPEPClient`` instance.
        agent_id: The agent identifier for policy evaluation.
        session_id: Session identifier (default ``"default"``).
        delegation_chain: Optional delegation chain for confused-deputy detection.
        on_decision: Optional callback invoked with each ``PolicyDecisionResponse``.

    Example::

        from agents import Agent
        from agentpep import AgentPEPClient
        from agentpep.integrations.openai_agents import AgentPEPHooks

        client = AgentPEPClient(base_url="http://localhost:8000")
        hooks = AgentPEPHooks(client=client, agent_id="openai-agent")

        agent = Agent(
            name="my-agent",
            instructions="You are a helpful assistant.",
            hooks=hooks,
        )
    """

    def __init__(
        self,
        client: Any,  # AgentPEPClient
        *,
        agent_id: str,
        session_id: str = "default",
        delegation_chain: list[str] | None = None,
        on_decision: Callable[[PolicyDecisionResponse], None] | None = None,
    ) -> None:
        self.client = client
        self.agent_id = agent_id
        self.session_id = session_id
        self.delegation_chain = delegation_chain or []
        self.on_decision = on_decision
        # Sprint 33 — APEP-259: Track receipts and modified args
        self._last_receipt: str | None = None
        self._pending_modified_args: dict[str, Any] | None = None

    async def on_tool_start(
        self,
        context: Any,
        agent: Any,
        tool: Any,
    ) -> None:
        """Pre-execution hook: evaluate policy before the tool runs.

        Called by the OpenAI Agents SDK runner before each tool invocation.

        Sprint 33 — APEP-259 behaviour:
        - ALLOW/DRY_RUN: validates execution token, stores receipt, proceeds
        - DEFER: raises ``PolicyDeferredError`` with timeout info
        - MODIFY: stores ``modified_args`` for the framework to use
        - Other decisions: raises ``PolicyDeniedError``
        """
        # Extract tool name from the tool object
        tool_name = getattr(tool, "name", None) or type(tool).__name__

        # Try to extract arguments from context if available
        tool_args: dict[str, Any] = {}
        if hasattr(context, "tool_input"):
            _, tool_args = map_openai_tool_call(tool, context.tool_input)
        elif hasattr(context, "tool_args"):
            _, tool_args = map_openai_tool_call(tool, context.tool_args)

        response = await self.client.evaluate(
            agent_id=self.agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
            session_id=self.session_id,
            delegation_chain=self.delegation_chain,
        )

        if self.on_decision:
            self.on_decision(response)

        # APEP-259: Handle DEFER — suspend execution pending review
        if response.decision == PolicyDecision.DEFER:
            raise PolicyDeferredError(
                tool_name=tool_name,
                reason=response.reason,
                defer_timeout_s=response.defer_timeout_s,
            )

        # APEP-259: Handle MODIFY — store rewritten args for framework use
        if response.decision == PolicyDecision.MODIFY:
            self._pending_modified_args = response.modified_args
            logger.info(
                "Tool args modified by policy for tool=%s agent=%s",
                tool_name,
                self.agent_id,
            )
            return

        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=tool_name,
                reason=response.reason,
                decision=response.decision.value,
            )

        # APEP-259: Validate execution token on ALLOW
        if response.execution_token is not None:
            execution_token_validator.validate_and_consume(
                response.execution_token,
                expected_tool_name=tool_name,
                expected_agent_id=self.agent_id,
            )

        # APEP-259: Store receipt for audit trail
        if response.receipt is not None:
            self._last_receipt = response.receipt

    async def on_tool_end(
        self,
        context: Any,
        agent: Any,
        tool: Any,
        result: str,
    ) -> None:
        """Post-execution hook: attach receipt to result metadata if available."""
        if self._last_receipt is not None:
            if hasattr(context, "agentpep_receipt"):
                context.agentpep_receipt = self._last_receipt
            self._last_receipt = None
        # Clear pending modified args after tool execution
        self._pending_modified_args = None

    async def on_start(self, context: Any, agent: Any) -> None:
        """Agent start hook (no-op)."""

    async def on_end(self, context: Any, agent: Any, output: Any) -> None:
        """Agent end hook (no-op)."""

    async def on_handoff(self, context: Any, agent: Any, source: Any) -> None:
        """Agent handoff hook (no-op)."""


def enforce_tool(
    client: Any,
    *,
    agent_id: str,
    session_id: str = "default",
    delegation_chain: list[str] | None = None,
) -> Callable[..., Any]:
    """Create a pre-execution guard for a single OpenAI Agents SDK tool call.

    Returns an async callable that evaluates AgentPEP policy for the given
    tool name and arguments. Suitable for use in custom agent runners.

    Sprint 33 — APEP-259: Handles DEFER (raises ``PolicyDeferredError``)
    and MODIFY (returns response with ``modified_args``).

    Args:
        client: An ``AgentPEPClient`` instance.
        agent_id: The agent identifier for policy evaluation.
        session_id: Session identifier.
        delegation_chain: Optional delegation chain.

    Usage::

        guard = enforce_tool(client, agent_id="my-agent")
        await guard(tool_name="send_email", tool_args={"to": "user@example.com"})
    """

    async def guard(
        tool_name: str,
        tool_args: str | dict[str, Any] | None = None,
    ) -> PolicyDecisionResponse:
        name, args = map_openai_tool_call(
            type("_Stub", (), {"name": tool_name})(),
            tool_args or {},
        )
        response = await client.evaluate(
            agent_id=agent_id,
            tool_name=name,
            tool_args=args,
            session_id=session_id,
            delegation_chain=delegation_chain or [],
        )

        # APEP-259: Handle DEFER
        if response.decision == PolicyDecision.DEFER:
            raise PolicyDeferredError(
                tool_name=name,
                reason=response.reason,
                defer_timeout_s=response.defer_timeout_s,
            )

        # APEP-259: Handle MODIFY — return response (caller inspects modified_args)
        if response.decision == PolicyDecision.MODIFY:
            return response

        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=name,
                reason=response.reason,
                decision=response.decision.value,
            )
        return response

    return guard
