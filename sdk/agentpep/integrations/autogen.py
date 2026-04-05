"""AutoGen / AutoGen Studio integration for AgentPEP (APEP-161, APEP-162).

Provides:
- ``AgentPEPSpeakerHook``: intercepts tool calls before each AutoGen speaker
  produces output, enforcing AgentPEP policy.
- ``AgentPEPStudioPlugin``: wrapper for AutoGen Studio that registers the
  hook as a plugin component.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from agentpep.exceptions import PolicyDeniedError
from agentpep.models import PolicyDecision, PolicyDecisionResponse

logger = logging.getLogger(__name__)

try:
    from autogen import ConversableAgent

    _HAS_AUTOGEN = True
except ImportError:  # pragma: no cover
    _HAS_AUTOGEN = False


def _check_autogen() -> None:
    if not _HAS_AUTOGEN:
        raise ImportError(
            "AutoGen integration requires pyautogen. "
            "Install with: pip install agentpep-sdk[autogen]"
        )


def map_autogen_tool_call(
    message: dict[str, Any],
) -> list[tuple[str, dict[str, Any]]]:
    """Extract tool calls from an AutoGen message.

    AutoGen messages may contain tool calls in several formats:
    - ``function_call``: legacy single function call
    - ``tool_calls``: list of tool call objects (OpenAI-style)

    Args:
        message: The AutoGen message dict.

    Returns:
        List of ``(tool_name, tool_args)`` tuples.
    """
    results: list[tuple[str, dict[str, Any]]] = []

    # OpenAI-style tool_calls list
    tool_calls = message.get("tool_calls", [])
    for tc in tool_calls:
        func = tc.get("function", {})
        name = func.get("name", "unknown")
        raw_args = func.get("arguments", "{}")
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args) if raw_args else {}
            except (json.JSONDecodeError, TypeError):
                args = {"raw_input": raw_args}
        elif isinstance(raw_args, dict):
            args = raw_args
        else:
            args = {}
        results.append((name, args))

    # Legacy function_call format
    func_call = message.get("function_call")
    if func_call and not tool_calls:
        name = func_call.get("name", "unknown")
        raw_args = func_call.get("arguments", "{}")
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args) if raw_args else {}
            except (json.JSONDecodeError, TypeError):
                args = {"raw_input": raw_args}
        elif isinstance(raw_args, dict):
            args = raw_args
        else:
            args = {}
        results.append((name, args))

    return results


class AgentPEPSpeakerHook:
    """AutoGen speaker hook that enforces AgentPEP policy on tool calls.

    Intercepts messages before each speaker (agent) produces output. If the
    message contains tool calls, each is evaluated against AgentPEP policy.

    This is designed to be used as a ``hook_list`` entry or called directly
    within a custom speaker selection function.

    Args:
        client: An ``AgentPEPClient`` instance.
        agent_id_fn: Callable that extracts the agent_id from the speaking agent.
            Defaults to using the agent's ``name`` attribute.
        session_id: Session identifier (default ``"default"``).
        delegation_chain_fn: Optional callable that returns the delegation chain
            for the current conversation context.

    Example::

        from agentpep import AgentPEPClient
        from agentpep.integrations.autogen import AgentPEPSpeakerHook

        client = AgentPEPClient(base_url="http://localhost:8000")
        hook = AgentPEPSpeakerHook(client=client)

        # Register as a reply function on an AutoGen agent
        agent.register_reply(
            trigger=autogen.Agent,
            reply_func=hook.intercept_reply,
            position=0,  # Run before other reply functions
        )
    """

    def __init__(
        self,
        client: Any,  # AgentPEPClient
        *,
        agent_id_fn: Callable[[Any], str] | None = None,
        session_id: str = "default",
        delegation_chain_fn: Callable[[], list[str]] | None = None,
    ) -> None:
        self.client = client
        self.agent_id_fn = agent_id_fn or (lambda agent: getattr(agent, "name", "unknown"))
        self.session_id = session_id
        self.delegation_chain_fn = delegation_chain_fn

    def _get_delegation_chain(self) -> list[str]:
        if self.delegation_chain_fn:
            return self.delegation_chain_fn()
        return []

    async def check_message(
        self,
        speaker: Any,
        message: dict[str, Any],
    ) -> list[PolicyDecisionResponse]:
        """Evaluate all tool calls in a message against AgentPEP policy.

        Args:
            speaker: The AutoGen agent producing the message.
            message: The message dict containing potential tool calls.

        Returns:
            List of ``PolicyDecisionResponse`` for each tool call checked.

        Raises:
            PolicyDeniedError: If any tool call is denied by policy.
        """
        tool_calls = map_autogen_tool_call(message)
        if not tool_calls:
            return []

        agent_id = self.agent_id_fn(speaker)
        delegation_chain = self._get_delegation_chain()
        responses: list[PolicyDecisionResponse] = []

        for tool_name, tool_args in tool_calls:
            response = await self.client.evaluate(
                agent_id=agent_id,
                tool_name=tool_name,
                tool_args=tool_args,
                session_id=self.session_id,
                delegation_chain=delegation_chain,
            )
            responses.append(response)

            if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
                raise PolicyDeniedError(
                    tool_name=tool_name,
                    reason=response.reason,
                    decision=response.decision.value,
                )

        return responses

    def check_message_sync(
        self,
        speaker: Any,
        message: dict[str, Any],
    ) -> list[PolicyDecisionResponse]:
        """Sync version of ``check_message``."""
        tool_calls = map_autogen_tool_call(message)
        if not tool_calls:
            return []

        agent_id = self.agent_id_fn(speaker)
        delegation_chain = self._get_delegation_chain()
        responses: list[PolicyDecisionResponse] = []

        for tool_name, tool_args in tool_calls:
            response = self.client.evaluate_sync(
                agent_id=agent_id,
                tool_name=tool_name,
                tool_args=tool_args,
                session_id=self.session_id,
                delegation_chain=delegation_chain,
            )
            responses.append(response)

            if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
                raise PolicyDeniedError(
                    tool_name=tool_name,
                    reason=response.reason,
                    decision=response.decision.value,
                )

        return responses

    async def intercept_reply(
        self,
        recipient: Any,
        messages: list[dict[str, Any]] | None = None,
        sender: Any | None = None,
        config: Any | None = None,
    ) -> tuple[bool, None]:
        """AutoGen reply function that intercepts tool calls before execution.

        Register this with ``agent.register_reply()`` at position 0 to run
        before other reply functions. Returns ``(True, None)`` to indicate
        the hook has been processed (but does not replace the actual reply).

        Raises:
            PolicyDeniedError: If the latest message contains a denied tool call.
        """
        if messages:
            last_message = messages[-1]
            await self.check_message(
                speaker=sender or recipient,
                message=last_message,
            )
        # Return (False, None) to allow the normal reply flow to continue
        return False, None


class AgentPEPStudioPlugin:
    """AutoGen Studio plugin wrapper for AgentPEP (APEP-162).

    Provides an interface compatible with AutoGen Studio's plugin system.
    Wraps ``AgentPEPSpeakerHook`` and exposes configuration via Studio-friendly
    metadata.

    Args:
        client: An ``AgentPEPClient`` instance.
        session_id: Session identifier (default ``"default"``).
        agent_id_fn: Optional callable to derive agent_id from AutoGen agent.
        delegation_chain_fn: Optional callable returning the current delegation chain.

    Example::

        from agentpep import AgentPEPClient
        from agentpep.integrations.autogen import AgentPEPStudioPlugin

        client = AgentPEPClient(base_url="http://localhost:8000")
        plugin = AgentPEPStudioPlugin(client=client)

        # Register with AutoGen Studio workflow
        plugin.register_agents(agent_list)
    """

    # Studio plugin metadata
    name: str = "AgentPEP Policy Enforcement"
    description: str = (
        "Enforces deterministic RBAC, taint tracking, and confused-deputy "
        "detection on all tool calls in AutoGen workflows."
    )
    version: str = "0.1.0"

    def __init__(
        self,
        client: Any,  # AgentPEPClient
        *,
        session_id: str = "default",
        agent_id_fn: Callable[[Any], str] | None = None,
        delegation_chain_fn: Callable[[], list[str]] | None = None,
    ) -> None:
        self.client = client
        self.hook = AgentPEPSpeakerHook(
            client=client,
            agent_id_fn=agent_id_fn,
            session_id=session_id,
            delegation_chain_fn=delegation_chain_fn,
        )
        self.session_id = session_id
        self._registered_agents: list[str] = []

    def register_agent(self, agent: Any) -> None:
        """Register the AgentPEP hook on a single AutoGen agent.

        Calls ``agent.register_reply()`` to insert the policy hook before
        other reply functions.
        """
        agent_name = getattr(agent, "name", "unknown")

        if hasattr(agent, "register_reply"):
            agent.register_reply(
                trigger=lambda _sender: True,
                reply_func=self.hook.intercept_reply,
                position=0,
            )
            self._registered_agents.append(agent_name)
            logger.info("AgentPEP hook registered on agent: %s", agent_name)
        else:
            logger.warning(
                "Agent '%s' does not support register_reply; skipping hook registration",
                agent_name,
            )

    def register_agents(self, agents: list[Any]) -> None:
        """Register the AgentPEP hook on a list of AutoGen agents."""
        for agent in agents:
            self.register_agent(agent)

    @property
    def registered_agents(self) -> list[str]:
        """Return names of agents where the hook has been registered."""
        return list(self._registered_agents)

    async def evaluate_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        delegation_chain: list[str] | None = None,
    ) -> PolicyDecisionResponse:
        """Manually evaluate a tool call via the plugin.

        Useful for Studio workflows that need explicit policy checks
        outside the normal reply flow.
        """
        return await self.client.evaluate(
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=tool_args or {},
            session_id=self.session_id,
            delegation_chain=delegation_chain or [],
        )
