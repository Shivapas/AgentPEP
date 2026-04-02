"""LangGraph node pre-execution hook for AgentPEP (APEP-034).

Provides a hook function that can be inserted before any LangGraph node
to enforce AgentPEP policy on tool calls within the graph.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from agentpep.client import AgentPEPClient
from agentpep.exceptions import PolicyDeniedError
from agentpep.models import PolicyDecision

logger = logging.getLogger(__name__)


def agentpep_pre_hook(
    client: AgentPEPClient,
    *,
    agent_id: str,
    session_id: str = "default",
    tool_name: str | None = None,
) -> Callable[..., Any]:
    """Create a LangGraph pre-execution hook that enforces AgentPEP policy.

    Returns a function compatible with LangGraph's node interface. The hook
    evaluates the policy and raises ``PolicyDeniedError`` if the decision
    is not ALLOW.

    Args:
        client: An ``AgentPEPClient`` instance.
        agent_id: The agent identifier for policy evaluation.
        session_id: Session identifier.
        tool_name: Override tool name (defaults to extracting from state).

    Usage with LangGraph::

        from langgraph.graph import StateGraph
        from agentpep import AgentPEPClient
        from agentpep.integrations.langgraph import agentpep_pre_hook

        client = AgentPEPClient(base_url="http://localhost:8000")

        graph = StateGraph(State)
        graph.add_node("check_policy", agentpep_pre_hook(
            client, agent_id="lg-agent", tool_name="send_email"
        ))
        graph.add_node("send_email", send_email_node)
        graph.add_edge("check_policy", "send_email")
    """

    async def hook(state: dict[str, Any]) -> dict[str, Any]:
        resolved_name = tool_name or state.get("tool_name", "unknown")
        tool_args = state.get("tool_args", {})

        response = await client.evaluate(
            agent_id=agent_id,
            tool_name=resolved_name,
            tool_args=tool_args,
            session_id=session_id,
        )

        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=resolved_name,
                reason=response.reason,
                decision=response.decision.value,
            )

        return {
            **state,
            "agentpep_decision": response.decision.value,
            "agentpep_risk_score": response.risk_score,
        }

    return hook


def enforce_tool_node(
    client: AgentPEPClient,
    *,
    agent_id: str,
    session_id: str = "default",
) -> Callable[..., Any]:
    """Create a wrapper that enforces policy on LangGraph ToolNode messages.

    This is designed to wrap a ToolNode and inspect the tool call messages
    in the state before execution.

    Args:
        client: An ``AgentPEPClient`` instance.
        agent_id: The agent identifier for policy evaluation.
        session_id: Session identifier.

    Usage::

        from agentpep.integrations.langgraph import enforce_tool_node

        tool_guard = enforce_tool_node(client, agent_id="lg-agent")
        # Use as a pre-check node before the actual ToolNode
    """

    async def guard(state: dict[str, Any]) -> dict[str, Any]:
        messages = state.get("messages", [])
        if not messages:
            return state

        last_msg = messages[-1]

        # Extract tool calls from AIMessage (LangGraph convention)
        tool_calls = getattr(last_msg, "tool_calls", None) or []
        for tc in tool_calls:
            tc_name = tc.get("name", tc.get("function", {}).get("name", "unknown"))
            tc_args = tc.get("args", tc.get("function", {}).get("arguments", {}))

            response = await client.evaluate(
                agent_id=agent_id,
                tool_name=tc_name,
                tool_args=tc_args if isinstance(tc_args, dict) else {},
                session_id=session_id,
            )

            if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
                raise PolicyDeniedError(
                    tool_name=tc_name,
                    reason=response.reason,
                    decision=response.decision.value,
                )

        return state

    return guard
