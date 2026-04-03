"""CrewAI integration for AgentPEP (APEP-165, APEP-166).

Provides a tool wrapper that intercepts CrewAI ``BaseTool.run()`` calls
with AgentPEP policy enforcement, and a role-mapping helper that maps
CrewAI agent roles to AgentPEP policy roles.
"""

from __future__ import annotations

import logging
from typing import Any

from agentpep.exceptions import PolicyDeniedError
from agentpep.models import PolicyDecision

logger = logging.getLogger(__name__)

try:
    from crewai.tools import BaseTool as CrewAIBaseTool

    _HAS_CREWAI = True
except ImportError:  # pragma: no cover
    CrewAIBaseTool = None  # type: ignore[assignment,misc]
    _HAS_CREWAI = False


def _check_crewai() -> None:
    if not _HAS_CREWAI:
        raise ImportError(
            "CrewAI integration requires crewai. "
            "Install with: pip install agentpep-sdk[crewai]"
        )


# ---------------------------------------------------------------------------
# APEP-166 — Role mapping configuration
# ---------------------------------------------------------------------------


class CrewAIRoleMapping:
    """Maps CrewAI agent roles to AgentPEP policy roles.

    In a multi-agent CrewAI crew, each agent has a ``role`` string
    (e.g. ``"Researcher"``, ``"Writer"``).  This class maps those
    human-readable roles to AgentPEP policy role identifiers so that
    different crew members can be governed by different policies.

    Args:
        role_map: Dictionary mapping CrewAI role strings to AgentPEP role IDs.
        default_role: Fallback AgentPEP role when no mapping is found.

    Example::

        mapping = CrewAIRoleMapping(
            role_map={
                "Researcher": "crewai-researcher",
                "Writer": "crewai-writer",
            },
            default_role="crewai-default",
        )
        agentpep_role = mapping.resolve("Researcher")
        # => "crewai-researcher"
    """

    def __init__(
        self,
        role_map: dict[str, str] | None = None,
        default_role: str = "crewai-default",
    ) -> None:
        self._role_map: dict[str, str] = role_map or {}
        self.default_role = default_role

    def resolve(self, crewai_role: str) -> str:
        """Return the AgentPEP role for the given CrewAI role string."""
        return self._role_map.get(crewai_role, self.default_role)

    def register(self, crewai_role: str, agentpep_role: str) -> None:
        """Add or update a role mapping entry."""
        self._role_map[crewai_role] = agentpep_role

    @property
    def mappings(self) -> dict[str, str]:
        """Return a copy of the current role map."""
        return dict(self._role_map)


# ---------------------------------------------------------------------------
# APEP-165 — Task execution interceptor
# ---------------------------------------------------------------------------


class AgentPEPCrewAITool:
    """CrewAI tool wrapper that enforces AgentPEP policy before execution.

    Wraps an existing CrewAI ``BaseTool`` and calls the AgentPEP Intercept
    API before delegating to the wrapped tool's ``_run`` method.  This class
    acts as a drop-in replacement: it forwards ``name``, ``description``, and
    ``args_schema`` from the wrapped tool.

    Args:
        wrapped_tool: The original CrewAI tool to wrap.
        client: An ``AgentPEPClient`` instance.
        agent_id: The agent identifier for policy evaluation.
        session_id: Session identifier (default ``"default"``).
        role_mapping: Optional ``CrewAIRoleMapping`` for multi-agent role resolution.
        crewai_role: The CrewAI agent role string (used with ``role_mapping``).
        delegation_chain: Optional delegation chain for confused-deputy detection.

    Example::

        from agentpep import AgentPEPClient
        from agentpep.integrations.crewai import AgentPEPCrewAITool

        client = AgentPEPClient(base_url="http://localhost:8000")
        wrapped = AgentPEPCrewAITool(
            wrapped_tool=my_crewai_tool,
            client=client,
            agent_id="crew-researcher",
        )
    """

    def __init__(
        self,
        *,
        wrapped_tool: Any,
        client: Any,
        agent_id: str,
        session_id: str = "default",
        role_mapping: CrewAIRoleMapping | None = None,
        crewai_role: str | None = None,
        delegation_chain: list[str] | None = None,
    ) -> None:
        self.wrapped_tool = wrapped_tool
        self.client = client
        self.agent_id = agent_id
        self.session_id = session_id
        self.role_mapping = role_mapping
        self.crewai_role = crewai_role
        self.delegation_chain = delegation_chain

    # Forward metadata from the wrapped tool
    @property
    def name(self) -> str:
        return self.wrapped_tool.name

    @property
    def description(self) -> str:
        return self.wrapped_tool.description

    @property
    def args_schema(self) -> Any:
        return getattr(self.wrapped_tool, "args_schema", None)

    def _build_agent_id(self) -> str:
        """Resolve the agent_id, incorporating role mapping if available."""
        if self.role_mapping and self.crewai_role:
            return self.role_mapping.resolve(self.crewai_role)
        return self.agent_id

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Sync execution with policy enforcement."""
        tool_args = kwargs if kwargs else {"input": args[0] if args else ""}
        resolved_agent_id = self._build_agent_id()

        response = self.client.evaluate_sync(
            agent_id=resolved_agent_id,
            tool_name=self.wrapped_tool.name,
            tool_args=tool_args,
            session_id=self.session_id,
            delegation_chain=self.delegation_chain,
        )

        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=self.wrapped_tool.name,
                reason=response.reason,
                decision=response.decision.value,
            )

        logger.debug(
            "AgentPEP ALLOW for tool=%s agent=%s risk=%.2f",
            self.wrapped_tool.name,
            resolved_agent_id,
            response.risk_score,
        )
        return self.wrapped_tool._run(*args, **kwargs)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Public run method matching CrewAI BaseTool.run() interface."""
        return self._run(*args, **kwargs)


def wrap_crew_tools(
    tools: list[Any],
    client: Any,
    *,
    agent_id: str,
    session_id: str = "default",
    role_mapping: CrewAIRoleMapping | None = None,
    crewai_role: str | None = None,
    delegation_chain: list[str] | None = None,
) -> list[AgentPEPCrewAITool]:
    """Convenience helper to wrap a list of CrewAI tools with AgentPEP enforcement.

    Args:
        tools: List of CrewAI ``BaseTool`` instances.
        client: An ``AgentPEPClient`` instance.
        agent_id: The agent identifier for policy evaluation.
        session_id: Session identifier.
        role_mapping: Optional role mapping for multi-agent crews.
        crewai_role: The CrewAI agent role string.
        delegation_chain: Optional delegation chain for confused-deputy detection.

    Returns:
        List of ``AgentPEPCrewAITool`` wrappers.
    """
    return [
        AgentPEPCrewAITool(
            wrapped_tool=tool,
            client=client,
            agent_id=agent_id,
            session_id=session_id,
            role_mapping=role_mapping,
            crewai_role=crewai_role,
            delegation_chain=delegation_chain,
        )
        for tool in tools
    ]
