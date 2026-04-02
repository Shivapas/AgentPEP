"""LangChain BaseTool wrapper for AgentPEP (APEP-033).

Wraps any LangChain tool so that every invocation is checked against
AgentPEP before the tool's ``_run`` / ``_arun`` method executes.
"""

from __future__ import annotations

import logging
from typing import Any, Type

from agentpep.exceptions import PolicyDeniedError
from agentpep.models import PolicyDecision

logger = logging.getLogger(__name__)

try:
    from langchain_core.tools import BaseTool
    from pydantic import BaseModel

    _HAS_LANGCHAIN = True
except ImportError:  # pragma: no cover
    _HAS_LANGCHAIN = False


def _check_langchain() -> None:
    if not _HAS_LANGCHAIN:
        raise ImportError(
            "LangChain integration requires langchain-core. "
            "Install with: pip install agentpep-sdk[langchain]"
        )


class AgentPEPToolWrapper(BaseTool):  # type: ignore[misc]
    """LangChain tool wrapper that enforces AgentPEP policy.

    Wraps an existing LangChain ``BaseTool`` and calls the AgentPEP Intercept
    API before delegating to the wrapped tool's ``_run`` / ``_arun``.

    Args:
        wrapped_tool: The original LangChain tool to wrap.
        client: An ``AgentPEPClient`` instance.
        agent_id: The agent identifier for policy evaluation.
        session_id: Session identifier (default ``"default"``).

    Example::

        from agentpep import AgentPEPClient
        from agentpep.integrations.langchain import AgentPEPToolWrapper

        client = AgentPEPClient(base_url="http://localhost:8000")
        wrapped = AgentPEPToolWrapper(
            wrapped_tool=my_tool,
            client=client,
            agent_id="lc-agent",
        )
    """

    wrapped_tool: Any  # BaseTool instance
    client: Any  # AgentPEPClient
    agent_id: str
    session_id: str = "default"

    # Forward metadata from the wrapped tool
    @property
    def name(self) -> str:  # type: ignore[override]
        return self.wrapped_tool.name

    @property
    def description(self) -> str:  # type: ignore[override]
        return self.wrapped_tool.description

    @property
    def args_schema(self) -> Type[BaseModel] | None:  # type: ignore[override]
        return self.wrapped_tool.args_schema

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Sync execution with policy enforcement."""
        _check_langchain()

        tool_args = kwargs if kwargs else {"input": args[0] if args else ""}
        response = self.client.evaluate_sync(
            agent_id=self.agent_id,
            tool_name=self.wrapped_tool.name,
            tool_args=tool_args,
            session_id=self.session_id,
        )

        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=self.wrapped_tool.name,
                reason=response.reason,
                decision=response.decision.value,
            )

        return self.wrapped_tool._run(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Async execution with policy enforcement."""
        _check_langchain()

        tool_args = kwargs if kwargs else {"input": args[0] if args else ""}
        response = await self.client.evaluate(
            agent_id=self.agent_id,
            tool_name=self.wrapped_tool.name,
            tool_args=tool_args,
            session_id=self.session_id,
        )

        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=self.wrapped_tool.name,
                reason=response.reason,
                decision=response.decision.value,
            )

        return await self.wrapped_tool._arun(*args, **kwargs)
