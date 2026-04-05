"""Semantic Kernel integration for AgentPEP (APEP-168, APEP-169).

Provides an ``IFunctionInvocationFilter`` implementation that intercepts
Semantic Kernel plugin function invocations with AgentPEP policy enforcement,
and a helper that maps Semantic Kernel plugin metadata to AgentPEP tool schemas.
"""

from __future__ import annotations

import logging
from typing import Any

from agentpep.exceptions import PolicyDeniedError
from agentpep.models import PolicyDecision

logger = logging.getLogger(__name__)

try:
    from semantic_kernel.filters.filter_types import FilterTypes  # noqa: F401

    _HAS_SK = True
except ImportError:  # pragma: no cover
    _HAS_SK = False


def _check_semantic_kernel() -> None:
    if not _HAS_SK:
        raise ImportError(
            "Semantic Kernel integration requires semantic-kernel. "
            "Install with: pip install agentpep-sdk[semantic-kernel]"
        )


# ---------------------------------------------------------------------------
# APEP-169 — Plugin metadata → tool schema mapping
# ---------------------------------------------------------------------------

class SKPluginMapper:
    """Maps Semantic Kernel plugin/function metadata to AgentPEP tool schemas.

    Semantic Kernel organises functions within named plugins.  This mapper
    converts that two-level hierarchy into a flat tool name that AgentPEP
    can match against policy rules (e.g. ``"plugin_name.function_name"``).

    It also extracts parameter metadata from ``KernelFunction`` to build
    a tool-args dict that AgentPEP can validate.

    Args:
        separator: Character to join plugin and function names (default ``"."``).
        plugin_alias: Optional map from SK plugin names to shorter aliases.

    Example::

        mapper = SKPluginMapper(
            plugin_alias={"MathPlugin": "math", "FilePlugin": "file"},
        )
        tool_name = mapper.tool_name("MathPlugin", "add")
        # => "math.add"
    """

    def __init__(
        self,
        separator: str = ".",
        plugin_alias: dict[str, str] | None = None,
    ) -> None:
        self._separator = separator
        self._plugin_alias: dict[str, str] = plugin_alias or {}

    def tool_name(self, plugin_name: str | None, function_name: str) -> str:
        """Build an AgentPEP tool name from plugin + function name."""
        resolved_plugin = self._plugin_alias.get(plugin_name or "", plugin_name or "")
        if resolved_plugin:
            return f"{resolved_plugin}{self._separator}{function_name}"
        return function_name

    def extract_args(
        self, context: Any, function: Any | None = None
    ) -> dict[str, Any]:
        """Extract tool arguments from a FunctionInvocationContext or KernelFunction.

        Pulls arguments from the context's ``arguments`` attribute, converting
        ``KernelArguments`` to a plain dict for AgentPEP evaluation.
        """
        args: dict[str, Any] = {}

        # FunctionInvocationContext carries arguments
        if hasattr(context, "arguments") and context.arguments is not None:
            kernel_args = context.arguments
            if hasattr(kernel_args, "items"):
                args = {k: v for k, v in kernel_args.items()}
            elif isinstance(kernel_args, dict):
                args = dict(kernel_args)

        return args

    def extract_metadata(self, function: Any) -> dict[str, Any]:
        """Extract metadata from a KernelFunction for documentation/policy use.

        Returns a dict with ``name``, ``plugin_name``, ``description``,
        and ``parameters`` keys.
        """
        metadata: dict[str, Any] = {
            "name": getattr(function, "name", "unknown"),
            "plugin_name": getattr(function, "plugin_name", None),
            "description": getattr(function, "description", ""),
        }

        # Extract parameter metadata if available
        params = []
        if hasattr(function, "parameters"):
            for param in function.parameters:
                params.append({
                    "name": getattr(param, "name", ""),
                    "description": getattr(param, "description", ""),
                    "type": getattr(param, "type_", "str"),
                    "required": getattr(param, "is_required", False),
                })
        metadata["parameters"] = params
        return metadata

    def register_alias(self, plugin_name: str, alias: str) -> None:
        """Add or update a plugin alias."""
        self._plugin_alias[plugin_name] = alias


# ---------------------------------------------------------------------------
# APEP-168 — IFunctionInvocationFilter implementation
# ---------------------------------------------------------------------------

class AgentPEPFunctionFilter:
    """Semantic Kernel function invocation filter that enforces AgentPEP policy.

    Implements the Semantic Kernel filter pipeline pattern.  When registered
    on a ``Kernel`` instance, it intercepts every plugin function invocation
    and checks it against the AgentPEP Intercept API before allowing execution.

    Args:
        client: An ``AgentPEPClient`` instance.
        agent_id: The agent identifier for policy evaluation.
        session_id: Session identifier (default ``"default"``).
        plugin_mapper: Optional ``SKPluginMapper`` for custom tool name resolution.

    Example::

        from semantic_kernel import Kernel
        from agentpep import AgentPEPClient
        from agentpep.integrations.semantic_kernel import AgentPEPFunctionFilter

        kernel = Kernel()
        client = AgentPEPClient(base_url="http://localhost:8000")
        policy_filter = AgentPEPFunctionFilter(client=client, agent_id="sk-agent")
        kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, policy_filter)
    """

    def __init__(
        self,
        client: Any,
        *,
        agent_id: str,
        session_id: str = "default",
        plugin_mapper: SKPluginMapper | None = None,
    ) -> None:
        self.client = client
        self.agent_id = agent_id
        self.session_id = session_id
        self.plugin_mapper = plugin_mapper or SKPluginMapper()

    async def __call__(
        self, context: Any, next_filter: Any
    ) -> None:
        """Intercept function invocation and enforce AgentPEP policy.

        This method follows the Semantic Kernel filter pipeline signature:
        ``async def filter(context, next) -> None``.

        On ALLOW/DRY_RUN, delegates to ``next(context)`` to continue the
        pipeline.  On DENY/ESCALATE, raises ``PolicyDeniedError`` and the
        function is never invoked.
        """
        function = context.function
        plugin_name = getattr(function, "plugin_name", None)
        function_name = getattr(function, "name", "unknown")

        tool_name = self.plugin_mapper.tool_name(plugin_name, function_name)
        tool_args = self.plugin_mapper.extract_args(context, function)

        response = await self.client.evaluate(
            agent_id=self.agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
            session_id=self.session_id,
        )

        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=tool_name,
                reason=response.reason,
                decision=response.decision.value,
            )

        logger.debug(
            "AgentPEP ALLOW for SK function=%s plugin=%s risk=%.2f",
            function_name,
            plugin_name,
            response.risk_score,
        )

        # Continue the filter pipeline
        await next_filter(context)


class AgentPEPFunctionFilterSync:
    """Synchronous variant of AgentPEPFunctionFilter for non-async Semantic Kernel usage.

    Uses the sync client methods for environments where async is not available.
    """

    def __init__(
        self,
        client: Any,
        *,
        agent_id: str,
        session_id: str = "default",
        plugin_mapper: SKPluginMapper | None = None,
    ) -> None:
        self.client = client
        self.agent_id = agent_id
        self.session_id = session_id
        self.plugin_mapper = plugin_mapper or SKPluginMapper()

    def __call__(self, context: Any, next_filter: Any) -> None:
        """Synchronous filter pipeline intercept."""
        function = context.function
        plugin_name = getattr(function, "plugin_name", None)
        function_name = getattr(function, "name", "unknown")

        tool_name = self.plugin_mapper.tool_name(plugin_name, function_name)
        tool_args = self.plugin_mapper.extract_args(context, function)

        response = self.client.evaluate_sync(
            agent_id=self.agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
            session_id=self.session_id,
        )

        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=tool_name,
                reason=response.reason,
                decision=response.decision.value,
            )

        next_filter(context)
