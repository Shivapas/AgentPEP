"""@enforce decorator for plain Python tool functions (APEP-031).

Wraps any sync or async function so that every call is checked against
AgentPEP before execution. If the policy decision is not ALLOW (or DRY_RUN),
a PolicyDeniedError is raised and the function is never called.
"""

from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Callable, TypeVar

from agentpep.client import AgentPEPClient
from agentpep.exceptions import PolicyDeniedError
from agentpep.execution_token import execution_token_validator
from agentpep.models import PolicyDecision
from agentpep.offline import OfflineEvaluator
from agentpep.tamper_detection import tamper_detector

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def enforce(
    client: AgentPEPClient | OfflineEvaluator,
    *,
    agent_id: str,
    role: str = "*",
    session_id: str = "default",
    tool_name: str | None = None,
) -> Callable[[F], F]:
    """Decorator that enforces AgentPEP policy before function execution.

    Args:
        client: An ``AgentPEPClient`` for remote evaluation or an
            ``OfflineEvaluator`` for local dev/test evaluation.
        agent_id: The agent identifier to send with the request.
        role: The agent role (used with ``OfflineEvaluator``).
        session_id: Session identifier for the request.
        tool_name: Override the tool name (defaults to the function name).

    Example::

        from agentpep import enforce, AgentPEPClient

        client = AgentPEPClient(base_url="http://localhost:8000")

        @enforce(client=client, agent_id="my-agent", role="WriterAgent")
        async def send_email(to: str, subject: str, body: str):
            await smtp_client.send(to, subject, body)
    """

    def decorator(fn: F) -> F:
        resolved_tool_name = tool_name or fn.__name__

        if isinstance(client, OfflineEvaluator):
            return _wrap_offline(fn, client, resolved_tool_name, agent_id, role, session_id)

        if inspect.iscoroutinefunction(fn):
            return _wrap_async(fn, client, resolved_tool_name, agent_id, session_id)  # type: ignore[return-value]
        return _wrap_sync(fn, client, resolved_tool_name, agent_id, session_id)  # type: ignore[return-value]

    return decorator


def _wrap_async(
    fn: Callable[..., Any],
    client: AgentPEPClient,
    tool_name: str,
    agent_id: str,
    session_id: str,
) -> Callable[..., Any]:
    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        response = await client.evaluate(
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=kwargs,
            session_id=session_id,
        )
        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=tool_name,
                reason=response.reason,
                decision=response.decision.value,
            )
        # APEP-190: Verify intercept was recorded before execution
        tamper_detector.verify_before_execution(tool_name, agent_id)
        # APEP-232: Validate execution token before tool execution
        if response.execution_token is not None:
            execution_token_validator.validate_and_consume(
                response.execution_token,
                expected_tool_name=tool_name,
                expected_agent_id=agent_id,
            )
        return await fn(*args, **kwargs)

    return wrapper


def _wrap_sync(
    fn: Callable[..., Any],
    client: AgentPEPClient,
    tool_name: str,
    agent_id: str,
    session_id: str,
) -> Callable[..., Any]:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        response = client.evaluate_sync(
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=kwargs,
            session_id=session_id,
        )
        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=tool_name,
                reason=response.reason,
                decision=response.decision.value,
            )
        # APEP-190: Verify intercept was recorded before execution
        tamper_detector.verify_before_execution(tool_name, agent_id)
        # APEP-232: Validate execution token before tool execution
        if response.execution_token is not None:
            execution_token_validator.validate_and_consume(
                response.execution_token,
                expected_tool_name=tool_name,
                expected_agent_id=agent_id,
            )
        return fn(*args, **kwargs)

    return wrapper


def _wrap_offline(
    fn: Callable[..., Any],
    evaluator: OfflineEvaluator,
    tool_name: str,
    agent_id: str,
    role: str,
    session_id: str,
) -> Any:
    """Wrap with offline evaluation — works for both sync and async functions."""

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            response = evaluator.evaluate(
                agent_id=agent_id,
                tool_name=tool_name,
                tool_args=kwargs,
                role=role,
                session_id=session_id,
            )
            if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
                raise PolicyDeniedError(
                    tool_name=tool_name,
                    reason=response.reason,
                    decision=response.decision.value,
                )
            return await fn(*args, **kwargs)

        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        response = evaluator.evaluate(
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args=kwargs,
            role=role,
            session_id=session_id,
        )
        if response.decision not in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN):
            raise PolicyDeniedError(
                tool_name=tool_name,
                reason=response.reason,
                decision=response.decision.value,
            )
        return fn(*args, **kwargs)

    return sync_wrapper
