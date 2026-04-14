"""Sprint 43 -- ToolTrustSession: plan-aware SDK session class.

APEP-344: ToolTrustSession provides a high-level, plan-aware API for
interacting with AgentPEP.  It wraps the AgentPEPClient and adds
plan lifecycle management (issue, bind, audit) so that SDK consumers
can work with MissionPlans without manually orchestrating API calls.

APEP-345: The ``delegate()`` method enables explicit sub-agent delegation
within the context of a plan, automatically checking the plan's
``delegates_to`` whitelist.

Usage::

    async with ToolTrustSession(base_url="http://localhost:8000") as session:
        plan = await session.issue_plan(
            action="Analyze Q3 finance reports",
            issuer="alice@corp.com",
            scope=["read:internal:finance.*"],
        )
        result = await session.evaluate(
            agent_id="analyst-bot",
            tool_name="db.read.internal.finance.q3",
        )
        sub = await session.delegate(
            child_agent_id="summary-bot",
            tool_name="api.get.external.summary",
        )
        tree = await session.audit()
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

import httpx

from agentpep.client import AgentPEPClient
from agentpep.exceptions import (
    AgentPEPConnectionError,
    AgentPEPTimeoutError,
    PolicyDeniedError,
)
from agentpep.models import PolicyDecision, PolicyDecisionResponse

logger = logging.getLogger(__name__)


class PlanInfo:
    """Lightweight plan handle returned by ``issue_plan``."""

    __slots__ = (
        "plan_id", "action", "issuer", "status", "signature",
        "issued_at", "expires_at",
    )

    def __init__(self, data: dict[str, Any]) -> None:
        self.plan_id: str = str(data["plan_id"])
        self.action: str = data.get("action", "")
        self.issuer: str = data.get("issuer", "")
        self.status: str = data.get("status", "ACTIVE")
        self.signature: str = data.get("signature", "")
        self.issued_at: str = data.get("issued_at", "")
        self.expires_at: str | None = data.get("expires_at")

    def __repr__(self) -> str:
        return f"PlanInfo(plan_id={self.plan_id!r}, action={self.action!r}, status={self.status!r})"


class AuditTree:
    """Receipt chain tree returned by ``audit()``."""

    __slots__ = ("plan_id", "receipts", "total", "chain_valid")

    def __init__(self, data: dict[str, Any]) -> None:
        self.plan_id: str = str(data.get("plan_id", ""))
        self.receipts: list[dict[str, Any]] = data.get("receipts", [])
        self.total: int = data.get("total", len(self.receipts))
        self.chain_valid: bool = data.get("chain_valid", True)

    def __repr__(self) -> str:
        return f"AuditTree(plan_id={self.plan_id!r}, total={self.total})"


class DelegationResult:
    """Result of a ``delegate()`` call."""

    __slots__ = ("allowed", "child_agent_id", "decision", "reason")

    def __init__(
        self,
        allowed: bool,
        child_agent_id: str,
        decision: str = "ALLOW",
        reason: str = "",
    ) -> None:
        self.allowed = allowed
        self.child_agent_id = child_agent_id
        self.decision = decision
        self.reason = reason

    def __repr__(self) -> str:
        return (
            f"DelegationResult(allowed={self.allowed}, "
            f"child={self.child_agent_id!r}, decision={self.decision!r})"
        )


class ToolTrustSession:
    """Plan-aware session for AgentPEP SDK.

    Wraps ``AgentPEPClient`` with MissionPlan lifecycle management.
    Use as an async context manager for automatic cleanup::

        async with ToolTrustSession(base_url="http://localhost:8000") as s:
            plan = await s.issue_plan(...)
            result = await s.evaluate(agent_id="bot", tool_name="file.read")
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str | None = None,
        timeout: float = 5.0,
        fail_open: bool = False,
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> None:
        self._client = AgentPEPClient(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            fail_open=fail_open,
        )
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self.session_id: str = session_id or "default"
        self.agent_id: str = agent_id or "default-agent"
        self._plan: PlanInfo | None = None
        self._http: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> ToolTrustSession:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Release resources."""
        await self._client.aclose()
        if self._http and not self._http.is_closed:
            await self._http.aclose()

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self._api_key:
                headers["X-API-Key"] = self._api_key
            self._http = httpx.AsyncClient(
                base_url=self._base_url,
                headers=headers,
                timeout=self._timeout,
            )
        return self._http

    # ------------------------------------------------------------------
    # Plan lifecycle
    # ------------------------------------------------------------------

    async def issue_plan(
        self,
        *,
        action: str,
        issuer: str,
        scope: list[str] | None = None,
        requires_checkpoint: list[str] | None = None,
        delegates_to: list[str] | None = None,
        budget: dict[str, Any] | None = None,
        human_intent: str = "",
    ) -> PlanInfo:
        """Issue a new MissionPlan and bind the current session to it.

        Args:
            action: Human-readable intent label.
            issuer: Identity of the human issuing the plan.
            scope: Allowed scope patterns (verb:namespace:resource).
            requires_checkpoint: Patterns that require checkpoint approval.
            delegates_to: Agent IDs permitted to receive delegation.
            budget: Budget constraints dict (max_delegations, max_risk_total, ttl_seconds).
            human_intent: Explicit human intent to propagate.

        Returns:
            PlanInfo handle.
        """
        payload: dict[str, Any] = {
            "action": action,
            "issuer": issuer,
        }
        if scope is not None:
            payload["scope"] = scope
        if requires_checkpoint is not None:
            payload["requires_checkpoint"] = requires_checkpoint
        if delegates_to is not None:
            payload["delegates_to"] = delegates_to
        if budget is not None:
            payload["budget"] = budget
        if human_intent:
            payload["human_intent"] = human_intent

        http = await self._get_http()
        resp = await http.post("/v1/plans", json=payload)
        resp.raise_for_status()
        data = resp.json()
        self._plan = PlanInfo(data)

        # Auto-bind session to plan
        await self._bind_session()

        return self._plan

    async def _bind_session(self) -> None:
        """Bind the current session to the active plan."""
        if self._plan is None:
            return
        http = await self._get_http()
        resp = await http.post(
            f"/v1/plans/{self._plan.plan_id}/bind",
            json={
                "session_id": self.session_id,
                "agent_id": self.agent_id,
            },
        )
        resp.raise_for_status()

    @property
    def plan(self) -> PlanInfo | None:
        """The currently bound plan, or None."""
        return self._plan

    async def get_plan_detail(self) -> dict[str, Any]:
        """Fetch full plan details from the server."""
        if self._plan is None:
            raise RuntimeError("No plan bound to session")
        http = await self._get_http()
        resp = await http.get(f"/v1/plans/{self._plan.plan_id}")
        resp.raise_for_status()
        return resp.json()

    async def revoke_plan(self) -> dict[str, Any]:
        """Revoke the current plan."""
        if self._plan is None:
            raise RuntimeError("No plan bound to session")
        http = await self._get_http()
        resp = await http.delete(f"/v1/plans/{self._plan.plan_id}")
        resp.raise_for_status()
        data = resp.json()
        self._plan = None
        return data

    # ------------------------------------------------------------------
    # Policy evaluation
    # ------------------------------------------------------------------

    async def evaluate(
        self,
        *,
        agent_id: str | None = None,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        delegation_chain: list[str] | None = None,
        dry_run: bool = False,
    ) -> PolicyDecisionResponse:
        """Evaluate a tool call within the plan-bound session.

        Uses the session's agent_id and session_id by default.
        """
        return await self._client.evaluate(
            agent_id=agent_id or self.agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
            session_id=self.session_id,
            delegation_chain=delegation_chain,
            dry_run=dry_run,
        )

    async def enforce(
        self,
        *,
        agent_id: str | None = None,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        delegation_chain: list[str] | None = None,
    ) -> PolicyDecisionResponse:
        """Evaluate and enforce: raises PolicyDeniedError if not ALLOW."""
        return await self._client.enforce(
            agent_id=agent_id or self.agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
            session_id=self.session_id,
            delegation_chain=delegation_chain,
        )

    # ------------------------------------------------------------------
    # APEP-345: Delegation
    # ------------------------------------------------------------------

    async def delegate(
        self,
        *,
        child_agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
    ) -> DelegationResult:
        """Delegate a tool call to a child agent within the plan context.

        Checks the plan's ``delegates_to`` whitelist and evaluates the
        tool call with the child agent as the caller.

        Args:
            child_agent_id: Agent ID of the child receiving delegation.
            tool_name: Tool the child agent wants to invoke.
            tool_args: Arguments for the tool call.

        Returns:
            DelegationResult with the evaluation outcome.
        """
        if self._plan is None:
            raise RuntimeError("No plan bound to session — call issue_plan() first")

        # Check delegates_to whitelist via plan detail
        detail = await self.get_plan_detail()
        delegates_to = detail.get("delegates_to", [])

        if delegates_to:
            import fnmatch as _fnmatch

            allowed = any(
                _fnmatch.fnmatch(child_agent_id, pattern)
                for pattern in delegates_to
            )
            if not allowed:
                return DelegationResult(
                    allowed=False,
                    child_agent_id=child_agent_id,
                    decision="DENY",
                    reason=(
                        f"Agent '{child_agent_id}' is not in the plan's "
                        f"delegates_to whitelist: {delegates_to}"
                    ),
                )

        # Evaluate the tool call with the child agent and delegation chain
        try:
            response = await self._client.evaluate(
                agent_id=child_agent_id,
                tool_name=tool_name,
                tool_args=tool_args,
                session_id=self.session_id,
                delegation_chain=[self.agent_id, child_agent_id],
            )
            return DelegationResult(
                allowed=response.decision in (PolicyDecision.ALLOW, PolicyDecision.DRY_RUN),
                child_agent_id=child_agent_id,
                decision=response.decision.value,
                reason=response.reason,
            )
        except PolicyDeniedError as exc:
            return DelegationResult(
                allowed=False,
                child_agent_id=child_agent_id,
                decision=exc.decision,
                reason=exc.reason,
            )

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    async def audit(self) -> AuditTree:
        """Fetch the receipt chain tree for the current plan."""
        if self._plan is None:
            raise RuntimeError("No plan bound to session")
        http = await self._get_http()
        resp = await http.get(f"/v1/plans/{self._plan.plan_id}/receipts")
        resp.raise_for_status()
        data = resp.json()
        data["plan_id"] = self._plan.plan_id
        return AuditTree(data)

    async def budget_status(self) -> dict[str, Any]:
        """Fetch budget status for the current plan."""
        if self._plan is None:
            raise RuntimeError("No plan bound to session")
        http = await self._get_http()
        resp = await http.get(f"/v1/plans/{self._plan.plan_id}/budget")
        resp.raise_for_status()
        return resp.json()
