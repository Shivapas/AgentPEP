"""Delegation context — principal chain propagation for recursive trust enforcement.

Every tool call evaluation in a multi-agent workflow carries a DelegationContext
that records the full chain of principals from the root to the current agent.
The context is immutable: creating a child context produces a new object one
hop deeper in the chain.

Key invariants:
  - hop_count = len(principal_chain) - 1  (root is hop 0)
  - principal_chain[0] is always the root principal
  - principal_chain[-1] is always the current (leaf) agent
  - root_permissions are never expanded by delegation — only narrowed

Sprint S-E06 (E06-T01)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class DelegationContext:
    """Immutable snapshot of the delegation chain at a single evaluation point.

    Attributes:
        root_principal:   Identity of the originating principal (human or root agent).
        principal_chain:  Ordered tuple from root to current agent (inclusive).
                          Single-element tuple at root level (hop_count == 0).
        root_permissions: Permissions held by the root principal.  All subagents
                          in the chain are bounded to this set — a delegated agent
                          can never receive permissions that exceed it.
    """

    root_principal: str
    principal_chain: tuple[str, ...]
    root_permissions: frozenset[str]

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def hop_count(self) -> int:
        """Number of delegation hops from the root principal (0 = root itself)."""
        return max(0, len(self.principal_chain) - 1)

    @property
    def current_agent(self) -> str:
        """Identity of the agent at the leaf of the current delegation chain."""
        return self.principal_chain[-1] if self.principal_chain else ""

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def for_root(
        cls,
        root_agent_id: str,
        permissions: Iterable[str] | None = None,
    ) -> "DelegationContext":
        """Create a root-level DelegationContext (hop_count = 0).

        Args:
            root_agent_id: Identity of the root principal.
            permissions:   Initial permission set for the root principal.
                           Defaults to an empty set (no permissions claimed).
        """
        return cls(
            root_principal=root_agent_id,
            principal_chain=(root_agent_id,),
            root_permissions=frozenset(permissions or []),
        )

    def create_child(self, child_agent_id: str) -> "DelegationContext":
        """Return a new DelegationContext one hop deeper in the chain.

        The child inherits the root principal and root permissions unchanged;
        only the chain grows.  The effective permissions of the child are
        computed separately by EffectivePermissionCalculator.

        Args:
            child_agent_id: Identity of the agent receiving delegated authority.
        """
        return DelegationContext(
            root_principal=self.root_principal,
            principal_chain=self.principal_chain + (child_agent_id,),
            root_permissions=self.root_permissions,
        )

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def chain_as_list(self) -> list[str]:
        """Return principal_chain as a plain list (for JSON serialisation)."""
        return list(self.principal_chain)

    def permissions_as_list(self) -> list[str]:
        """Return root_permissions as a sorted list (for deterministic output)."""
        return sorted(self.root_permissions)
