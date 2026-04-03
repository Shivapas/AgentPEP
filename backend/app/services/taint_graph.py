"""TaintGraph -- per-session in-memory DAG for taint tracking and propagation.

Sprint 5 (APEP-038 through APEP-046):
  - TaintGraph data structure (directed acyclic graph of TaintNodes per session).
  - Session lifecycle management (create, update, destroy taint graphs).
  - Taint propagation engine (output inherits highest taint from inputs).
  - QUARANTINE level assignment on injection signature detection.
  - Session graph persistence to MongoDB for forensic inspection.

Sprint 6:
  APEP-047: Multi-hop taint propagation with tool_call_id and hop_depth tracking.
  APEP-048: Sanitisation gates -- registered sanitisation functions that downgrade
            taint levels through a controlled gate mechanism.
  APEP-049: Expanded injection signature library -- backward-compatible wrappers
            around the categorised InjectionSignatureLibrary in
            ``app.services.injection_signatures``.
  APEP-051: Cross-agent taint propagation -- data flowing between agents
            (possibly across sessions) preserves taint lineage.
  APEP-052: Taint audit events -- structured audit log for every taint lifecycle
            event, with in-memory collection and MongoDB flush.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from app.core.config import settings
from app.models.policy import (
    SanitisationGate,
    TaintAuditEvent,
    TaintEventType,
    TaintLevel,
    TaintNode,
    TaintSource,
)
from app.services.injection_signatures import injection_library

logger = logging.getLogger(__name__)

# MongoDB collection name for audit events (APEP-052)
TAINT_AUDIT_EVENTS = "taint_audit_events"

# ---------------------------------------------------------------------------
# Backward-compatible injection signature list (Sprint 5 API)
# ---------------------------------------------------------------------------

# Legacy Sprint 5 patterns that may not be in the APEP-049 library but must
# remain for backward compatibility with existing tests and consumers.
_LEGACY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(your\s+)?(previous|prior)\s+(instructions|rules|constraints)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"system\s*:\s*(you\s+are|your\s+new\s+role)", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"ADMIN\s+OVERRIDE", re.IGNORECASE),
    re.compile(r"do\s+not\s+follow\s+(any|the)\s+(previous|original)\s+(instructions|rules)", re.IGNORECASE),
    re.compile(r"pretend\s+(that\s+)?you\s+(are|have)\s+no\s+(restrictions|rules|limits)", re.IGNORECASE),
    re.compile(r"act\s+as\s+if\s+(there\s+are\s+)?no\s+(rules|restrictions|safety)", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN\s+mode", re.IGNORECASE),
    re.compile(r"developer\s+mode\s+(enabled|activated|on)", re.IGNORECASE),
]

# Combined list: library patterns + legacy patterns
INJECTION_SIGNATURES: list[re.Pattern[str]] = [
    re.compile(sig.pattern) for sig in injection_library.signatures
] + _LEGACY_PATTERNS

# Sources automatically classified as UNTRUSTED (APEP-042)
UNTRUSTED_SOURCES: frozenset[TaintSource] = frozenset({
    TaintSource.WEB,
    TaintSource.EMAIL,
    TaintSource.TOOL_OUTPUT,
    TaintSource.AGENT_MSG,
})

# Taint level ordering (higher index = more restrictive)
_TAINT_ORDER = {
    TaintLevel.TRUSTED: 0,
    TaintLevel.UNTRUSTED: 1,
    TaintLevel.QUARANTINE: 2,
}


def _highest_taint(*levels: TaintLevel) -> TaintLevel:
    """Return the most restrictive taint level."""
    return max(levels, key=lambda l: _TAINT_ORDER[l])


def _hash_value(value: Any) -> str:
    """SHA-256 hash of a value for tracking."""
    return hashlib.sha256(str(value).encode()).hexdigest()


def _check_legacy_patterns(text: str) -> bool:
    """Check text against the legacy Sprint 5 injection patterns."""
    for pattern in _LEGACY_PATTERNS:
        if pattern.search(text):
            return True
    return False


def check_injection_signatures(text: str) -> bool:
    """Return True if text matches any known injection signature.

    Backward-compatible entry point.  Checks both the APEP-049 categorised
    library and the legacy Sprint 5 patterns.
    """
    return injection_library.check_any(text) or _check_legacy_patterns(text)


def check_injection_signature_id(text: str) -> str | None:
    """Return the signature_id of the first matching injection signature, or None.

    This is a convenience wrapper for callers that need the matched signature
    identifier (e.g. for audit events).
    """
    matches = injection_library.check(text)
    if matches:
        return matches[0].signature_id
    return None


# ---------------------------------------------------------------------------
# APEP-048: Sanitisation Gate Registry
# ---------------------------------------------------------------------------


class SanitisationGateRegistry:
    """Registry of sanitisation functions that can downgrade taint levels.

    A *sanitisation gate* declares that data passing through a specific
    sanitisation function may have its taint level reduced from
    ``downgrades_from`` to ``downgrades_to``.  The gate can optionally require
    human approval before the downgrade takes effect.

    Thread-safe.
    """

    def __init__(self) -> None:
        self._gates: dict[UUID, SanitisationGate] = {}
        self._lock = threading.Lock()

    def register(self, gate: SanitisationGate) -> SanitisationGate:
        """Register a new sanitisation gate.  Returns the gate for chaining."""
        with self._lock:
            self._gates[gate.gate_id] = gate
        logger.debug("Registered sanitisation gate %s (%s)", gate.name, gate.gate_id)
        return gate

    def remove(self, gate_id: UUID) -> bool:
        """Remove a gate by ID.  Returns ``True`` if it existed."""
        with self._lock:
            gate = self._gates.pop(gate_id, None)
            return gate is not None

    def list_gates(self) -> list[SanitisationGate]:
        """Return all registered gates."""
        return list(self._gates.values())

    def find_gate(self, function_name: str) -> SanitisationGate | None:
        """Find the first enabled gate whose ``function_pattern`` matches
        *function_name*.

        Disabled gates are excluded from the search.
        """
        for gate in self._gates.values():
            if not gate.enabled:
                continue
            if re.search(gate.function_pattern, function_name):
                return gate
        return None

    def find_applicable(
        self,
        function_name: str,
        current_taint: TaintLevel,
    ) -> SanitisationGate | None:
        """Find the first enabled gate whose ``function_pattern`` matches
        *function_name* and whose ``downgrades_from`` matches *current_taint*.
        """
        for gate in self._gates.values():
            if not gate.enabled:
                continue
            if gate.downgrades_from != current_taint:
                continue
            if re.search(gate.function_pattern, function_name):
                return gate
        return None

    def get_by_id(self, gate_id: UUID) -> SanitisationGate | None:
        """Look up a gate by its UUID."""
        return self._gates.get(gate_id)

    @property
    def gate_count(self) -> int:
        return len(self._gates)


# Module-level singleton
sanitisation_gate_registry = SanitisationGateRegistry()


# ---------------------------------------------------------------------------
# APEP-052: Taint Audit Logger
# ---------------------------------------------------------------------------


class TaintAuditLogger:
    """In-memory collector for taint audit events with MongoDB flush support.

    Every significant taint lifecycle event (assignment, propagation,
    sanitisation downgrade, cross-agent transfer) is recorded as a
    :class:`TaintAuditEvent`.  Events accumulate in memory and can be flushed
    to the ``taint_audit_events`` MongoDB collection.

    Thread-safe.
    """

    def __init__(self) -> None:
        self._events: list[TaintAuditEvent] = []
        self._lock = threading.Lock()

    def emit(self, event: TaintAuditEvent) -> None:
        """Record an audit event."""
        with self._lock:
            self._events.append(event)
        logger.debug(
            "Audit event %s: %s node=%s session=%s",
            event.event_type.value,
            event.taint_level.value,
            event.node_id,
            event.session_id,
        )

    def emit_from_node(
        self,
        event_type: TaintEventType,
        node: TaintNode,
        previous_taint_level: TaintLevel | None = None,
        matched_signature: str | None = None,
    ) -> TaintAuditEvent:
        """Convenience: build and emit an event directly from a TaintNode."""
        event = TaintAuditEvent(
            event_id=uuid4(),
            event_type=event_type,
            session_id=node.session_id,
            node_id=node.node_id,
            agent_id=node.agent_id,
            taint_level=node.taint_level,
            previous_taint_level=previous_taint_level,
            source=node.source,
            propagated_from=list(node.propagated_from),
            tool_call_id=node.tool_call_id,
            hop_depth=node.hop_depth,
            sanitised_by=node.sanitised_by,
            matched_signature=matched_signature,
            timestamp=node.created_at,
        )
        self.emit(event)
        return event

    def get_events(
        self,
        session_id: str,
        event_type: TaintEventType | None = None,
        limit: int | None = None,
    ) -> list[TaintAuditEvent]:
        """Return audit events for a session, optionally filtered by type.

        Args:
            session_id: Only return events for this session.
            event_type: If provided, only return events of this type.
            limit: If provided, return at most this many events.

        Returns:
            List of matching events in chronological order.
        """
        with self._lock:
            result: list[TaintAuditEvent] = []
            for ev in self._events:
                if ev.session_id != session_id:
                    continue
                if event_type is not None and ev.event_type != event_type:
                    continue
                result.append(ev)
                if limit is not None and len(result) >= limit:
                    break
            return result

    @property
    def events(self) -> list[TaintAuditEvent]:
        """Snapshot of all collected events."""
        with self._lock:
            return list(self._events)

    @property
    def event_count(self) -> int:
        with self._lock:
            return len(self._events)

    def clear(self) -> int:
        """Discard all events and return the count that was cleared."""
        with self._lock:
            count = len(self._events)
            self._events.clear()
            return count

    async def flush(self, session_id: str | None = None) -> int:
        """Write pending events to MongoDB and clear the flushed events.

        Args:
            session_id: If provided, only flush events for this session.
                        Otherwise flush all events.

        Returns the number of events flushed.
        """
        with self._lock:
            if not self._events:
                return 0
            if session_id is not None:
                batch = [e for e in self._events if e.session_id == session_id]
                remaining = [e for e in self._events if e.session_id != session_id]
            else:
                batch = list(self._events)
                remaining = []
            if not batch:
                return 0
            self._events = remaining

        from app.db import mongodb as db_module

        db = db_module.get_database()
        docs = [event.model_dump(mode="json") for event in batch]
        try:
            await db[TAINT_AUDIT_EVENTS].insert_many(docs)
            logger.debug("Flushed %d taint audit events to MongoDB", len(docs))
            return len(docs)
        except Exception:
            logger.exception("Failed to flush taint audit events")
            # Re-enqueue on failure so events are not lost
            with self._lock:
                self._events = batch + self._events
            return 0


# Module-level singleton
taint_audit_logger = TaintAuditLogger()


# ---------------------------------------------------------------------------
# TaintGraph (APEP-038 + Sprint 6 extensions)
# ---------------------------------------------------------------------------


class TaintGraph:
    """Per-session directed acyclic graph of TaintNodes.

    Thread-safe.  Each node tracks its taint level, source, and which parent
    nodes it was propagated from.

    Sprint 6 additions:
    - ``propagate_tool_chain()`` for multi-hop tool-call tracking (APEP-047).
    - ``apply_sanitisation()`` for sanitisation-gate downgrades (APEP-048).
    - Audit event emission on every mutation (APEP-052).
    """

    __slots__ = (
        "session_id", "_nodes", "_children", "_lock", "created_at",
        "_audit_logger", "_max_nodes", "_access_order", "_evicted_count",
    )

    def __init__(
        self,
        session_id: str,
        audit_logger: TaintAuditLogger | None = None,
        max_nodes: int | None = None,
    ) -> None:
        self.session_id = session_id
        self._nodes: dict[UUID, TaintNode] = {}
        self._children: dict[UUID, list[UUID]] = {}  # parent -> children edges
        self._lock = threading.Lock()
        self.created_at = datetime.utcnow()
        self._audit_logger = audit_logger or taint_audit_logger
        # APEP-183: Bounded node limit with LRU eviction
        self._max_nodes = max_nodes or settings.taint_graph_max_nodes_per_session
        self._access_order: list[UUID] = []  # oldest-first for LRU eviction
        self._evicted_count = 0

    # --- Node operations ---

    def add_node(
        self,
        source: TaintSource,
        value: Any = None,
        taint_level: TaintLevel | None = None,
        propagated_from: list[UUID] | None = None,
        node_id: UUID | None = None,
        agent_id: str | None = None,
        tool_call_id: str | None = None,
        hop_depth: int = 0,
        sanitised_by: str | None = None,
    ) -> TaintNode:
        """Add a new taint node to the graph.

        If taint_level is not specified, it is inferred:
        - UNTRUSTED if source is in UNTRUSTED_SOURCES
        - QUARANTINE if value contains injection signatures
        - TRUSTED otherwise

        If propagated_from is provided, the node inherits the highest taint
        level from its parents (APEP-040).
        """
        matched_sig_id: str | None = None

        # Determine taint level
        if taint_level is None:
            taint_level = self._infer_taint_level(source, value)

        # If propagated from parents, inherit highest taint (APEP-040)
        if propagated_from:
            parent_taint = self._get_highest_parent_taint(propagated_from)
            taint_level = _highest_taint(taint_level, parent_taint)

        # Check for injection signatures -> QUARANTINE (APEP-044 / APEP-049)
        if value is not None and isinstance(value, str):
            matches = injection_library.check(value)
            if matches:
                taint_level = TaintLevel.QUARANTINE
                matched_sig_id = matches[0].signature_id
            elif _check_legacy_patterns(value):
                taint_level = TaintLevel.QUARANTINE

        node = TaintNode(
            node_id=node_id or uuid4(),
            session_id=self.session_id,
            taint_level=taint_level,
            source=source,
            propagated_from=propagated_from or [],
            value_hash=_hash_value(value) if value is not None else None,
            agent_id=agent_id,
            tool_call_id=tool_call_id,
            hop_depth=hop_depth,
            sanitised_by=sanitised_by,
        )

        with self._lock:
            # APEP-183: Evict LRU nodes if at capacity
            while len(self._nodes) >= self._max_nodes and self._access_order:
                self._evict_oldest()

            self._nodes[node.node_id] = node
            self._access_order.append(node.node_id)
            # Register parent->child edges
            for parent_id in node.propagated_from:
                self._children.setdefault(parent_id, []).append(node.node_id)

        # Emit audit event (APEP-052)
        event_type = TaintEventType.TAINT_ASSIGNED
        if propagated_from:
            event_type = TaintEventType.TAINT_PROPAGATED
        if taint_level == TaintLevel.QUARANTINE and matched_sig_id:
            event_type = TaintEventType.TAINT_QUARANTINED

        self._audit_logger.emit_from_node(
            event_type=event_type,
            node=node,
            matched_signature=matched_sig_id,
        )

        return node

    def get_node(self, node_id: UUID) -> TaintNode | None:
        """Get a node by ID. Touches LRU access order (APEP-183)."""
        node = self._nodes.get(node_id)
        if node is not None:
            # Touch: move to end of access order (most recently used)
            try:
                self._access_order.remove(node_id)
            except ValueError:
                pass
            self._access_order.append(node_id)
        return node

    def get_children(self, node_id: UUID) -> list[TaintNode]:
        """Get direct children of a node."""
        child_ids = self._children.get(node_id, [])
        return [self._nodes[cid] for cid in child_ids if cid in self._nodes]

    def get_ancestors(self, node_id: UUID) -> list[TaintNode]:
        """Get all ancestor nodes (BFS up the propagated_from edges)."""
        visited: set[UUID] = set()
        queue = list(self._nodes[node_id].propagated_from) if node_id in self._nodes else []
        ancestors: list[TaintNode] = []
        while queue:
            pid = queue.pop(0)
            if pid in visited or pid not in self._nodes:
                continue
            visited.add(pid)
            parent = self._nodes[pid]
            ancestors.append(parent)
            queue.extend(parent.propagated_from)
        return ancestors

    @property
    def nodes(self) -> list[TaintNode]:
        """All nodes in the graph."""
        return list(self._nodes.values())

    def _evict_oldest(self) -> None:
        """Remove the least-recently-used node (APEP-183). Caller must hold _lock."""
        if not self._access_order:
            return
        evict_id = self._access_order.pop(0)
        evicted = self._nodes.pop(evict_id, None)
        if evicted is not None:
            self._evicted_count += 1
            # Remove from children index
            self._children.pop(evict_id, None)
            # Remove from parent->child edges
            for children_list in self._children.values():
                try:
                    children_list.remove(evict_id)
                except ValueError:
                    pass
            logger.debug(
                "Evicted LRU taint node %s from session %s (total evicted: %d)",
                evict_id, self.session_id, self._evicted_count,
            )

    @property
    def evicted_count(self) -> int:
        """Number of nodes evicted due to LRU capacity limit (APEP-183)."""
        return self._evicted_count

    @property
    def max_nodes(self) -> int:
        """Maximum node capacity for this graph (APEP-183)."""
        return self._max_nodes

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    # --- Propagation (APEP-040) ---

    def propagate(
        self,
        parent_ids: list[UUID],
        source: TaintSource,
        value: Any = None,
    ) -> TaintNode:
        """Create a new node that inherits taint from parent nodes.

        The output node's taint level is the maximum of all parent taint levels,
        elevated further if the value contains injection signatures.
        """
        return self.add_node(
            source=source,
            value=value,
            propagated_from=parent_ids,
        )

    # --- APEP-047: Multi-hop tool chain propagation ---

    def propagate_tool_chain(
        self,
        parent_ids: list[UUID],
        source: TaintSource,
        tool_call_id: str,
        value: Any = None,
        agent_id: str | None = None,
    ) -> TaintNode:
        """Propagate taint through a tool call chain, tracking hop depth.

        The ``hop_depth`` of the new node is one greater than the maximum
        ``hop_depth`` among its parents.  The ``tool_call_id`` identifies the
        specific tool invocation in the chain.

        Args:
            parent_ids: Node IDs that feed into this tool call.
            source: Taint source label (typically TOOL_OUTPUT).
            tool_call_id: Unique identifier of the tool invocation.
            value: Optional value associated with the tool output.
            agent_id: Optional agent that performed the tool call.

        Returns:
            The newly created TaintNode with incremented hop_depth.
        """
        # Calculate hop_depth as max parent hop_depth + 1
        max_hop = 0
        for pid in parent_ids:
            parent = self._nodes.get(pid)
            if parent is not None:
                max_hop = max(max_hop, parent.hop_depth)
        new_hop_depth = max_hop + 1

        return self.add_node(
            source=source,
            value=value,
            propagated_from=parent_ids,
            agent_id=agent_id,
            tool_call_id=tool_call_id,
            hop_depth=new_hop_depth,
        )

    # --- APEP-048: Sanitisation gate application ---

    def apply_sanitisation(
        self,
        node_id: UUID,
        sanitiser_function: str,
        registry: SanitisationGateRegistry | None = None,
        value: Any = None,
    ) -> TaintNode | None:
        """Apply a sanitisation gate to a node, producing a downgraded child.

        Searches the provided (or global) registry for an enabled gate whose
        ``function_pattern`` matches *sanitiser_function* and whose
        ``downgrades_from`` matches the node's current taint level.  If found,
        a new child node is created with the downgraded taint level.

        Args:
            node_id: The source node to sanitise.
            sanitiser_function: Name of the sanitisation function to match.
            registry: Gate registry (defaults to module-level singleton).
            value: Optional new value after sanitisation.

        Returns:
            The new sanitised TaintNode, or ``None`` if no applicable gate is
            found (not found, disabled, taint mismatch, or requires approval).
        """
        reg = registry or sanitisation_gate_registry
        source_node = self._nodes.get(node_id)
        if source_node is None:
            return None

        gate = reg.find_applicable(sanitiser_function, source_node.taint_level)
        if gate is None:
            logger.debug(
                "No applicable sanitisation gate for function %r at taint level %s",
                sanitiser_function,
                source_node.taint_level.value,
            )
            return None
        if gate.requires_approval:
            logger.debug(
                "Sanitisation gate %r requires approval; skipping auto-apply",
                gate.name,
            )
            return None

        previous_taint = source_node.taint_level

        sanitised_node = TaintNode(
            node_id=uuid4(),
            session_id=self.session_id,
            taint_level=gate.downgrades_to,
            source=TaintSource.SANITISED,
            propagated_from=[node_id],
            value_hash=_hash_value(value) if value is not None else source_node.value_hash,
            agent_id=source_node.agent_id,
            tool_call_id=source_node.tool_call_id,
            hop_depth=source_node.hop_depth,
            sanitised_by=sanitiser_function,
        )

        with self._lock:
            # APEP-183: Evict LRU nodes if at capacity
            while len(self._nodes) >= self._max_nodes and self._access_order:
                self._evict_oldest()

            self._nodes[sanitised_node.node_id] = sanitised_node
            self._access_order.append(sanitised_node.node_id)
            self._children.setdefault(node_id, []).append(sanitised_node.node_id)

        # Emit audit event (APEP-052)
        self._audit_logger.emit_from_node(
            event_type=TaintEventType.TAINT_DOWNGRADED,
            node=sanitised_node,
            previous_taint_level=previous_taint,
        )

        return sanitised_node

    # --- Taint queries ---

    def get_taint_flags(self, node_ids: list[UUID]) -> list[str]:
        """Return a list of taint level strings for the given nodes."""
        flags: list[str] = []
        for nid in node_ids:
            node = self._nodes.get(nid)
            if node and node.taint_level != TaintLevel.TRUSTED:
                flags.append(node.taint_level.value)
        return flags

    def has_untrusted_nodes(self, node_ids: list[UUID]) -> bool:
        """Check if any of the given nodes are UNTRUSTED or QUARANTINE."""
        for nid in node_ids:
            node = self._nodes.get(nid)
            if node and node.taint_level in (TaintLevel.UNTRUSTED, TaintLevel.QUARANTINE):
                return True
        return False

    def has_quarantined_nodes(self, node_ids: list[UUID]) -> bool:
        """Check if any of the given nodes are QUARANTINE."""
        for nid in node_ids:
            node = self._nodes.get(nid)
            if node and node.taint_level == TaintLevel.QUARANTINE:
                return True
        return False

    def highest_taint_level(self, node_ids: list[UUID]) -> TaintLevel:
        """Return the highest taint level across the given nodes."""
        level = TaintLevel.TRUSTED
        for nid in node_ids:
            node = self._nodes.get(nid)
            if node:
                level = _highest_taint(level, node.taint_level)
        return level

    # --- Serialization (APEP-045) ---

    def to_dict(self) -> dict[str, Any]:
        """Serialize the graph for MongoDB persistence."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "node_count": self.node_count,
            "nodes": [
                node.model_dump(mode="json") for node in self._nodes.values()
            ],
            "edges": {
                str(parent_id): [str(cid) for cid in children]
                for parent_id, children in self._children.items()
            },
        }

    # --- Internal helpers ---

    def _infer_taint_level(self, source: TaintSource, value: Any) -> TaintLevel:
        """Infer taint level from source type (APEP-042)."""
        if source in UNTRUSTED_SOURCES:
            return TaintLevel.UNTRUSTED
        return TaintLevel.TRUSTED

    def _get_highest_parent_taint(self, parent_ids: list[UUID]) -> TaintLevel:
        """Get the highest taint level from parent nodes."""
        level = TaintLevel.TRUSTED
        for pid in parent_ids:
            parent = self._nodes.get(pid)
            if parent:
                level = _highest_taint(level, parent.taint_level)
        return level


# ---------------------------------------------------------------------------
# SessionGraphManager (APEP-039 + APEP-051 cross-agent + APEP-052 audit)
# ---------------------------------------------------------------------------


class SessionGraphManager:
    """Manages per-session TaintGraph instances (APEP-039).

    Thread-safe singleton that creates, retrieves, and destroys session graphs.

    Sprint 6 additions:
    - ``propagate_cross_agent()`` for cross-agent taint transfer (APEP-051).
    - ``link_sessions()`` to track cross-agent session linkage (APEP-051).
    - Audit event emission on cross-agent propagation (APEP-052).
    """

    def __init__(self, audit_logger: TaintAuditLogger | None = None) -> None:
        self._graphs: dict[str, TaintGraph] = {}
        self._lock = threading.Lock()
        self._linked_sessions: dict[str, set[str]] = {}  # APEP-051
        self._audit_logger = audit_logger or taint_audit_logger

    def create_session(self, session_id: str) -> TaintGraph:
        """Create a new taint graph for a session. Overwrites existing."""
        graph = TaintGraph(
            session_id,
            audit_logger=self._audit_logger,
            max_nodes=settings.taint_graph_max_nodes_per_session,
        )
        with self._lock:
            self._graphs[session_id] = graph
        logger.debug("Created taint graph for session %s", session_id)
        return graph

    def get_or_create(self, session_id: str) -> TaintGraph:
        """Get existing graph or create a new one."""
        with self._lock:
            if session_id not in self._graphs:
                self._graphs[session_id] = TaintGraph(
                    session_id,
                    audit_logger=self._audit_logger,
                    max_nodes=settings.taint_graph_max_nodes_per_session,
                )
                logger.debug("Auto-created taint graph for session %s", session_id)
            return self._graphs[session_id]

    def get_session(self, session_id: str) -> TaintGraph | None:
        """Get the taint graph for a session, or None."""
        return self._graphs.get(session_id)

    def destroy_session(self, session_id: str) -> bool:
        """Remove and destroy a session's taint graph. Returns True if existed."""
        with self._lock:
            graph = self._graphs.pop(session_id, None)
            # Clean up linked session references
            self._linked_sessions.pop(session_id, None)
            for linked in self._linked_sessions.values():
                linked.discard(session_id)
        if graph is not None:
            logger.debug("Destroyed taint graph for session %s", session_id)
            return True
        return False

    @property
    def active_sessions(self) -> list[str]:
        """List all active session IDs."""
        return list(self._graphs.keys())

    @property
    def session_count(self) -> int:
        return len(self._graphs)

    # --- APEP-051: Cross-agent taint propagation ---

    def link_sessions(self, session_a: str, session_b: str) -> None:
        """Record a bidirectional link between two sessions for cross-agent
        data flow tracking.

        This does not transfer any taint data; it merely records that data may
        flow between the two sessions.  Use :meth:`propagate_cross_agent` to
        actually transfer taint nodes.

        Args:
            session_a: First session identifier.
            session_b: Second session identifier.
        """
        with self._lock:
            self._linked_sessions.setdefault(session_a, set()).add(session_b)
            self._linked_sessions.setdefault(session_b, set()).add(session_a)
        logger.debug("Linked sessions %s <-> %s", session_a, session_b)

    def get_linked_sessions(self, session_id: str) -> set[str]:
        """Return the set of session IDs linked to *session_id*."""
        return set(self._linked_sessions.get(session_id, set()))

    def propagate_cross_agent(
        self,
        source_session_id: str,
        source_node_ids: list[UUID],
        target_session_id: str,
        target_agent_id: str | None = None,
        value: Any = None,
    ) -> TaintNode | None:
        """Propagate taint node(s) from one session/agent to another.

        Creates a new node in the *target* session that references the source
        node(s), preserves the highest taint level, and is labelled with
        ``TaintSource.CROSS_AGENT``.  The sessions are automatically linked.

        Args:
            source_session_id: Session containing the source node(s).
            source_node_ids: Node ID(s) in the source session.
            target_session_id: Session to receive the propagated node.
            target_agent_id: Optional agent ID in the target session.
            value: Optional value associated with the cross-agent transfer.

        Returns:
            The new TaintNode in the target session, or ``None`` if the source
            session does not exist or none of the source nodes are found.
        """
        source_graph = self.get_session(source_session_id)
        if source_graph is None:
            logger.warning(
                "Cross-agent propagation failed: source session %s not found",
                source_session_id,
            )
            return None

        # Resolve all source nodes
        source_nodes: list[TaintNode] = []
        for nid in source_node_ids:
            node = source_graph.get_node(nid)
            if node is not None:
                source_nodes.append(node)

        if not source_nodes:
            logger.warning(
                "Cross-agent propagation failed: no valid source nodes found in session %s",
                source_session_id,
            )
            return None

        # Determine highest taint and max hop depth from source nodes
        highest = TaintLevel.TRUSTED
        max_hop = 0
        for sn in source_nodes:
            highest = _highest_taint(highest, sn.taint_level)
            max_hop = max(max_hop, sn.hop_depth)

        # Link the sessions
        self.link_sessions(source_session_id, target_session_id)

        # Get or create target graph
        target_graph = self.get_or_create(target_session_id)

        # Determine value_hash: use provided value, or fall back to first source node
        if value is not None:
            vh = _hash_value(value)
        else:
            vh = source_nodes[0].value_hash

        # Create the cross-agent node in the target graph.
        # Note: propagated_from contains source_node_ids which live in a
        # different session graph -- this is intentional for lineage tracking.
        cross_node = TaintNode(
            node_id=uuid4(),
            session_id=target_session_id,
            taint_level=highest,
            source=TaintSource.CROSS_AGENT,
            propagated_from=list(source_node_ids),
            value_hash=vh,
            agent_id=target_agent_id,
            tool_call_id=source_nodes[0].tool_call_id,
            hop_depth=max_hop + 1,
            sanitised_by=None,
        )

        with target_graph._lock:
            target_graph._nodes[cross_node.node_id] = cross_node

        # Emit audit event (APEP-052)
        self._audit_logger.emit_from_node(
            event_type=TaintEventType.CROSS_AGENT_PROPAGATED,
            node=cross_node,
        )

        logger.debug(
            "Cross-agent propagation: %s/%s -> %s/%s (taint=%s)",
            source_session_id,
            source_node_ids,
            target_session_id,
            cross_node.node_id,
            cross_node.taint_level.value,
        )
        return cross_node

    # --- Persistence (APEP-045) ---

    async def persist_session(self, session_id: str) -> bool:
        """Persist a session's taint graph to MongoDB (APEP-045).

        Returns True if persisted, False if session not found.
        """
        graph = self.get_session(session_id)
        if graph is None:
            return False

        from app.db import mongodb as db_module

        db = db_module.get_database()
        doc = graph.to_dict()
        doc["persisted_at"] = datetime.utcnow()

        try:
            await db[db_module.TAINT_GRAPHS].replace_one(
                {"session_id": session_id},
                doc,
                upsert=True,
            )
            logger.debug("Persisted taint graph for session %s", session_id)
            return True
        except Exception:
            logger.exception("Failed to persist taint graph for session %s", session_id)
            return False

    async def persist_and_destroy(self, session_id: str) -> bool:
        """Persist to MongoDB then remove from memory."""
        persisted = await self.persist_session(session_id)
        self.destroy_session(session_id)
        return persisted


# Module-level singleton
session_graph_manager = SessionGraphManager()
