"""TaintGraph — per-session in-memory DAG for taint tracking and propagation.

Sprint 5:
APEP-038: TaintGraph data structure (directed acyclic graph of TaintNodes per session).
APEP-039: Session lifecycle management (create, update, destroy taint graphs).
APEP-040: Taint propagation engine (output inherits highest taint from inputs).
APEP-044: QUARANTINE level assignment on injection signature detection.
APEP-045: Session graph persistence to MongoDB for forensic inspection.

Sprint 6:
APEP-047: Multi-hop taint propagation across tool call chains within session.
APEP-048: Sanitisation gate API — declare sanitisation functions that downgrade taint.
APEP-049: Injection signature library (prompt injection patterns → QUARANTINE).
APEP-051: Cross-agent taint propagation — taint persists across agent boundaries.
APEP-052: Taint audit events — log every taint assignment and propagation.
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import re
import threading
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from app.models.policy import (
    SanitisationGate,
    TaintAuditEvent,
    TaintEventType,
    TaintLevel,
    TaintNode,
    TaintSource,
)

logger = logging.getLogger(__name__)

# --- Injection signature patterns (APEP-044) ---

INJECTION_SIGNATURES: list[re.Pattern[str]] = [
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


def check_injection_signatures(text: str) -> bool:
    """Return True if text matches any known injection signature."""
    for pattern in INJECTION_SIGNATURES:
        if pattern.search(text):
            return True
    return False


def check_injection_signature_id(text: str) -> str | None:
    """Return the signature_id of the first matching injection pattern, or None.

    Uses the expanded InjectionSignatureLibrary (APEP-049) if available,
    falling back to the legacy INJECTION_SIGNATURES list.
    """
    try:
        from app.services.injection_signatures import injection_library

        matches = injection_library.check(text)
        if matches:
            return matches[0].signature_id
    except ImportError:
        pass

    # Fallback to legacy list
    for i, pattern in enumerate(INJECTION_SIGNATURES):
        if pattern.search(text):
            return f"LEGACY-{i:03d}"
    return None


class TaintGraph:
    """Per-session directed acyclic graph of TaintNodes.

    Thread-safe. Each node tracks its taint level, source, and which parent
    nodes it was propagated from.
    """

    __slots__ = ("session_id", "_nodes", "_children", "_lock", "created_at")

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._nodes: dict[UUID, TaintNode] = {}
        self._children: dict[UUID, list[UUID]] = {}  # parent -> children edges
        self._lock = threading.Lock()
        self.created_at = datetime.utcnow()

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
        # Determine taint level
        if taint_level is None:
            taint_level = self._infer_taint_level(source, value)

        # If propagated from parents, inherit highest taint (APEP-040)
        # Skip inheritance for sanitisation nodes — they explicitly downgrade (APEP-048)
        if propagated_from and sanitised_by is None:
            parent_taint = self._get_highest_parent_taint(propagated_from)
            taint_level = _highest_taint(taint_level, parent_taint)

        # Auto-compute hop_depth from parents (APEP-047)
        if propagated_from and hop_depth == 0:
            hop_depth = self._compute_hop_depth(propagated_from)

        # Check for injection signatures → QUARANTINE (APEP-044/049)
        matched_signature: str | None = None
        if value is not None and isinstance(value, str):
            matched_signature = check_injection_signature_id(value)
            if matched_signature is not None:
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
            self._nodes[node.node_id] = node
            # Register parent→child edges
            for parent_id in node.propagated_from:
                self._children.setdefault(parent_id, []).append(node.node_id)

        # Emit taint audit event (APEP-052)
        event_type = TaintEventType.TAINT_ASSIGNED
        if propagated_from:
            event_type = TaintEventType.TAINT_PROPAGATED
        if taint_level == TaintLevel.QUARANTINE and matched_signature:
            event_type = TaintEventType.TAINT_QUARANTINED

        taint_audit_logger.emit(TaintAuditEvent(
            event_type=event_type,
            session_id=self.session_id,
            node_id=node.node_id,
            agent_id=agent_id,
            taint_level=taint_level,
            source=source,
            propagated_from=propagated_from or [],
            tool_call_id=tool_call_id,
            hop_depth=hop_depth,
            matched_signature=matched_signature,
        ))

        return node

    def get_node(self, node_id: UUID) -> TaintNode | None:
        """Get a node by ID."""
        return self._nodes.get(node_id)

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

    # --- Multi-hop tool chain propagation (APEP-047) ---

    def propagate_tool_chain(
        self,
        parent_ids: list[UUID],
        source: TaintSource,
        tool_call_id: str,
        value: Any = None,
        agent_id: str | None = None,
    ) -> TaintNode:
        """Propagate taint through a tool call chain.

        Creates a node that tracks which tool call produced it and the hop
        depth from the original data source. Hop depth is auto-incremented
        from the deepest parent.
        """
        return self.add_node(
            source=source,
            value=value,
            propagated_from=parent_ids,
            tool_call_id=tool_call_id,
            agent_id=agent_id,
        )

    # --- Sanitisation gate (APEP-048) ---

    def apply_sanitisation(
        self,
        node_id: UUID,
        sanitiser_function: str,
        registry: SanitisationGateRegistry,
    ) -> TaintNode | None:
        """Apply a sanitisation gate to downgrade taint on a node.

        Looks up a matching gate from the registry. If the gate's
        downgrades_from matches the node's current taint level, creates
        a new child node with the downgraded taint level.

        Returns the new sanitised node, or None if no matching gate or
        the node's taint level does not match the gate.
        """
        source_node = self.get_node(node_id)
        if source_node is None:
            return None

        gate = registry.find_gate(sanitiser_function)
        if gate is None:
            return None

        if source_node.taint_level != gate.downgrades_from:
            return None

        new_node = self.add_node(
            source=TaintSource.SANITISED,
            taint_level=gate.downgrades_to,
            propagated_from=[node_id],
            sanitised_by=sanitiser_function,
            agent_id=source_node.agent_id,
        )

        # Emit downgrade audit event (APEP-052)
        taint_audit_logger.emit(TaintAuditEvent(
            event_type=TaintEventType.TAINT_DOWNGRADED,
            session_id=self.session_id,
            node_id=new_node.node_id,
            agent_id=source_node.agent_id,
            taint_level=gate.downgrades_to,
            previous_taint_level=source_node.taint_level,
            source=TaintSource.SANITISED,
            propagated_from=[node_id],
            sanitised_by=sanitiser_function,
        ))

        return new_node

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

    def _compute_hop_depth(self, parent_ids: list[UUID]) -> int:
        """Compute hop depth as max parent hop depth + 1 (APEP-047)."""
        max_depth = 0
        for pid in parent_ids:
            parent = self._nodes.get(pid)
            if parent:
                max_depth = max(max_depth, parent.hop_depth)
        return max_depth + 1

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


class SessionGraphManager:
    """Manages per-session TaintGraph instances (APEP-039).

    Thread-safe singleton that creates, retrieves, and destroys session graphs.
    """

    def __init__(self) -> None:
        self._graphs: dict[str, TaintGraph] = {}
        self._linked_sessions: dict[str, set[str]] = {}  # APEP-051
        self._lock = threading.Lock()

    def create_session(self, session_id: str) -> TaintGraph:
        """Create a new taint graph for a session. Overwrites existing."""
        graph = TaintGraph(session_id)
        with self._lock:
            self._graphs[session_id] = graph
        logger.debug("Created taint graph for session %s", session_id)
        return graph

    def get_or_create(self, session_id: str) -> TaintGraph:
        """Get existing graph or create a new one."""
        with self._lock:
            if session_id not in self._graphs:
                self._graphs[session_id] = TaintGraph(session_id)
                logger.debug("Auto-created taint graph for session %s", session_id)
            return self._graphs[session_id]

    def get_session(self, session_id: str) -> TaintGraph | None:
        """Get the taint graph for a session, or None."""
        return self._graphs.get(session_id)

    def destroy_session(self, session_id: str) -> bool:
        """Remove and destroy a session's taint graph. Returns True if existed."""
        with self._lock:
            graph = self._graphs.pop(session_id, None)
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

    # --- Cross-agent taint propagation (APEP-051) ---

    def propagate_cross_agent(
        self,
        source_session_id: str,
        source_node_ids: list[UUID],
        target_session_id: str,
        target_agent_id: str,
        value: Any = None,
    ) -> TaintNode | None:
        """Propagate taint across an agent boundary.

        Reads taint from source nodes in the source session, then creates
        a new node in the target session with source=CROSS_AGENT and the
        highest taint level from the source nodes preserved.
        """
        source_graph = self.get_session(source_session_id)
        if source_graph is None:
            return None

        # Determine highest taint from source nodes
        highest = TaintLevel.TRUSTED
        for nid in source_node_ids:
            node = source_graph.get_node(nid)
            if node:
                highest = _highest_taint(highest, node.taint_level)

        # Compute max hop depth from source nodes
        max_hop = 0
        for nid in source_node_ids:
            node = source_graph.get_node(nid)
            if node:
                max_hop = max(max_hop, node.hop_depth)

        target_graph = self.get_or_create(target_session_id)
        new_node = target_graph.add_node(
            source=TaintSource.CROSS_AGENT,
            value=value,
            taint_level=highest,
            agent_id=target_agent_id,
            hop_depth=max_hop + 1,
        )

        # Track session linkage
        with self._lock:
            self._linked_sessions.setdefault(source_session_id, set()).add(
                target_session_id
            )

        # Emit cross-agent audit event (APEP-052)
        taint_audit_logger.emit(TaintAuditEvent(
            event_type=TaintEventType.CROSS_AGENT_PROPAGATED,
            session_id=target_session_id,
            node_id=new_node.node_id,
            agent_id=target_agent_id,
            taint_level=highest,
            source=TaintSource.CROSS_AGENT,
            propagated_from=source_node_ids,
            hop_depth=max_hop + 1,
        ))

        return new_node

    def get_linked_sessions(self, session_id: str) -> set[str]:
        """Return session IDs linked to the given session via cross-agent propagation."""
        return self._linked_sessions.get(session_id, set()).copy()


class SanitisationGateRegistry:
    """Registry of sanitisation functions that can downgrade taint (APEP-048).

    Security teams register gates declaring which functions are trusted
    sanitisers capable of cleaning tainted data.
    """

    def __init__(self) -> None:
        self._gates: dict[UUID, SanitisationGate] = {}
        self._lock = threading.Lock()

    def register(self, gate: SanitisationGate) -> SanitisationGate:
        """Register a sanitisation gate."""
        with self._lock:
            self._gates[gate.gate_id] = gate
        logger.debug("Registered sanitisation gate %s (%s)", gate.name, gate.gate_id)
        return gate

    def list_gates(self) -> list[SanitisationGate]:
        """List all registered sanitisation gates."""
        return list(self._gates.values())

    def remove(self, gate_id: UUID) -> bool:
        """Remove a sanitisation gate. Returns True if existed."""
        with self._lock:
            return self._gates.pop(gate_id, None) is not None

    def find_gate(self, function_name: str) -> SanitisationGate | None:
        """Find a matching enabled gate for the given function name.

        Matches using glob/fnmatch against the gate's function_pattern.
        """
        for gate in self._gates.values():
            if not gate.enabled:
                continue
            if fnmatch.fnmatch(function_name, gate.function_pattern):
                return gate
        return None


class TaintAuditLogger:
    """Collects taint audit events and flushes them to MongoDB (APEP-052).

    Events are buffered in memory per session for efficient batch writes.
    """

    def __init__(self) -> None:
        self._events: list[TaintAuditEvent] = []
        self._lock = threading.Lock()

    def emit(self, event: TaintAuditEvent) -> None:
        """Record a taint audit event."""
        with self._lock:
            self._events.append(event)
        logger.debug(
            "Taint audit event: %s session=%s node=%s level=%s",
            event.event_type.value,
            event.session_id,
            event.node_id,
            event.taint_level.value,
        )

    def get_events(
        self,
        session_id: str,
        event_type: TaintEventType | None = None,
        limit: int = 100,
    ) -> list[TaintAuditEvent]:
        """Get audit events for a session, optionally filtered by type."""
        with self._lock:
            filtered = [
                e for e in self._events
                if e.session_id == session_id
                and (event_type is None or e.event_type == event_type)
            ]
        return filtered[-limit:]

    async def flush(self, session_id: str | None = None) -> int:
        """Write buffered events to MongoDB. Returns number of events flushed.

        If session_id is given, only flush events for that session.
        """
        from app.db import mongodb as db_module

        with self._lock:
            if session_id:
                to_flush = [e for e in self._events if e.session_id == session_id]
                self._events = [e for e in self._events if e.session_id != session_id]
            else:
                to_flush = list(self._events)
                self._events.clear()

        if not to_flush:
            return 0

        db = db_module.get_database()
        try:
            docs = [e.model_dump(mode="json") for e in to_flush]
            await db[TAINT_AUDIT_EVENTS].insert_many(docs)
            return len(docs)
        except Exception:
            logger.exception("Failed to flush %d taint audit events", len(to_flush))
            # Re-add events on failure
            with self._lock:
                self._events.extend(to_flush)
            return 0

    def clear(self, session_id: str | None = None) -> None:
        """Clear buffered events (for testing)."""
        with self._lock:
            if session_id:
                self._events = [e for e in self._events if e.session_id != session_id]
            else:
                self._events.clear()

    @property
    def event_count(self) -> int:
        return len(self._events)


# Collection name for taint audit events
TAINT_AUDIT_EVENTS = "taint_audit_events"

# Module-level singletons
taint_audit_logger = TaintAuditLogger()
sanitisation_gate_registry = SanitisationGateRegistry()
session_graph_manager = SessionGraphManager()
