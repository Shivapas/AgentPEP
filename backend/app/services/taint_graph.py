"""TaintGraph — per-session in-memory DAG for taint tracking and propagation.

APEP-038: TaintGraph data structure (directed acyclic graph of TaintNodes per session).
APEP-039: Session lifecycle management (create, update, destroy taint graphs).
APEP-040: Taint propagation engine (output inherits highest taint from inputs).
APEP-044: QUARANTINE level assignment on injection signature detection.
APEP-045: Session graph persistence to MongoDB for forensic inspection.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from app.models.policy import TaintLevel, TaintNode, TaintSource

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
        if propagated_from:
            parent_taint = self._get_highest_parent_taint(propagated_from)
            taint_level = _highest_taint(taint_level, parent_taint)

        # Check for injection signatures → QUARANTINE (APEP-044)
        if value is not None and isinstance(value, str) and check_injection_signatures(value):
            taint_level = TaintLevel.QUARANTINE

        node = TaintNode(
            node_id=node_id or uuid4(),
            session_id=self.session_id,
            taint_level=taint_level,
            source=source,
            propagated_from=propagated_from or [],
            value_hash=_hash_value(value) if value is not None else None,
        )

        with self._lock:
            self._nodes[node.node_id] = node
            # Register parent→child edges
            for parent_id in node.propagated_from:
                self._children.setdefault(parent_id, []).append(node.node_id)

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


class SessionGraphManager:
    """Manages per-session TaintGraph instances (APEP-039).

    Thread-safe singleton that creates, retrieves, and destroys session graphs.
    """

    def __init__(self) -> None:
        self._graphs: dict[str, TaintGraph] = {}
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


# Module-level singleton
session_graph_manager = SessionGraphManager()
