"""Taint API — endpoints for taint source labelling and session graph management.

APEP-041: Taint source labelling API.
APEP-045: Session graph persistence to MongoDB.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.models.policy import TaintLevel, TaintSource
from app.services.taint_graph import session_graph_manager

router = APIRouter(prefix="/v1/taint", tags=["taint"])


# --- Request/Response schemas ---


class LabelTaintRequest(BaseModel):
    """Request to label data with a taint source."""

    session_id: str
    source: TaintSource
    value: str | None = None
    taint_level: TaintLevel | None = None


class PropagateTaintRequest(BaseModel):
    """Request to propagate taint from parent nodes."""

    session_id: str
    parent_node_ids: list[UUID]
    source: TaintSource
    value: str | None = None


class TaintNodeResponse(BaseModel):
    node_id: UUID
    session_id: str
    taint_level: TaintLevel
    source: TaintSource
    propagated_from: list[UUID] = Field(default_factory=list)
    value_hash: str | None = None


class SessionGraphResponse(BaseModel):
    session_id: str
    node_count: int
    nodes: list[TaintNodeResponse]


# --- Endpoints ---


@router.post("/label", response_model=TaintNodeResponse)
async def label_taint(request: LabelTaintRequest) -> TaintNodeResponse:
    """Label ingested external data with a taint source (APEP-041)."""
    graph = session_graph_manager.get_or_create(request.session_id)
    node = graph.add_node(
        source=request.source,
        value=request.value,
        taint_level=request.taint_level,
    )
    return TaintNodeResponse(
        node_id=node.node_id,
        session_id=node.session_id,
        taint_level=node.taint_level,
        source=node.source,
        propagated_from=node.propagated_from,
        value_hash=node.value_hash,
    )


@router.post("/propagate", response_model=TaintNodeResponse)
async def propagate_taint(request: PropagateTaintRequest) -> TaintNodeResponse:
    """Propagate taint from parent nodes to a new output node (APEP-040)."""
    graph = session_graph_manager.get_session(request.session_id)
    if graph is None:
        raise HTTPException(status_code=404, detail=f"Session '{request.session_id}' not found")

    node = graph.propagate(
        parent_ids=request.parent_node_ids,
        source=request.source,
        value=request.value,
    )
    return TaintNodeResponse(
        node_id=node.node_id,
        session_id=node.session_id,
        taint_level=node.taint_level,
        source=node.source,
        propagated_from=node.propagated_from,
        value_hash=node.value_hash,
    )


@router.get("/session/{session_id}", response_model=SessionGraphResponse)
async def get_session_graph(session_id: str) -> SessionGraphResponse:
    """Get the taint graph for a session."""
    graph = session_graph_manager.get_session(session_id)
    if graph is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

    return SessionGraphResponse(
        session_id=graph.session_id,
        node_count=graph.node_count,
        nodes=[
            TaintNodeResponse(
                node_id=n.node_id,
                session_id=n.session_id,
                taint_level=n.taint_level,
                source=n.source,
                propagated_from=n.propagated_from,
                value_hash=n.value_hash,
            )
            for n in graph.nodes
        ],
    )


@router.post("/session/{session_id}/persist")
async def persist_session(session_id: str) -> dict[str, Any]:
    """Persist a session's taint graph to MongoDB (APEP-045)."""
    ok = await session_graph_manager.persist_session(session_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    return {"status": "persisted", "session_id": session_id}


@router.delete("/session/{session_id}")
async def destroy_session(session_id: str) -> dict[str, Any]:
    """Destroy a session's taint graph."""
    existed = session_graph_manager.destroy_session(session_id)
    if not existed:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    return {"status": "destroyed", "session_id": session_id}
