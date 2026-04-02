"""Taint API — endpoints for taint source labelling and session graph management.

APEP-041: Taint source labelling API.
APEP-045: Session graph persistence to MongoDB.
APEP-047: Multi-hop propagation through tool call chains.
APEP-048: Sanitisation gates for taint downgrading.
APEP-050: Taint visualisation endpoint.
APEP-051: Cross-agent taint propagation.
APEP-052: Taint audit events.
"""

from __future__ import annotations

from collections import Counter
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.models.policy import (
    SanitisationGate,
    TaintEventType,
    TaintLevel,
    TaintSource,
)
from app.services.taint_graph import (
    sanitisation_gate_registry,
    session_graph_manager,
    taint_audit_logger,
)

router = APIRouter(prefix="/v1/taint", tags=["taint"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


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


# --- Sprint 6 request schemas ---


class PropagateToolChainRequest(BaseModel):
    """Request to propagate taint through a tool call chain (APEP-047)."""

    session_id: str
    parent_node_ids: list[UUID]
    source: TaintSource
    tool_call_id: str
    value: str | None = None
    agent_id: str | None = None


class RegisterSanitisationGateRequest(BaseModel):
    """Request to register a new sanitisation gate (APEP-048)."""

    name: str
    function_pattern: str
    downgrades_from: TaintLevel
    downgrades_to: TaintLevel
    requires_approval: bool = False


class SanitisationGateResponse(BaseModel):
    """Response for a registered sanitisation gate."""

    gate_id: UUID
    name: str
    function_pattern: str
    downgrades_from: TaintLevel
    downgrades_to: TaintLevel
    requires_approval: bool


class ApplySanitisationRequest(BaseModel):
    """Request to apply sanitisation to a node (APEP-048)."""

    session_id: str
    node_id: UUID
    sanitiser_function: str


class VisualisationNodeResponse(BaseModel):
    """A single node in the visualisation graph."""

    id: UUID
    label: str
    taint_level: TaintLevel
    source: TaintSource
    agent_id: str | None = None
    hop_depth: int = 0


class VisualisationEdgeResponse(BaseModel):
    """A single edge in the visualisation graph."""

    source: UUID
    target: UUID
    label: str


class VisualisationMetadata(BaseModel):
    node_count: int
    edge_count: int
    max_hop_depth: int
    taint_level_counts: dict[str, int]


class VisualisationResponse(BaseModel):
    """Full visualisation payload for the taint graph UI (APEP-050)."""

    session_id: str
    nodes: list[VisualisationNodeResponse]
    edges: list[VisualisationEdgeResponse]
    metadata: VisualisationMetadata


class CrossAgentPropagateRequest(BaseModel):
    """Request to propagate taint across an agent boundary (APEP-051)."""

    source_session_id: str
    source_node_ids: list[UUID]
    target_session_id: str
    target_agent_id: str
    value: str | None = None


# ---------------------------------------------------------------------------
# Helper to build a TaintNodeResponse from a TaintNode model
# ---------------------------------------------------------------------------


def _node_response(node: Any) -> TaintNodeResponse:
    return TaintNodeResponse(
        node_id=node.node_id,
        session_id=node.session_id,
        taint_level=node.taint_level,
        source=node.source,
        propagated_from=node.propagated_from,
        value_hash=node.value_hash,
    )


# ---------------------------------------------------------------------------
# Existing endpoints
# ---------------------------------------------------------------------------


@router.post("/label", response_model=TaintNodeResponse)
async def label_taint(request: LabelTaintRequest) -> TaintNodeResponse:
    """Label ingested external data with a taint source (APEP-041)."""
    graph = session_graph_manager.get_or_create(request.session_id)
    node = graph.add_node(
        source=request.source,
        value=request.value,
        taint_level=request.taint_level,
    )
    return _node_response(node)


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
    return _node_response(node)


@router.get("/session/{session_id}", response_model=SessionGraphResponse)
async def get_session_graph(session_id: str) -> SessionGraphResponse:
    """Get the taint graph for a session."""
    graph = session_graph_manager.get_session(session_id)
    if graph is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

    return SessionGraphResponse(
        session_id=graph.session_id,
        node_count=graph.node_count,
        nodes=[_node_response(n) for n in graph.nodes],
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


# ---------------------------------------------------------------------------
# APEP-047: Multi-hop propagation
# ---------------------------------------------------------------------------


@router.post(
    "/propagate/tool-chain",
    response_model=TaintNodeResponse,
    status_code=status.HTTP_200_OK,
)
async def propagate_tool_chain(request: PropagateToolChainRequest) -> TaintNodeResponse:
    """Propagate taint through a tool call chain (APEP-047)."""
    graph = session_graph_manager.get_session(request.session_id)
    if graph is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{request.session_id}' not found",
        )

    node = graph.propagate_tool_chain(
        parent_ids=request.parent_node_ids,
        source=request.source,
        tool_call_id=request.tool_call_id,
        value=request.value,
        agent_id=request.agent_id,
    )
    return _node_response(node)


# ---------------------------------------------------------------------------
# APEP-048: Sanitisation gates
# ---------------------------------------------------------------------------


@router.post(
    "/sanitisation-gates",
    response_model=SanitisationGateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_sanitisation_gate(
    request: RegisterSanitisationGateRequest,
) -> SanitisationGateResponse:
    """Register a new sanitisation gate (APEP-048)."""
    gate = SanitisationGate(
        name=request.name,
        function_pattern=request.function_pattern,
        downgrades_from=request.downgrades_from,
        downgrades_to=request.downgrades_to,
        requires_approval=request.requires_approval,
    )
    registered = sanitisation_gate_registry.register(gate)
    return SanitisationGateResponse(
        gate_id=registered.gate_id,
        name=registered.name,
        function_pattern=registered.function_pattern,
        downgrades_from=registered.downgrades_from,
        downgrades_to=registered.downgrades_to,
        requires_approval=registered.requires_approval,
    )


@router.get("/sanitisation-gates", response_model=list[SanitisationGateResponse])
async def list_sanitisation_gates() -> list[SanitisationGateResponse]:
    """List all registered sanitisation gates (APEP-048)."""
    gates = sanitisation_gate_registry.list_gates()
    return [
        SanitisationGateResponse(
            gate_id=g.gate_id,
            name=g.name,
            function_pattern=g.function_pattern,
            downgrades_from=g.downgrades_from,
            downgrades_to=g.downgrades_to,
            requires_approval=g.requires_approval,
        )
        for g in gates
    ]


@router.delete(
    "/sanitisation-gates/{gate_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_sanitisation_gate(gate_id: UUID) -> None:
    """Remove a sanitisation gate (APEP-048)."""
    removed = sanitisation_gate_registry.remove(gate_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sanitisation gate '{gate_id}' not found",
        )


@router.post("/sanitise", response_model=TaintNodeResponse)
async def apply_sanitisation(request: ApplySanitisationRequest) -> TaintNodeResponse:
    """Apply sanitisation to a taint node, producing a downgraded copy (APEP-048)."""
    graph = session_graph_manager.get_session(request.session_id)
    if graph is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{request.session_id}' not found",
        )

    node = graph.apply_sanitisation(
        node_id=request.node_id,
        sanitiser_function=request.sanitiser_function,
        registry=sanitisation_gate_registry,
    )
    if node is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"No matching sanitisation gate for function "
                f"'{request.sanitiser_function}' on node '{request.node_id}'"
            ),
        )
    return _node_response(node)


# ---------------------------------------------------------------------------
# APEP-050: Taint visualisation
# ---------------------------------------------------------------------------


@router.get(
    "/session/{session_id}/visualisation",
    response_model=VisualisationResponse,
)
async def get_session_visualisation(session_id: str) -> VisualisationResponse:
    """Return the taint graph as a nodes+edges structure for the UI (APEP-050)."""
    graph = session_graph_manager.get_session(session_id)
    if graph is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found",
        )

    vis_nodes: list[VisualisationNodeResponse] = []
    taint_counts: Counter[str] = Counter()
    max_hop = 0

    for n in graph.nodes:
        hop = getattr(n, "hop_depth", 0)
        max_hop = max(max_hop, hop)
        taint_counts[n.taint_level.value] += 1
        vis_nodes.append(
            VisualisationNodeResponse(
                id=n.node_id,
                label=f"{n.source.value}:{n.taint_level.value}",
                taint_level=n.taint_level,
                source=n.source,
                agent_id=getattr(n, "agent_id", None),
                hop_depth=hop,
            )
        )

    vis_edges: list[VisualisationEdgeResponse] = []
    for n in graph.nodes:
        for parent_id in n.propagated_from:
            vis_edges.append(
                VisualisationEdgeResponse(
                    source=parent_id,
                    target=n.node_id,
                    label="propagated_from",
                )
            )

    return VisualisationResponse(
        session_id=session_id,
        nodes=vis_nodes,
        edges=vis_edges,
        metadata=VisualisationMetadata(
            node_count=len(vis_nodes),
            edge_count=len(vis_edges),
            max_hop_depth=max_hop,
            taint_level_counts=dict(taint_counts),
        ),
    )


# ---------------------------------------------------------------------------
# APEP-051: Cross-agent propagation
# ---------------------------------------------------------------------------


@router.post("/propagate/cross-agent", response_model=TaintNodeResponse)
async def propagate_cross_agent(
    request: CrossAgentPropagateRequest,
) -> TaintNodeResponse:
    """Propagate taint across an agent boundary (APEP-051)."""
    node = session_graph_manager.propagate_cross_agent(
        source_session_id=request.source_session_id,
        source_node_ids=request.source_node_ids,
        target_session_id=request.target_session_id,
        target_agent_id=request.target_agent_id,
        value=request.value,
    )
    if node is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Source session '{request.source_session_id}' not found "
                f"or source nodes do not exist"
            ),
        )
    return _node_response(node)


# ---------------------------------------------------------------------------
# APEP-052: Taint audit events
# ---------------------------------------------------------------------------


@router.get("/audit-events/{session_id}")
async def get_audit_events(
    session_id: str,
    event_type: TaintEventType | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=10000),
) -> list[dict[str, Any]]:
    """Get taint audit events for a session (APEP-052)."""
    events = taint_audit_logger.get_events(
        session_id=session_id,
        event_type=event_type,
        limit=limit,
    )
    return [e.model_dump(mode="json") for e in events]
