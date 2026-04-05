"""Pydantic models for the simulation API (Sprint 19 — APEP-151/152/154)."""

from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.models.policy import Decision, DelegationHop, PolicyRule


# --- Simulation Request / Response ---


class SimulateRequest(BaseModel):
    """Request body for POST /v1/simulate (APEP-151)."""

    session_id: str = Field(default="sim-session", description="Session identifier")
    agent_id: str = Field(..., description="Agent making the tool call")
    tool_name: str = Field(..., description="Tool being invoked")
    tool_args: dict[str, Any] = Field(default_factory=dict)
    delegation_chain: list[str] = Field(default_factory=list)
    delegation_hops: list[DelegationHop] = Field(default_factory=list)
    taint_node_ids: list[UUID] = Field(default_factory=list)
    policy_version: str = Field(
        default="current",
        description="Policy version label to evaluate against",
    )
    policy_rules: list[PolicyRule] | None = Field(
        default=None,
        description="Optional explicit rule set to evaluate against instead of current rules",
    )


class SimulationStepResponse(BaseModel):
    """Detail of a single evaluation step in the simulation trace."""

    step: str = Field(..., description="Step name (e.g. 'role_resolution', 'rule_match')")
    passed: bool = Field(..., description="Whether this step passed")
    detail: str = Field(default="", description="Human-readable explanation")


class SimulateResponse(BaseModel):
    """Full simulation result (APEP-152).

    Includes: decision, matched rule, risk score, taint evaluation,
    delegation chain result, and step-by-step evaluation trace.
    """

    request_id: UUID = Field(default_factory=uuid4)
    decision: Decision
    matched_rule_id: UUID | None = None
    matched_rule_name: str = ""
    risk_score: float = 0.0
    taint_eval: dict[str, Any] = Field(default_factory=dict)
    chain_result: dict[str, Any] = Field(default_factory=dict)
    resolved_roles: list[str] = Field(default_factory=list)
    steps: list[SimulationStepResponse] = Field(default_factory=list)
    reason: str = ""
    latency_ms: int = 0
    policy_version: str = "current"


# --- Simulation Comparison (APEP-154) ---


class SimulationCompareRequest(BaseModel):
    """Run the same request against two policy versions and diff results."""

    session_id: str = Field(default="sim-session")
    agent_id: str
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    delegation_chain: list[str] = Field(default_factory=list)
    delegation_hops: list[DelegationHop] = Field(default_factory=list)
    taint_node_ids: list[UUID] = Field(default_factory=list)

    version_a_label: str = Field(default="version_a")
    version_a_rules: list[PolicyRule]

    version_b_label: str = Field(default="version_b")
    version_b_rules: list[PolicyRule]


class SimulationChangeEntry(BaseModel):
    """A single field that changed between two simulation runs."""

    field: str
    from_value: Any = Field(alias="from")
    to_value: Any = Field(alias="to")

    model_config = {"populate_by_name": True}


class SimulationCompareResponse(BaseModel):
    """Diff of two simulation runs (APEP-154)."""

    decision_changed: bool
    matched_rule_changed: bool
    risk_score_changed: bool
    version_a: SimulateResponse
    version_b: SimulateResponse
    changes: list[dict[str, Any]] = Field(default_factory=list)


# --- Test Vector (APEP-155) ---


class TestVector(BaseModel):
    """A single test vector — a curated tool call payload with expected outcome."""

    vector_id: str = Field(..., description="Unique vector identifier, e.g. TV-001")
    name: str = Field(..., description="Short human-readable name")
    category: str = Field(
        ...,
        description="Category: benign, privilege_escalation, injection, "
        "data_exfiltration, confused_deputy, taint_bypass",
    )
    description: str = Field(default="")
    request: SimulateRequest
    expected_decision: Decision
    tags: list[str] = Field(default_factory=list)


class TestVectorSuiteResult(BaseModel):
    """Result of running a test vector suite."""

    total: int
    passed: int
    failed: int
    results: list[dict[str, Any]] = Field(default_factory=list)
