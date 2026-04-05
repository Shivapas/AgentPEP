"""Simulation API — DRY_RUN evaluation for CI/CD integration.

Sprint 19: APEP-151, APEP-152, APEP-154, APEP-155.
"""

from typing import Any

from fastapi import APIRouter, Query

from app.models.policy import ToolCallRequest
from app.models.simulation import (
    SimulateRequest,
    SimulateResponse,
    SimulationCompareRequest,
    SimulationCompareResponse,
    SimulationStepResponse,
    TestVector,
    TestVectorSuiteResult,
)
from app.services.simulation_engine import simulation_engine
from app.services.test_vectors import (
    VECTORS_BY_CATEGORY,
    VECTORS_BY_ID,
    get_vectors,
)

router = APIRouter(prefix="/v1", tags=["simulate"])


def _to_tool_call_request(req: SimulateRequest) -> ToolCallRequest:
    """Convert a SimulateRequest to a ToolCallRequest with dry_run=True."""
    return ToolCallRequest(
        session_id=req.session_id,
        agent_id=req.agent_id,
        tool_name=req.tool_name,
        tool_args=req.tool_args,
        delegation_chain=req.delegation_chain,
        delegation_hops=req.delegation_hops,
        taint_node_ids=req.taint_node_ids,
        dry_run=True,
    )


def _result_to_response(result: Any) -> SimulateResponse:
    """Convert a SimulationResult to a SimulateResponse."""
    return SimulateResponse(
        request_id=result.request_id,
        decision=result.decision,
        matched_rule_id=result.matched_rule_id,
        matched_rule_name=result.matched_rule_name,
        risk_score=result.risk_score,
        taint_eval=result.taint_eval,
        chain_result=result.chain_result,
        resolved_roles=result.resolved_roles,
        steps=[
            SimulationStepResponse(step=s.step, passed=s.passed, detail=s.detail)
            for s in result.steps
        ],
        reason=result.reason,
        latency_ms=result.latency_ms,
        policy_version=result.policy_version,
    )


# --- APEP-151: POST /v1/simulate ---

@router.post("/simulate", response_model=SimulateResponse)
async def simulate(request: SimulateRequest) -> SimulateResponse:
    """Evaluate a tool call request against the full policy stack without enforcement.

    Returns the full simulation result including decision, matched rule,
    risk score, taint evaluation, delegation chain result, and step-by-step trace.
    """
    tool_call = _to_tool_call_request(request)
    result = await simulation_engine.simulate(
        tool_call,
        policy_rules=request.policy_rules,
        policy_version=request.policy_version,
    )
    return _result_to_response(result)


# --- APEP-154: POST /v1/simulate/compare ---

@router.post("/simulate/compare", response_model=SimulationCompareResponse)
async def simulate_compare(request: SimulationCompareRequest) -> SimulationCompareResponse:
    """Run the same request against two policy versions and diff results."""
    tool_call = ToolCallRequest(
        session_id=request.session_id,
        agent_id=request.agent_id,
        tool_name=request.tool_name,
        tool_args=request.tool_args,
        delegation_chain=request.delegation_chain,
        delegation_hops=request.delegation_hops,
        taint_node_ids=request.taint_node_ids,
        dry_run=True,
    )

    diff = await simulation_engine.compare(
        tool_call,
        rules_a=request.version_a_rules,
        rules_b=request.version_b_rules,
        version_a=request.version_a_label,
        version_b=request.version_b_label,
    )

    return SimulationCompareResponse(
        decision_changed=diff.decision_changed,
        matched_rule_changed=diff.matched_rule_changed,
        risk_score_changed=diff.risk_score_changed,
        version_a=_result_to_response(diff.result_a),
        version_b=_result_to_response(diff.result_b),
        changes=diff._compute_changes(),
    )


# --- APEP-155: Test Vector Library ---

@router.get("/simulate/vectors", response_model=list[TestVector])
async def list_vectors(
    category: str | None = Query(None, description="Filter by category"),
    tag: str | None = Query(None, description="Filter by tag"),
) -> list[TestVector]:
    """List available test vectors from the curated library."""
    tags = [tag] if tag else None
    return get_vectors(category=category, tags=tags)


@router.get("/simulate/vectors/categories", response_model=list[str])
async def list_vector_categories() -> list[str]:
    """List available test vector categories."""
    return sorted(VECTORS_BY_CATEGORY.keys())


@router.get("/simulate/vectors/{vector_id}", response_model=TestVector)
async def get_vector(vector_id: str) -> TestVector:
    """Get a specific test vector by ID."""
    from fastapi import HTTPException

    vector = VECTORS_BY_ID.get(vector_id)
    if vector is None:
        raise HTTPException(status_code=404, detail=f"Test vector '{vector_id}' not found")
    return vector


@router.post("/simulate/vectors/run", response_model=TestVectorSuiteResult)
async def run_vector_suite(
    category: str | None = Query(None, description="Run vectors from specific category"),
    tag: str | None = Query(None, description="Run vectors matching tag"),
    vector_ids: list[str] | None = None,
) -> TestVectorSuiteResult:
    """Run a suite of test vectors and return pass/fail results.

    Used by CI/CD pipelines to validate policy configurations.
    """
    if vector_ids:
        vectors = [VECTORS_BY_ID[vid] for vid in vector_ids if vid in VECTORS_BY_ID]
    else:
        tags = [tag] if tag else None
        vectors = get_vectors(category=category, tags=tags)

    results: list[dict[str, Any]] = []
    passed = 0
    failed = 0

    for vector in vectors:
        tool_call = _to_tool_call_request(vector.request)
        sim_result = await simulation_engine.simulate(
            tool_call,
            policy_rules=vector.request.policy_rules,
        )

        # Compare actual decision to expected
        actual_decision = sim_result.decision
        # In simulation mode, the decision reflects the would-be enforcement decision
        vector_passed = actual_decision == vector.expected_decision

        if vector_passed:
            passed += 1
        else:
            failed += 1

        results.append({
            "vector_id": vector.vector_id,
            "name": vector.name,
            "category": vector.category,
            "expected_decision": vector.expected_decision.value,
            "actual_decision": actual_decision.value,
            "passed": vector_passed,
            "reason": sim_result.reason,
            "latency_ms": sim_result.latency_ms,
        })

    return TestVectorSuiteResult(
        total=len(vectors),
        passed=passed,
        failed=failed,
        results=results,
    )
