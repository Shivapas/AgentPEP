"""Sprint 36 API endpoints — ToolTrust enhancements.

APEP-286: Trust degradation engine endpoints.
APEP-287: DEFER decision management endpoints.
APEP-288: STEP_UP challenge management endpoints.
APEP-289: Policy conflict detection and resolution endpoints.
APEP-290: Multi-tenancy isolation endpoints.
APEP-285: Hash-chained context endpoints.
"""

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.models.sprint36 import (
    ConflictReport,
    ConflictResolutionStrategy,
    DeferCondition,
    DeferDecisionRecord,
    HashChainedContextEntry,
    HashChainVerificationResult,
    PolicyConflict,
    StepUpChallenge,
    TenantIsolationConfig,
    TenantIsolationViolation,
    TrustDegradationRecord,
)

router = APIRouter(prefix="/v1/sprint36", tags=["sprint36"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class AppendContextRequest(BaseModel):
    session_id: str
    content: str
    source: str = ""
    agent_id: str | None = None
    tenant_id: str = "default"


class RecordDegradationRequest(BaseModel):
    session_id: str
    interaction_type: str
    taint_level: str = "TRUSTED"
    agent_id: str = ""
    tool_name: str = ""
    tenant_id: str = "default"


class CreateDeferRequest(BaseModel):
    request_id: UUID
    session_id: str
    agent_id: str
    tool_name: str
    condition: str = "PENDING_REVIEW"
    reason: str = ""
    timeout_s: int = 60
    tenant_id: str = "default"


class ResolveDeferRequest(BaseModel):
    resolution: str


class CreateStepUpRequest(BaseModel):
    request_id: UUID
    session_id: str
    agent_id: str
    required_factors: list[str]
    tenant_id: str = "default"


class VerifyFactorRequest(BaseModel):
    factor: str


class ResolveConflictRequest(BaseModel):
    resolution_detail: str


class CheckAccessRequest(BaseModel):
    source_tenant_id: str
    target_tenant_id: str
    resource_type: str = "session"
    resource_id: str = ""


class AccessCheckResponse(BaseModel):
    allowed: bool
    reason: str


class TrustResetRequest(BaseModel):
    session_id: str


# ---------------------------------------------------------------------------
# Hash-Chained Context (APEP-285)
# ---------------------------------------------------------------------------


@router.post("/context/append", response_model=HashChainedContextEntry)
async def append_context(request: AppendContextRequest) -> HashChainedContextEntry:
    """Append a new entry to a session's hash-chained context."""
    from app.services.hash_chained_context import hash_chained_context

    return await hash_chained_context.append(
        session_id=request.session_id,
        content=request.content,
        source=request.source,
        agent_id=request.agent_id,
        tenant_id=request.tenant_id,
    )


@router.get("/context/{session_id}/verify", response_model=HashChainVerificationResult)
async def verify_context_chain(session_id: str) -> HashChainVerificationResult:
    """Verify integrity of a session's hash-chained context."""
    from app.services.hash_chained_context import hash_chained_context

    return await hash_chained_context.verify_chain(session_id)


@router.get("/context/{session_id}", response_model=list[HashChainedContextEntry])
async def get_context_chain(session_id: str) -> list[HashChainedContextEntry]:
    """Get all entries in a session's hash-chained context."""
    from app.services.hash_chained_context import hash_chained_context

    return await hash_chained_context.get_chain(session_id)


# ---------------------------------------------------------------------------
# Trust Degradation Engine (APEP-286)
# ---------------------------------------------------------------------------


@router.post("/trust/degrade", response_model=TrustDegradationRecord)
async def record_degradation(
    request: RecordDegradationRequest,
) -> TrustDegradationRecord:
    """Record an interaction event and update trust ceiling."""
    from app.services.trust_degradation_engine import trust_degradation_engine

    return await trust_degradation_engine.record_event(
        session_id=request.session_id,
        interaction_type=request.interaction_type,
        taint_level=request.taint_level,
        agent_id=request.agent_id,
        tool_name=request.tool_name,
        tenant_id=request.tenant_id,
    )


@router.get("/trust/{session_id}", response_model=TrustDegradationRecord)
async def get_trust_record(session_id: str) -> TrustDegradationRecord:
    """Get the trust degradation record for a session."""
    from app.services.trust_degradation_engine import trust_degradation_engine

    return await trust_degradation_engine.get_or_create_record(session_id)


@router.post("/trust/reset", response_model=TrustDegradationRecord)
async def admin_trust_reset(request: TrustResetRequest) -> TrustDegradationRecord:
    """Admin-only: reset trust ceiling for a session."""
    from app.services.trust_degradation_engine import trust_degradation_engine

    return await trust_degradation_engine.admin_reset(request.session_id)


# ---------------------------------------------------------------------------
# DEFER Decision Handler (APEP-287)
# ---------------------------------------------------------------------------


@router.post("/defer", response_model=DeferDecisionRecord)
async def create_defer(request: CreateDeferRequest) -> DeferDecisionRecord:
    """Create a new DEFER decision record."""
    from app.services.defer_handler import defer_handler

    return await defer_handler.create_deferral(
        request_id=request.request_id,
        session_id=request.session_id,
        agent_id=request.agent_id,
        tool_name=request.tool_name,
        condition=DeferCondition(request.condition),
        reason=request.reason,
        timeout_s=request.timeout_s,
        tenant_id=request.tenant_id,
    )


@router.post("/defer/{defer_id}/resolve", response_model=DeferDecisionRecord)
async def resolve_defer(
    defer_id: UUID,
    request: ResolveDeferRequest,
) -> DeferDecisionRecord:
    """Resolve a pending DEFER decision."""
    from app.services.defer_handler import defer_handler

    record = await defer_handler.resolve(defer_id, request.resolution)
    if not record:
        raise HTTPException(status_code=404, detail="Defer record not found")
    return record


@router.get("/defer/pending", response_model=list[DeferDecisionRecord])
async def list_pending_defers(
    session_id: str | None = Query(default=None),
    tenant_id: str | None = Query(default=None),
) -> list[DeferDecisionRecord]:
    """List pending DEFER decisions."""
    from app.services.defer_handler import defer_handler

    return await defer_handler.get_pending(session_id, tenant_id)


# ---------------------------------------------------------------------------
# STEP_UP Challenge Handler (APEP-288)
# ---------------------------------------------------------------------------


@router.post("/stepup", response_model=StepUpChallenge)
async def create_step_up(request: CreateStepUpRequest) -> StepUpChallenge:
    """Create a new STEP_UP authentication challenge."""
    from app.services.step_up_handler import step_up_handler

    return await step_up_handler.create_challenge(
        request_id=request.request_id,
        session_id=request.session_id,
        agent_id=request.agent_id,
        required_factors=request.required_factors,
        tenant_id=request.tenant_id,
    )


@router.post("/stepup/{challenge_id}/verify", response_model=StepUpChallenge)
async def verify_step_up_factor(
    challenge_id: UUID,
    request: VerifyFactorRequest,
) -> StepUpChallenge:
    """Verify an authentication factor on a STEP_UP challenge."""
    from app.services.step_up_handler import step_up_handler

    challenge = await step_up_handler.verify_factor(challenge_id, request.factor)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return challenge


@router.get("/stepup/{challenge_id}", response_model=StepUpChallenge)
async def get_step_up_challenge(challenge_id: UUID) -> StepUpChallenge:
    """Get the status of a STEP_UP challenge."""
    from app.services.step_up_handler import step_up_handler

    challenge = await step_up_handler.get_challenge(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return challenge


# ---------------------------------------------------------------------------
# Policy Conflict Detection (APEP-289)
# ---------------------------------------------------------------------------


@router.post("/conflicts/scan", response_model=ConflictReport)
async def scan_conflicts(
    tenant_id: str = Query(default="default"),
    strategy: str = Query(default="PRIORITY_WINS"),
) -> ConflictReport:
    """Scan all enabled rules for conflicts and generate a report."""
    from app.services.conflict_resolution import conflict_resolution_engine

    return await conflict_resolution_engine.scan_and_report(
        tenant_id=tenant_id,
        strategy=ConflictResolutionStrategy(strategy),
    )


@router.get("/conflicts", response_model=list[PolicyConflict])
async def list_conflicts(
    tenant_id: str | None = Query(default=None),
    resolved: bool | None = Query(default=None),
    severity: str | None = Query(default=None),
) -> list[PolicyConflict]:
    """List persisted policy conflicts."""
    from app.services.conflict_resolution import conflict_resolution_engine

    return await conflict_resolution_engine.get_conflicts(
        tenant_id=tenant_id,
        resolved=resolved,
        severity=severity,
    )


@router.post("/conflicts/{conflict_id}/resolve", response_model=PolicyConflict)
async def resolve_conflict(
    conflict_id: UUID,
    request: ResolveConflictRequest,
) -> PolicyConflict:
    """Manually resolve a policy conflict."""
    from app.services.conflict_resolution import conflict_resolution_engine

    conflict = await conflict_resolution_engine.resolve_conflict_by_id(
        conflict_id, request.resolution_detail
    )
    if not conflict:
        raise HTTPException(status_code=404, detail="Conflict not found")
    return conflict


# ---------------------------------------------------------------------------
# Multi-Tenancy Isolation (APEP-290)
# ---------------------------------------------------------------------------


@router.post("/tenants/config", response_model=TenantIsolationConfig)
async def set_tenant_config(
    config: TenantIsolationConfig,
) -> TenantIsolationConfig:
    """Create or update a tenant isolation configuration."""
    from app.services.tenant_isolation import tenant_isolation_guard

    return await tenant_isolation_guard.set_config(config)


@router.get("/tenants/{tenant_id}/config", response_model=TenantIsolationConfig)
async def get_tenant_config(tenant_id: str) -> TenantIsolationConfig:
    """Get the isolation configuration for a tenant."""
    from app.services.tenant_isolation import tenant_isolation_guard

    config = await tenant_isolation_guard.get_config(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail="Tenant config not found")
    return config


@router.post("/tenants/check-access", response_model=AccessCheckResponse)
async def check_tenant_access(request: CheckAccessRequest) -> AccessCheckResponse:
    """Check if cross-tenant data access is allowed."""
    from app.services.tenant_isolation import tenant_isolation_guard

    allowed, reason = await tenant_isolation_guard.check_access(
        source_tenant_id=request.source_tenant_id,
        target_tenant_id=request.target_tenant_id,
        resource_type=request.resource_type,
        resource_id=request.resource_id,
    )
    return AccessCheckResponse(allowed=allowed, reason=reason)


@router.get("/tenants/{tenant_id}/violations", response_model=list[TenantIsolationViolation])
async def list_tenant_violations(
    tenant_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[TenantIsolationViolation]:
    """List tenant isolation violations."""
    from app.services.tenant_isolation import tenant_isolation_guard

    return await tenant_isolation_guard.get_violations(tenant_id, limit)
