"""GitOps policy sync API — Sprint 30 (APEP-236).

Provides the ``POST /v1/policies/sync`` endpoint that accepts a YAML policy
payload, validates it against JSON Schema, computes a diff against the
current policy state, and applies changes atomically.

Also exposes ``POST /v1/policies/validate`` for dry-run validation and
``POST /v1/policies/diff`` for diff-only comparison.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.api.v1.console_auth import get_current_user, require_admin
from app.db.mongodb import AGENT_ROLES, POLICY_RULES, get_database
from app.services.policy_diff import PolicyDiffEngine
from app.services.yaml_policy_loader import (
    PolicyBundle,
    PolicyValidationError,
    YAMLPolicyLoader,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/policies", tags=["policy-sync"])

RISK_MODEL_CONFIGS = "risk_model_configs"


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ValidationResponse(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    file_name: str = ""


class SyncResponse(BaseModel):
    status: str = "applied"
    diff: dict[str, Any] = Field(default_factory=dict)
    roles_count: int = 0
    rules_count: int = 0
    applied_at: str = ""


class DiffResponse(BaseModel):
    diff: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_loader = YAMLPolicyLoader()
_differ = PolicyDiffEngine()


async def _load_current_bundle() -> PolicyBundle:
    """Load the current policy state from MongoDB into a PolicyBundle."""
    from app.models.policy import (
        AgentRole,
        PolicyRule,
        RiskModelConfig,
    )

    db = get_database()
    bundle = PolicyBundle()

    # Roles
    cursor = db[AGENT_ROLES].find({}, {"_id": 0})
    async for doc in cursor:
        try:
            bundle.roles.append(AgentRole(**doc))
        except Exception:
            pass

    # Rules
    cursor = db[POLICY_RULES].find({}, {"_id": 0})
    async for doc in cursor:
        try:
            bundle.rules.append(PolicyRule(**doc))
        except Exception:
            pass

    # Risk model
    doc = await db[RISK_MODEL_CONFIGS].find_one({"model_id": "default"}, {"_id": 0})
    if doc:
        try:
            bundle.risk_model = RiskModelConfig(**doc)
        except Exception:
            pass

    return bundle


async def _apply_bundle_atomically(bundle: PolicyBundle) -> None:
    """Replace current policy state with the bundle, atomically per collection."""
    db = get_database()
    now = datetime.now(UTC)

    # Apply roles
    await db[AGENT_ROLES].delete_many({})
    if bundle.roles:
        role_docs = []
        for r in bundle.roles:
            doc = r.model_dump()
            doc["created_at"] = now
            doc["updated_at"] = now
            role_docs.append(doc)
        await db[AGENT_ROLES].insert_many(role_docs)

    # Apply rules
    await db[POLICY_RULES].delete_many({})
    if bundle.rules:
        rule_docs = []
        for r in bundle.rules:
            doc = r.model_dump()
            doc["rule_id"] = str(doc["rule_id"])
            doc["created_at"] = now
            doc["updated_at"] = now
            rule_docs.append(doc)
        await db[POLICY_RULES].insert_many(rule_docs)

    # Apply risk model
    if bundle.risk_model:
        doc = bundle.risk_model.model_dump()
        doc["created_at"] = now
        doc["updated_at"] = now
        await db[RISK_MODEL_CONFIGS].replace_one(
            {"model_id": doc["model_id"]},
            doc,
            upsert=True,
        )

    # Invalidate rule cache if available
    try:
        from app.services.rule_cache import rule_cache
        rule_cache.invalidate()
    except ImportError:
        pass

    logger.info(
        "policy_sync_applied: roles=%d rules=%d has_risk_model=%s",
        len(bundle.roles),
        len(bundle.rules),
        bundle.risk_model is not None,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/validate")
async def validate_policy(
    request: Request,
    _user: dict = Depends(get_current_user),
) -> ValidationResponse:
    """Validate a YAML policy payload without applying it.

    Accepts raw YAML in the request body and validates against the
    policy bundle JSON Schema.
    """
    raw = await request.body()
    if len(raw) > _loader.MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Payload too large (max {_loader.MAX_PAYLOAD_BYTES} bytes)",
        )

    try:
        from app.services.yaml_policy_schema import POLICY_BUNDLE_SCHEMA
        data = _loader.parse_yaml(raw, "<request>")
        errors = _loader.validate_yaml(data, POLICY_BUNDLE_SCHEMA, "<request>")
    except PolicyValidationError as exc:
        return ValidationResponse(valid=False, errors=exc.errors)

    return ValidationResponse(valid=len(errors) == 0, errors=errors)


@router.post("/diff")
async def diff_policy(
    request: Request,
    _user: dict = Depends(get_current_user),
) -> DiffResponse:
    """Compare a YAML policy payload against the current policy state.

    Returns a structured diff without applying changes.
    """
    raw = await request.body()
    if len(raw) > _loader.MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Payload too large (max {_loader.MAX_PAYLOAD_BYTES} bytes)",
        )

    try:
        new_bundle = _loader.load_yaml_string(raw)
    except PolicyValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    current_bundle = await _load_current_bundle()
    diff_result = _differ.diff(current_bundle, new_bundle)
    return DiffResponse(diff=diff_result.to_dict())


@router.post("/sync")
async def sync_policy(
    request: Request,
    _user: dict = Depends(require_admin),
) -> SyncResponse:
    """Sync (apply) a YAML policy payload atomically (APEP-236).

    Accepts raw YAML in the request body, validates it, computes a diff
    against the current state, and applies all changes atomically.

    Requires admin privileges.
    """
    raw = await request.body()
    if len(raw) > _loader.MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Payload too large (max {_loader.MAX_PAYLOAD_BYTES} bytes)",
        )

    # Parse and validate
    try:
        new_bundle = _loader.load_yaml_string(raw)
    except PolicyValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Compute diff
    current_bundle = await _load_current_bundle()
    diff_result = _differ.diff(current_bundle, new_bundle)

    # Apply atomically
    await _apply_bundle_atomically(new_bundle)

    now = datetime.now(UTC)
    return SyncResponse(
        status="applied",
        diff=diff_result.to_dict(),
        roles_count=len(new_bundle.roles),
        rules_count=len(new_bundle.rules),
        applied_at=now.isoformat(),
    )
