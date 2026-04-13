"""Policy authoring API — CRUD for roles, rules, policy sets, and conflict detection.

Provides endpoints consumed by the Policy Console frontend for:
- Role management (CRUD)
- Rule management (CRUD + reorder + conflict detection)
- Policy set versioning (list, create version, restore, status update)
- YAML import/export
"""

from __future__ import annotations

import fnmatch
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app.api.v1.console_auth import get_current_user, require_admin
from app.db.mongodb import AGENT_ROLES, POLICY_RULES, get_database
from app.models.policy import Decision

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["policy"])

POLICY_SETS = "policy_sets"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serialize(doc: dict[str, Any]) -> dict[str, Any]:
    """Remove MongoDB _id and convert non-serialisable fields."""
    doc.pop("_id", None)
    for key, val in doc.items():
        if isinstance(val, datetime):
            doc[key] = val.isoformat()
    return doc


# ---------------------------------------------------------------------------
# Roles CRUD
# ---------------------------------------------------------------------------


class CreateRoleRequest(BaseModel):
    role_id: str
    name: str
    parent_roles: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    max_risk_threshold: float = Field(default=1.0, ge=0.0, le=1.0)
    enabled: bool = True


class UpdateRoleRequest(BaseModel):
    name: str | None = None
    parent_roles: list[str] | None = None
    allowed_tools: list[str] | None = None
    denied_tools: list[str] | None = None
    max_risk_threshold: float | None = None
    enabled: bool | None = None


@router.get("/roles")
async def list_roles(_user: dict = Depends(get_current_user)) -> list[dict[str, Any]]:
    """List all agent roles."""
    db = get_database()
    cursor = db[AGENT_ROLES].find({}, {"_id": 0}).sort("role_id", 1)
    return [_serialize(doc) async for doc in cursor]


@router.post("/roles", status_code=201)
async def create_role(
    body: CreateRoleRequest, _user: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Create a new agent role."""
    db = get_database()
    existing = await db[AGENT_ROLES].find_one({"role_id": body.role_id})
    if existing:
        raise HTTPException(status_code=409, detail=f"Role '{body.role_id}' already exists")

    now = datetime.now(UTC)
    doc = {
        **body.model_dump(),
        "created_at": now,
        "updated_at": now,
    }
    await db[AGENT_ROLES].insert_one(doc)
    doc.pop("_id", None)
    return _serialize(doc)


@router.patch("/roles/{role_id}")
async def update_role(
    role_id: str, body: UpdateRoleRequest, _user: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Update an existing agent role."""
    db = get_database()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    updates["updated_at"] = datetime.now(UTC)
    result = await db[AGENT_ROLES].find_one_and_update(
        {"role_id": role_id},
        {"$set": updates},
        return_document=True,
    )
    if not result:
        raise HTTPException(status_code=404, detail=f"Role '{role_id}' not found")
    return _serialize(result)


@router.delete("/roles/{role_id}", status_code=204)
async def delete_role(role_id: str, _user: dict = Depends(require_admin)) -> None:
    """Delete an agent role."""
    db = get_database()
    result = await db[AGENT_ROLES].delete_one({"role_id": role_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail=f"Role '{role_id}' not found")


# ---------------------------------------------------------------------------
# Rules CRUD
# ---------------------------------------------------------------------------


class CreateRuleRequest(BaseModel):
    name: str
    agent_role: list[str] = Field(default_factory=list)
    tool_pattern: str
    action: Decision
    taint_check: bool = False
    risk_threshold: float = Field(default=1.0, ge=0.0, le=1.0)
    priority: int = Field(default=100)
    enabled: bool = True


class UpdateRuleRequest(BaseModel):
    name: str | None = None
    agent_role: list[str] | None = None
    tool_pattern: str | None = None
    action: Decision | None = None
    taint_check: bool | None = None
    risk_threshold: float | None = None
    priority: int | None = None
    enabled: bool | None = None


class ReorderRequest(BaseModel):
    rule_ids: list[str]


@router.post("/rules", status_code=201)
async def create_rule(
    body: CreateRuleRequest, _user: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Create a new policy rule."""
    db = get_database()
    now = datetime.now(UTC)
    doc = {
        "rule_id": str(uuid4()),
        **body.model_dump(),
        "created_at": now,
        "updated_at": now,
    }
    await db[POLICY_RULES].insert_one(doc)
    doc.pop("_id", None)
    return _serialize(doc)


@router.patch("/rules/{rule_id}")
async def update_rule(
    rule_id: str, body: UpdateRuleRequest, _user: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Update an existing policy rule."""
    db = get_database()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    updates["updated_at"] = datetime.now(UTC)
    result = await db[POLICY_RULES].find_one_and_update(
        {"rule_id": rule_id},
        {"$set": updates},
        return_document=True,
    )
    if not result:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
    return _serialize(result)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: str, _user: dict = Depends(require_admin)) -> None:
    """Delete a policy rule."""
    db = get_database()
    result = await db[POLICY_RULES].delete_one({"rule_id": rule_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")


@router.post("/rules/reorder")
async def reorder_rules(
    body: ReorderRequest, _user: dict = Depends(require_admin),
) -> dict[str, bool]:
    """Reorder rules by assigning sequential priorities based on the provided order."""
    db = get_database()

    # Validate: no duplicates
    if len(body.rule_ids) != len(set(body.rule_ids)):
        raise HTTPException(status_code=400, detail="Duplicate rule IDs in reorder request")

    # Validate: all IDs must exist
    existing_cursor = db[POLICY_RULES].find({}, {"rule_id": 1, "_id": 0})
    existing_ids = {doc["rule_id"] async for doc in existing_cursor}
    unknown = set(body.rule_ids) - existing_ids
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown rule IDs: {', '.join(unknown)}")

    missing = existing_ids - set(body.rule_ids)
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Missing rule IDs (must include all rules): {', '.join(missing)}",
        )

    for idx, rule_id in enumerate(body.rule_ids):
        await db[POLICY_RULES].update_one(
            {"rule_id": rule_id},
            {"$set": {"priority": idx + 1, "updated_at": datetime.now(UTC)}},
        )
    return {"ok": True}


@router.get("/rules/conflicts")
async def detect_conflicts(_user: dict = Depends(get_current_user)) -> list[dict[str, Any]]:
    """Detect overlapping rules that may conflict."""
    db = get_database()
    cursor = db[POLICY_RULES].find({"enabled": True}, {"_id": 0}).sort("priority", 1)
    rules = [doc async for doc in cursor]

    conflicts: list[dict[str, Any]] = []
    for i, a in enumerate(rules):
        for b in rules[i + 1:]:
            # Check role overlap
            roles_a = set(a.get("agent_role", []))
            roles_b = set(b.get("agent_role", []))
            role_overlap = roles_a & roles_b or not roles_a or not roles_b

            if not role_overlap:
                continue

            # Check tool pattern overlap
            pat_a = a.get("tool_pattern", "")
            pat_b = b.get("tool_pattern", "")
            tool_overlap = (
                fnmatch.fnmatch(pat_a, pat_b)
                or fnmatch.fnmatch(pat_b, pat_a)
                or pat_a == pat_b
            )

            if not tool_overlap:
                continue

            # Different actions = conflict
            if a.get("action") != b.get("action"):
                conflicts.append({
                    "rule_a": _serialize(dict(a)),
                    "rule_b": _serialize(dict(b)),
                    "overlap_type": "role_and_tool",
                    "detail": (
                        f"Rules '{a.get('name')}' (priority {a.get('priority')}) and "
                        f"'{b.get('name')}' (priority {b.get('priority')}) have overlapping "
                        f"tool patterns and roles but different actions "
                        f"({a.get('action')} vs {b.get('action')})"
                    ),
                })

    return conflicts


# ---------------------------------------------------------------------------
# Policy Sets (versioning)
# ---------------------------------------------------------------------------


@router.get("/policy-sets")
async def list_policy_sets(_user: dict = Depends(get_current_user)) -> list[dict[str, Any]]:
    """List all policy sets."""
    db = get_database()
    cursor = db[POLICY_SETS].find({}, {"_id": 0}).sort("created_at", -1)
    return [_serialize(doc) async for doc in cursor]


@router.get("/policy-sets/{set_id}")
async def get_policy_set(set_id: str, _user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Get a policy set by ID."""
    db = get_database()
    doc = await db[POLICY_SETS].find_one({"policy_set_id": set_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail=f"Policy set '{set_id}' not found")
    return _serialize(doc)


@router.post("/policy-sets/{set_id}/versions", status_code=201)
async def create_policy_version(
    set_id: str, version: dict[str, Any], _user: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Create a new version snapshot for a policy set."""
    db = get_database()
    policy_set = await db[POLICY_SETS].find_one({"policy_set_id": set_id})
    if not policy_set:
        # Auto-create policy set if it doesn't exist
        now = datetime.now(UTC)
        policy_set = {
            "policy_set_id": set_id,
            "name": version.get("comment", set_id),
            "current_version": 0,
            "versions": [],
            "created_at": now,
            "updated_at": now,
        }
        await db[POLICY_SETS].insert_one(policy_set)

    # Collect current rules and roles for the snapshot
    rules_cursor = db[POLICY_RULES].find({}, {"_id": 0})
    rules = [_serialize(doc) async for doc in rules_cursor]
    roles_cursor = db[AGENT_ROLES].find({}, {"_id": 0})
    roles = [_serialize(doc) async for doc in roles_cursor]

    new_version_num = policy_set.get("current_version", 0) + 1
    now = datetime.now(UTC)
    version_doc = {
        "version_id": str(uuid4()),
        "version": new_version_num,
        "status": "draft",
        "rules": rules,
        "roles": roles,
        "author": version.get("author", "console_user"),
        "comment": version.get("comment", ""),
        "created_at": now,
    }

    await db[POLICY_SETS].update_one(
        {"policy_set_id": set_id},
        {
            "$push": {"versions": version_doc},
            "$set": {
                "current_version": new_version_num,
                "updated_at": now,
            },
        },
    )
    return _serialize(version_doc)


@router.post("/policy-sets/{set_id}/versions/{version_id}/restore")
async def restore_version(
    set_id: str, version_id: str, user: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Restore rules and roles from a specific version."""
    db = get_database()
    policy_set = await db[POLICY_SETS].find_one({"policy_set_id": set_id})
    if not policy_set:
        raise HTTPException(status_code=404, detail=f"Policy set '{set_id}' not found")

    version = None
    for v in policy_set.get("versions", []):
        if v.get("version_id") == version_id:
            version = v
            break

    if not version:
        raise HTTPException(status_code=404, detail=f"Version '{version_id}' not found")

    # Restore rules: clear current and insert version's rules
    await db[POLICY_RULES].delete_many({})
    if version.get("rules"):
        await db[POLICY_RULES].insert_many(version["rules"])

    # Restore roles: clear current and insert version's roles
    await db[AGENT_ROLES].delete_many({})
    if version.get("roles"):
        await db[AGENT_ROLES].insert_many(version["roles"])

    # Audit log the restore action
    logger.info(
        "policy_version_restored",
        policy_set_id=set_id,
        version_id=version_id,
        restored_by=user.get("sub", "unknown"),
    )

    return _serialize(dict(version))


@router.patch("/policy-sets/{set_id}/versions/{version_id}/status")
async def update_version_status(
    set_id: str,
    version_id: str,
    body: dict[str, str],
    _user: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Update the review status of a policy version."""
    new_status = body.get("status")
    if new_status not in ("draft", "submitted", "approved", "active"):
        raise HTTPException(status_code=400, detail=f"Invalid status: {new_status}")

    db = get_database()
    result = await db[POLICY_SETS].find_one_and_update(
        {"policy_set_id": set_id, "versions.version_id": version_id},
        {"$set": {"versions.$.status": new_status, "updated_at": datetime.now(UTC)}},
        return_document=True,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Policy set or version not found")

    for v in result.get("versions", []):
        if v.get("version_id") == version_id:
            return _serialize(dict(v))

    raise HTTPException(status_code=404, detail="Version not found after update")


# ---------------------------------------------------------------------------
# YAML Import / Export
# ---------------------------------------------------------------------------


@router.get("/policy-sets/{set_id}/export/yaml")
async def export_yaml(set_id: str, _user: dict = Depends(get_current_user)) -> PlainTextResponse:
    """Export a policy set's current rules and roles as YAML."""
    db = get_database()
    policy_set = await db[POLICY_SETS].find_one({"policy_set_id": set_id}, {"_id": 0})
    if not policy_set:
        raise HTTPException(status_code=404, detail=f"Policy set '{set_id}' not found")

    try:
        import yaml
    except ImportError:
        # Fallback to JSON if PyYAML not installed
        import json
        content = json.dumps(_serialize(dict(policy_set)), indent=2, default=str)
        return PlainTextResponse(content, media_type="application/json")

    return PlainTextResponse(
        yaml.dump(_serialize(dict(policy_set)), default_flow_style=False, sort_keys=False),
        media_type="text/yaml",
    )


@router.post("/policy-sets/import/yaml", status_code=201)
async def import_yaml(request: Request, _user: dict = Depends(require_admin)) -> dict[str, Any]:
    """Import a policy set from YAML."""
    raw = await request.body()
    # Limit payload size to 1MB to prevent memory exhaustion
    max_size = 1_048_576  # 1 MB
    if len(raw) > max_size:
        raise HTTPException(status_code=413, detail=f"Payload too large (max {max_size} bytes)")

    try:
        import yaml
        data = yaml.safe_load(raw)
    except ImportError:
        import json
        data = json.loads(raw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="YAML must be a mapping")

    db = get_database()
    now = datetime.now(UTC)
    set_id = data.get("policy_set_id", str(uuid4()))
    doc = {
        "policy_set_id": set_id,
        "name": data.get("name", "Imported Policy Set"),
        "current_version": data.get("current_version", 0),
        "versions": data.get("versions", []),
        "created_at": now,
        "updated_at": now,
    }

    await db[POLICY_SETS].replace_one(
        {"policy_set_id": set_id},
        doc,
        upsert=True,
    )
    doc.pop("_id", None)
    return _serialize(doc)


# ---------------------------------------------------------------------------
# Sprint 30 — APEP-236: GitOps Sync Endpoint
# ---------------------------------------------------------------------------


class PolicySyncResponse(BaseModel):
    """Response from the GitOps sync endpoint."""

    status: str = Field(..., description="'applied' or 'validated'")
    roles_synced: int = 0
    rules_synced: int = 0
    risk_config_synced: bool = False
    validation_errors: list[str] = Field(default_factory=list)
    diff_summary: dict[str, Any] = Field(default_factory=dict)


@router.post("/policies/sync", status_code=200)
async def sync_policies(
    request: Request,
    dry_run: bool = False,
    _user: dict = Depends(require_admin),
) -> dict[str, Any]:
    """GitOps sync endpoint: accept YAML payload, validate, and apply atomically.

    If ``dry_run=true``, validates and returns a diff without applying changes.
    Otherwise, atomically replaces all roles, rules, and risk config.
    """
    from app.services.yaml_loader import YAMLPolicyValidationError, yaml_policy_loader
    from app.services.policy_differ import policy_diff_engine

    raw = await request.body()
    max_size = 2_097_152  # 2 MB
    if len(raw) > max_size:
        raise HTTPException(status_code=413, detail=f"Payload too large (max {max_size} bytes)")

    # Parse and validate
    try:
        doc = yaml_policy_loader.load_and_validate(raw)
    except YAMLPolicyValidationError as exc:
        raise HTTPException(status_code=400, detail={"validation_errors": exc.errors})

    # Build diff against current state
    db = get_database()
    current_roles_cursor = db[AGENT_ROLES].find({}, {"_id": 0})
    current_roles_raw = [r async for r in current_roles_cursor]
    current_rules_cursor = db[POLICY_RULES].find({}, {"_id": 0}).sort("priority", 1)
    current_rules_raw = [r async for r in current_rules_cursor]

    # Build a YAMLPolicyDocument from current state for diffing
    current_doc = await _build_current_policy_doc(current_roles_raw, current_rules_raw)
    diff_result = policy_diff_engine.diff(current_doc, doc)

    if dry_run:
        return PolicySyncResponse(
            status="validated",
            roles_synced=len(doc.roles),
            rules_synced=len(doc.rules),
            risk_config_synced=True,
            diff_summary=diff_result.to_dict(),
        ).model_dump()

    # Atomic apply: replace all roles and rules
    hydrated_roles = yaml_policy_loader.hydrate_roles(doc)
    hydrated_rules = yaml_policy_loader.hydrate_rules(doc)
    hydrated_risk = yaml_policy_loader.hydrate_risk_config(doc)

    now = datetime.now(UTC)

    # Clear and re-insert roles
    await db[AGENT_ROLES].delete_many({})
    if hydrated_roles:
        role_docs = []
        for role in hydrated_roles:
            d = role.model_dump(mode="json")
            d["created_at"] = now
            d["updated_at"] = now
            role_docs.append(d)
        await db[AGENT_ROLES].insert_many(role_docs)

    # Clear and re-insert rules
    await db[POLICY_RULES].delete_many({})
    if hydrated_rules:
        rule_docs = []
        for rule in hydrated_rules:
            d = rule.model_dump(mode="json")
            d["created_at"] = now
            d["updated_at"] = now
            rule_docs.append(d)
        await db[POLICY_RULES].insert_many(rule_docs)

    # Update risk model config
    risk_doc = hydrated_risk.model_dump(mode="json")
    risk_doc["updated_at"] = now
    await db["risk_model_configs"].replace_one(
        {"model_id": "yaml-policy"},
        risk_doc,
        upsert=True,
    )

    # Invalidate rule cache
    try:
        from app.services.rule_cache import rule_cache
        rule_cache.invalidate()
    except ImportError:
        pass

    logger.info(
        "policy_sync_applied: roles=%d rules=%d user=%s",
        len(hydrated_roles),
        len(hydrated_rules),
        _user.get("sub", "unknown"),
    )

    return PolicySyncResponse(
        status="applied",
        roles_synced=len(hydrated_roles),
        rules_synced=len(hydrated_rules),
        risk_config_synced=True,
        diff_summary=diff_result.to_dict(),
    ).model_dump()


# ---------------------------------------------------------------------------
# Sprint 30 — APEP-237: Policy Diff Endpoint
# ---------------------------------------------------------------------------


@router.post("/policies/diff")
async def diff_policies(
    request: Request,
    _user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Compare a proposed YAML policy against the current active policy.

    Accepts a YAML payload and returns a structured diff showing added,
    removed, and changed roles/rules/risk/taint configuration.
    """
    from app.services.yaml_loader import YAMLPolicyValidationError, yaml_policy_loader
    from app.services.policy_differ import policy_diff_engine

    raw = await request.body()
    max_size = 2_097_152  # 2 MB
    if len(raw) > max_size:
        raise HTTPException(status_code=413, detail=f"Payload too large (max {max_size} bytes)")

    try:
        proposed_doc = yaml_policy_loader.load_and_validate(raw)
    except YAMLPolicyValidationError as exc:
        raise HTTPException(status_code=400, detail={"validation_errors": exc.errors})

    # Build current state
    db = get_database()
    current_roles_cursor = db[AGENT_ROLES].find({}, {"_id": 0})
    current_roles_raw = [r async for r in current_roles_cursor]
    current_rules_cursor = db[POLICY_RULES].find({}, {"_id": 0}).sort("priority", 1)
    current_rules_raw = [r async for r in current_rules_cursor]

    current_doc = await _build_current_policy_doc(current_roles_raw, current_rules_raw)
    diff_result = policy_diff_engine.diff(current_doc, proposed_doc)

    return diff_result.to_dict()


async def _build_current_policy_doc(
    roles_raw: list[dict[str, Any]],
    rules_raw: list[dict[str, Any]],
) -> "YAMLPolicyDocument":
    """Build a YAMLPolicyDocument from current MongoDB state for diffing."""
    from app.models.yaml_policy import (
        YAMLPolicyDocument,
        YAMLRiskConfig,
        YAMLRiskWeights,
        YAMLRoleDefinition,
        YAMLRuleDefinition,
        YAMLTaintPolicy,
    )

    yaml_roles = []
    for r in roles_raw:
        yaml_roles.append(
            YAMLRoleDefinition(
                role_id=r.get("role_id", ""),
                name=r.get("name", ""),
                parent_roles=r.get("parent_roles", []),
                allowed_tools=r.get("allowed_tools", []),
                denied_tools=r.get("denied_tools", []),
                max_risk_threshold=r.get("max_risk_threshold", 1.0),
                enabled=r.get("enabled", True),
            )
        )

    yaml_rules = []
    for r in rules_raw:
        yaml_rules.append(
            YAMLRuleDefinition(
                rule_id=r.get("rule_id", ""),
                name=r.get("name", ""),
                agent_roles=r.get("agent_role", []),
                tool_pattern=r.get("tool_pattern", "*"),
                action=r.get("action", "DENY"),
                taint_check=r.get("taint_check", False),
                risk_threshold=r.get("risk_threshold", 1.0),
                priority=r.get("priority", 100),
                enabled=r.get("enabled", True),
            )
        )

    # Read back risk config if available
    risk_config = YAMLRiskConfig()
    db = get_database()
    risk_doc = await db["risk_model_configs"].find_one(
        {"model_id": "yaml-policy"}, {"_id": 0}
    )
    if risk_doc:
        dw = risk_doc.get("default_weights", {})
        role_overrides = {}
        for role_id, weights in risk_doc.get("role_overrides", {}).items():
            role_overrides[role_id] = YAMLRiskWeights(
                operation_type=weights.get("operation_type", 0.25),
                data_sensitivity=weights.get("data_sensitivity", 0.25),
                taint=weights.get("taint", 0.20),
                session_accumulated=weights.get("session_accumulated", 0.10),
                delegation_depth=weights.get("delegation_depth", 0.20),
            )
        risk_config = YAMLRiskConfig(
            default_weights=YAMLRiskWeights(
                operation_type=dw.get("operation_type", 0.25),
                data_sensitivity=dw.get("data_sensitivity", 0.25),
                taint=dw.get("taint", 0.20),
                session_accumulated=dw.get("session_accumulated", 0.10),
                delegation_depth=dw.get("delegation_depth", 0.20),
            ),
            role_overrides=role_overrides,
            escalation_threshold=risk_doc.get("escalation_threshold", 0.7),
        )

    return YAMLPolicyDocument(
        roles=yaml_roles,
        rules=yaml_rules,
        risk=risk_config,
    )
