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

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

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
async def list_roles() -> list[dict[str, Any]]:
    """List all agent roles."""
    db = get_database()
    cursor = db[AGENT_ROLES].find({}, {"_id": 0}).sort("role_id", 1)
    return [_serialize(doc) async for doc in cursor]


@router.post("/roles", status_code=201)
async def create_role(body: CreateRoleRequest) -> dict[str, Any]:
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
async def update_role(role_id: str, body: UpdateRoleRequest) -> dict[str, Any]:
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
async def delete_role(role_id: str) -> None:
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
async def create_rule(body: CreateRuleRequest) -> dict[str, Any]:
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
async def update_rule(rule_id: str, body: UpdateRuleRequest) -> dict[str, Any]:
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
async def delete_rule(rule_id: str) -> None:
    """Delete a policy rule."""
    db = get_database()
    result = await db[POLICY_RULES].delete_one({"rule_id": rule_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")


@router.post("/rules/reorder")
async def reorder_rules(body: ReorderRequest) -> dict[str, bool]:
    """Reorder rules by assigning sequential priorities based on the provided order."""
    db = get_database()
    for idx, rule_id in enumerate(body.rule_ids):
        await db[POLICY_RULES].update_one(
            {"rule_id": rule_id},
            {"$set": {"priority": idx + 1, "updated_at": datetime.now(UTC)}},
        )
    return {"ok": True}


@router.get("/rules/conflicts")
async def detect_conflicts() -> list[dict[str, Any]]:
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
async def list_policy_sets() -> list[dict[str, Any]]:
    """List all policy sets."""
    db = get_database()
    cursor = db[POLICY_SETS].find({}, {"_id": 0}).sort("created_at", -1)
    return [_serialize(doc) async for doc in cursor]


@router.get("/policy-sets/{set_id}")
async def get_policy_set(set_id: str) -> dict[str, Any]:
    """Get a policy set by ID."""
    db = get_database()
    doc = await db[POLICY_SETS].find_one({"policy_set_id": set_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail=f"Policy set '{set_id}' not found")
    return _serialize(doc)


@router.post("/policy-sets/{set_id}/versions", status_code=201)
async def create_policy_version(set_id: str, version: dict[str, Any]) -> dict[str, Any]:
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
async def restore_version(set_id: str, version_id: str) -> dict[str, Any]:
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

    return _serialize(dict(version))


@router.patch("/policy-sets/{set_id}/versions/{version_id}/status")
async def update_version_status(
    set_id: str,
    version_id: str,
    body: dict[str, str],
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
async def export_yaml(set_id: str) -> PlainTextResponse:
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
async def import_yaml(request: Request) -> dict[str, Any]:
    """Import a policy set from YAML."""
    raw = await request.body()

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
