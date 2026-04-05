"""Agent Registry API — CRUD, key management, activity, bulk ops, delegation."""

import hashlib
import secrets
from datetime import datetime, timezone, UTC
from typing import Any
from uuid import uuid4

import logging

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.db.mongodb import AGENT_PROFILES, API_KEYS, AUDIT_DECISIONS, get_database

_key_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/agents", tags=["agents"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class AgentCreateRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, description="Unique agent identifier")
    name: str = Field(..., min_length=1)
    roles: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    risk_budget: float = Field(default=1.0, ge=0.0, le=1.0)
    max_delegation_depth: int = Field(default=5, ge=1)
    session_limit: int = Field(default=100, ge=1)


class AgentUpdateRequest(BaseModel):
    name: str | None = None
    roles: list[str] | None = None
    allowed_tools: list[str] | None = None
    risk_budget: float | None = Field(default=None, ge=0.0, le=1.0)
    max_delegation_depth: int | None = Field(default=None, ge=1)
    session_limit: int | None = Field(default=None, ge=1)
    enabled: bool | None = None


class AgentResponse(BaseModel):
    agent_id: str
    name: str
    roles: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    risk_budget: float = 1.0
    max_delegation_depth: int = 5
    session_limit: int = 100
    enabled: bool = True
    decision_count: int = 0
    created_at: str = ""
    updated_at: str = ""


class AgentListResponse(BaseModel):
    agents: list[AgentResponse]
    total: int


class APIKeyResponse(BaseModel):
    key_id: str
    prefix: str
    name: str
    agent_id: str
    enabled: bool
    created_at: str
    plain_key: str | None = None  # Only populated on creation


class APIKeyListResponse(BaseModel):
    keys: list[APIKeyResponse]


class BulkRoleRequest(BaseModel):
    agent_ids: list[str] = Field(..., min_length=1)
    roles: list[str] = Field(..., min_length=1)


class BulkRoleResponse(BaseModel):
    updated: int
    agent_ids: list[str]


class ActivityEntry(BaseModel):
    decision_id: str
    session_id: str
    tool_name: str
    decision: str
    risk_score: float
    timestamp: str


class ActivityResponse(BaseModel):
    agent_id: str
    entries: list[ActivityEntry]
    total: int


class DelegationGrant(BaseModel):
    target_agent_id: str
    granted_tools: list[str]
    authority_source: str


class DelegationChainResponse(BaseModel):
    agent_id: str
    grants: list[DelegationGrant]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _doc_to_response(doc: dict[str, Any], decision_count: int = 0) -> AgentResponse:
    return AgentResponse(
        agent_id=doc.get("agent_id", ""),
        name=doc.get("name", ""),
        roles=doc.get("roles", []),
        allowed_tools=doc.get("allowed_tools", []),
        risk_budget=doc.get("risk_budget", 1.0),
        max_delegation_depth=doc.get("max_delegation_depth", 5),
        session_limit=doc.get("session_limit", 100),
        enabled=doc.get("enabled", True),
        decision_count=decision_count,
        created_at=str(doc.get("created_at", "")),
        updated_at=str(doc.get("updated_at", "")),
    )


# ---------------------------------------------------------------------------
# CRUD endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=AgentListResponse)
async def list_agents(
    sort_by: str = Query("agent_id", description="Sort field"),
    sort_dir: str = Query("asc", pattern="^(asc|desc)$"),
    role: str | None = Query(None, description="Filter by role"),
    enabled: bool | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> AgentListResponse:
    """List agents with optional filters and sorting."""
    db = get_database()
    query: dict[str, Any] = {}
    if role is not None:
        query["roles"] = role
    if enabled is not None:
        query["enabled"] = enabled

    total = await db[AGENT_PROFILES].count_documents(query)
    cursor = db[AGENT_PROFILES].find(query).skip(offset).limit(limit)
    docs = await cursor.to_list(length=limit)

    # Gather decision counts per agent
    agents = []
    for doc in docs:
        count = await db[AUDIT_DECISIONS].count_documents({"agent_id": doc["agent_id"]})
        agents.append(_doc_to_response(doc, count))

    # Sort after decision_count is computed so that sort_by=decision_count works
    direction = 1 if sort_dir == "asc" else -1
    if sort_by == "decision_count":
        agents.sort(key=lambda a: a.decision_count, reverse=(direction == -1))
    else:
        agents.sort(key=lambda a: getattr(a, sort_by, ""), reverse=(direction == -1))

    return AgentListResponse(agents=agents, total=total)


@router.post("", response_model=AgentResponse, status_code=201)
async def create_agent(body: AgentCreateRequest) -> AgentResponse:
    """Register a new agent."""
    db = get_database()
    existing = await db[AGENT_PROFILES].find_one({"agent_id": body.agent_id})
    if existing:
        raise HTTPException(status_code=409, detail=f"Agent '{body.agent_id}' already exists")

    now = datetime.now(UTC)
    doc = {
        **body.model_dump(),
        "enabled": True,
        "created_at": now,
        "updated_at": now,
    }
    await db[AGENT_PROFILES].insert_one(doc)
    return _doc_to_response(doc)


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: str) -> AgentResponse:
    """Get agent profile by ID."""
    db = get_database()
    doc = await db[AGENT_PROFILES].find_one({"agent_id": agent_id})
    if not doc:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    count = await db[AUDIT_DECISIONS].count_documents({"agent_id": agent_id})
    return _doc_to_response(doc, count)


@router.patch("/{agent_id}", response_model=AgentResponse)
async def update_agent(agent_id: str, body: AgentUpdateRequest) -> AgentResponse:
    """Update agent profile fields."""
    db = get_database()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    updates["updated_at"] = datetime.now(UTC)

    result = await db[AGENT_PROFILES].find_one_and_update(
        {"agent_id": agent_id},
        {"$set": updates},
        return_document=True,
    )
    if not result:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    count = await db[AUDIT_DECISIONS].count_documents({"agent_id": agent_id})
    return _doc_to_response(result, count)


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(agent_id: str) -> None:
    """Delete agent profile and revoke all associated API keys."""
    db = get_database()
    result = await db[AGENT_PROFILES].delete_one({"agent_id": agent_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    # Disable all API keys belonging to this agent
    await db[API_KEYS].update_many(
        {"agent_id": agent_id},
        {"$set": {"enabled": False}},
    )


# ---------------------------------------------------------------------------
# API Key management  (APEP-123)
# ---------------------------------------------------------------------------

def _generate_api_key() -> str:
    """Generate a prefixed API key."""
    return f"apk_{secrets.token_urlsafe(32)}"


@router.get("/{agent_id}/keys", response_model=APIKeyListResponse)
async def list_keys(agent_id: str) -> APIKeyListResponse:
    """List API keys for an agent (keys are masked)."""
    db = get_database()
    cursor = db[API_KEYS].find({"agent_id": agent_id})
    docs = await cursor.to_list(length=100)
    keys = [
        APIKeyResponse(
            key_id=str(doc.get("key_id", "")),
            prefix=doc.get("key", "")[:12] + "...",
            name=doc.get("name", ""),
            agent_id=doc.get("agent_id", ""),
            enabled=doc.get("enabled", True),
            created_at=str(doc.get("created_at", "")),
        )
        for doc in docs
    ]
    return APIKeyListResponse(keys=keys)


@router.post("/{agent_id}/keys", response_model=APIKeyResponse, status_code=201)
async def generate_key(agent_id: str, name: str = Query("default")) -> APIKeyResponse:
    """Generate a new API key for an agent."""
    db = get_database()
    agent = await db[AGENT_PROFILES].find_one({"agent_id": agent_id})
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    plain_key = _generate_api_key()
    key_id = str(uuid4())
    now = datetime.now(UTC)
    doc = {
        "key_id": key_id,
        "key": plain_key,
        "key_hash": hashlib.sha256(plain_key.encode()).hexdigest(),
        "name": name,
        "agent_id": agent_id,
        "tenant_id": agent_id,
        "enabled": True,
        "created_at": now,
    }
    await db[API_KEYS].insert_one(doc)
    _key_logger.info(
        "api_key_generated agent_id=%s key_id=%s name=%s", agent_id, key_id, name
    )
    return APIKeyResponse(
        key_id=key_id,
        prefix=plain_key[:12] + "...",
        name=name,
        agent_id=agent_id,
        enabled=True,
        created_at=str(now),
        plain_key=plain_key,
    )


@router.post("/{agent_id}/keys/{key_id}/rotate", response_model=APIKeyResponse)
async def rotate_key(agent_id: str, key_id: str) -> APIKeyResponse:
    """Rotate an API key — disables old, creates new."""
    db = get_database()
    old = await db[API_KEYS].find_one({"key_id": key_id, "agent_id": agent_id})
    if not old:
        raise HTTPException(status_code=404, detail="Key not found")

    # Disable old key
    await db[API_KEYS].update_one({"key_id": key_id}, {"$set": {"enabled": False}})

    # Generate new key
    plain_key = _generate_api_key()
    new_key_id = str(uuid4())
    now = datetime.now(UTC)
    doc = {
        "key_id": new_key_id,
        "key": plain_key,
        "key_hash": hashlib.sha256(plain_key.encode()).hexdigest(),
        "name": old.get("name", "rotated"),
        "agent_id": agent_id,
        "tenant_id": agent_id,
        "enabled": True,
        "created_at": now,
    }
    await db[API_KEYS].insert_one(doc)
    _key_logger.info(
        "api_key_rotated agent_id=%s old_key_id=%s new_key_id=%s",
        agent_id, key_id, new_key_id,
    )
    return APIKeyResponse(
        key_id=new_key_id,
        prefix=plain_key[:12] + "...",
        name=doc["name"],
        agent_id=agent_id,
        enabled=True,
        created_at=str(now),
        plain_key=plain_key,
    )


@router.delete("/{agent_id}/keys/{key_id}", status_code=204)
async def revoke_key(agent_id: str, key_id: str) -> None:
    """Revoke (disable) an API key."""
    db = get_database()
    result = await db[API_KEYS].update_one(
        {"key_id": key_id, "agent_id": agent_id},
        {"$set": {"enabled": False}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Key not found")
    _key_logger.info(
        "api_key_revoked agent_id=%s key_id=%s", agent_id, key_id
    )


# ---------------------------------------------------------------------------
# Activity timeline  (APEP-124)
# ---------------------------------------------------------------------------

@router.get("/{agent_id}/activity", response_model=ActivityResponse)
async def get_activity(
    agent_id: str,
    limit: int = Query(100, ge=1, le=500),
) -> ActivityResponse:
    """Get last N decisions for an agent."""
    db = get_database()
    cursor = (
        db[AUDIT_DECISIONS]
        .find({"agent_id": agent_id})
        .sort("timestamp", -1)
        .limit(limit)
    )
    docs = await cursor.to_list(length=limit)
    total = await db[AUDIT_DECISIONS].count_documents({"agent_id": agent_id})

    entries = [
        ActivityEntry(
            decision_id=str(doc.get("decision_id", "")),
            session_id=doc.get("session_id", ""),
            tool_name=doc.get("tool_name", ""),
            decision=doc.get("decision", ""),
            risk_score=doc.get("risk_score", 0.0),
            timestamp=str(doc.get("timestamp", "")),
        )
        for doc in docs
    ]
    return ActivityResponse(agent_id=agent_id, entries=entries, total=total)


# ---------------------------------------------------------------------------
# Bulk role assignment  (APEP-125)
# ---------------------------------------------------------------------------

@router.post("/bulk/roles", response_model=BulkRoleResponse)
async def bulk_assign_roles(body: BulkRoleRequest) -> BulkRoleResponse:
    """Assign roles to multiple agents at once."""
    db = get_database()
    result = await db[AGENT_PROFILES].update_many(
        {"agent_id": {"$in": body.agent_ids}},
        {"$set": {"roles": body.roles, "updated_at": datetime.now(UTC)}},
    )
    return BulkRoleResponse(updated=result.modified_count, agent_ids=body.agent_ids)


# ---------------------------------------------------------------------------
# Delegation chain viewer  (APEP-126)
# ---------------------------------------------------------------------------

@router.get("/{agent_id}/delegations", response_model=DelegationChainResponse)
async def get_delegations(agent_id: str) -> DelegationChainResponse:
    """Get configured delegation grants for an agent.

    Scans all agents whose roles were granted by this agent via
    delegation chain records or agent profile cross-references.
    """
    db = get_database()
    agent = await db[AGENT_PROFILES].find_one({"agent_id": agent_id})
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    # Find agents that list this agent in their delegation configuration
    # Convention: agents store "delegated_by" or we infer from the
    # security_alerts collection for delegation relationships.
    grants: list[DelegationGrant] = []

    # Check audit decisions for delegation patterns
    pipeline = [
        {"$match": {"delegation_chain": agent_id}},
        {"$group": {
            "_id": "$agent_id",
            "tools": {"$addToSet": "$tool_name"},
        }},
    ]
    cursor = db[AUDIT_DECISIONS].aggregate(pipeline)
    async for entry in cursor:
        grants.append(DelegationGrant(
            target_agent_id=entry["_id"],
            granted_tools=entry.get("tools", []),
            authority_source=f"agent:{agent_id}",
        ))

    # Also check agents whose roles overlap (configured delegation)
    agent_roles = set(agent.get("roles", []))
    if agent_roles:
        cursor = db[AGENT_PROFILES].find({
            "agent_id": {"$ne": agent_id},
            "roles": {"$in": list(agent_roles)},
        })
        async for peer in cursor:
            # Only include if not already added from audit
            existing_ids = {g.target_agent_id for g in grants}
            if peer["agent_id"] not in existing_ids:
                grants.append(DelegationGrant(
                    target_agent_id=peer["agent_id"],
                    granted_tools=peer.get("allowed_tools", []),
                    authority_source=f"role:{','.join(agent_roles & set(peer.get('roles', [])))}",
                ))

    return DelegationChainResponse(agent_id=agent_id, grants=grants)
