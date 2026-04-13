"""Memory access control API — Sprint 33 (APEP-261, APEP-262, APEP-263).

Provides endpoints for evaluating memory access requests and managing
memory access policies.
"""

from uuid import UUID

from fastapi import APIRouter

from app.db import mongodb as db_module
from app.services.memory_access_gate import (
    MemoryAccessPolicy,
    MemoryAccessRequest,
    MemoryAccessResult,
    memory_access_gate,
)

router = APIRouter(prefix="/v1/memory", tags=["memory"])


@router.post("/access", response_model=MemoryAccessResult)
async def check_memory_access(request: MemoryAccessRequest) -> MemoryAccessResult:
    """Evaluate a memory access request through the MemoryAccessGate."""
    return await memory_access_gate.evaluate(request)


@router.post("/policies", response_model=MemoryAccessPolicy, status_code=201)
async def create_memory_policy(policy: MemoryAccessPolicy) -> MemoryAccessPolicy:
    """Create a new memory access policy."""
    db = db_module.get_database()
    doc = policy.model_dump(mode="json")
    await db[db_module.MEMORY_ACCESS_POLICIES].insert_one(doc)
    return policy


@router.get("/policies", response_model=list[MemoryAccessPolicy])
async def list_memory_policies() -> list[MemoryAccessPolicy]:
    """List all memory access policies."""
    db = db_module.get_database()
    cursor = db[db_module.MEMORY_ACCESS_POLICIES].find()
    policies: list[MemoryAccessPolicy] = []
    async for doc in cursor:
        doc.pop("_id", None)
        policies.append(MemoryAccessPolicy(**doc))
    return policies


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_memory_policy(policy_id: UUID) -> None:
    """Delete a memory access policy."""
    db = db_module.get_database()
    await db[db_module.MEMORY_ACCESS_POLICIES].delete_one(
        {"policy_id": str(policy_id)}
    )
