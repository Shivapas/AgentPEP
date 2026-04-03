"""Audit integrity verification API — APEP-191."""

from fastapi import APIRouter

from app.services.audit_integrity import audit_integrity_verifier

router = APIRouter(tags=["audit"])


@router.post("/v1/audit/verify-integrity")
async def verify_audit_integrity():
    """Run hash chain verification on the audit log.

    Returns verification result including any broken links detected.
    """
    result = await audit_integrity_verifier.verify_chain()
    return result.to_dict()


@router.get("/v1/audit/chain-length")
async def get_chain_length():
    """Return the current number of entries in the audit hash chain."""
    length = await audit_integrity_verifier.get_chain_length()
    return {"chain_length": length}
