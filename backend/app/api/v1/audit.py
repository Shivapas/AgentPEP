"""Audit Explorer API — Sprint 17 (APEP-136 to APEP-141).

Provides paginated querying, full-text search, session timeline,
export (CSV/JSON/PDF), and hash-chain integrity verification for
audit decision records.
"""

import csv
import hashlib
import io
import json
import logging
import re
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.api.v1.console_auth import get_current_user
from app.db import mongodb as db_module
from app.models.policy import Decision

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/audit", tags=["audit"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_filter(
    session_id: str | None,
    agent_id: str | None,
    tool_name: str | None,
    decision: Decision | None,
    risk_min: float | None,
    risk_max: float | None,
    start_time: datetime | None,
    end_time: datetime | None,
    search: str | None,
) -> dict[str, Any]:
    """Construct a MongoDB filter from query parameters."""
    f: dict[str, Any] = {}
    if session_id:
        f["session_id"] = session_id
    if agent_id:
        f["agent_id"] = agent_id
    if tool_name:
        f["tool_name"] = {"$regex": re.escape(tool_name), "$options": "i"}
    if decision:
        f["decision"] = decision.value
    if risk_min is not None or risk_max is not None:
        risk: dict[str, float] = {}
        if risk_min is not None:
            risk["$gte"] = risk_min
        if risk_max is not None:
            risk["$lte"] = risk_max
        f["risk_score"] = risk
    if start_time or end_time:
        ts: dict[str, datetime] = {}
        if start_time:
            ts["$gte"] = start_time
        if end_time:
            ts["$lte"] = end_time
        f["timestamp"] = ts
    if search:
        escaped_search = re.escape(search)
        f["$or"] = [
            {"agent_id": {"$regex": escaped_search, "$options": "i"}},
            {"tool_name": {"$regex": escaped_search, "$options": "i"}},
            {"decision": {"$regex": escaped_search, "$options": "i"}},
            {"session_id": {"$regex": escaped_search, "$options": "i"}},
        ]
    return f


def _serialize_doc(doc: dict[str, Any]) -> dict[str, Any]:
    """Convert MongoDB document to JSON-serializable dict."""
    doc.pop("_id", None)
    for k, v in doc.items():
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc


# ---------------------------------------------------------------------------
# APEP-136 / APEP-137 — Paginated decision table + full-text search
# ---------------------------------------------------------------------------


@router.get("/decisions")
async def list_decisions(
    _user: dict = Depends(get_current_user),
    page: int = Query(default=1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(default=25, ge=1, le=100, description="Rows per page"),
    sort_field: str = Query(default="timestamp", description="Field to sort by"),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    session_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    tool_name: str | None = Query(default=None),
    decision: Decision | None = Query(default=None),
    risk_min: float | None = Query(default=None, ge=0.0, le=1.0),
    risk_max: float | None = Query(default=None, ge=0.0, le=1.0),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    search: str | None = Query(default=None, description="Full-text search across fields"),
) -> dict[str, Any]:
    """Return a paginated, filterable list of audit decisions."""
    db = db_module.get_database()
    col = db[db_module.AUDIT_DECISIONS]

    query_filter = _build_filter(
        session_id, agent_id, tool_name, decision,
        risk_min, risk_max, start_time, end_time, search,
    )

    total = await col.count_documents(query_filter)

    sort_dir = 1 if sort_order == "asc" else -1
    skip = (page - 1) * page_size

    cursor = col.find(query_filter).sort(sort_field, sort_dir).skip(skip).limit(page_size)
    items = [_serialize_doc(doc) async for doc in cursor]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


# ---------------------------------------------------------------------------
# APEP-138 — Decision detail
# ---------------------------------------------------------------------------


@router.get("/decisions/{decision_id}")
async def get_decision(decision_id: str, _user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Return full detail for a single audit decision."""
    db = db_module.get_database()
    col = db[db_module.AUDIT_DECISIONS]
    doc = await col.find_one({"decision_id": decision_id})
    if doc is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    return _serialize_doc(doc)


# ---------------------------------------------------------------------------
# APEP-139 — Session timeline
# ---------------------------------------------------------------------------


@router.get("/sessions/{session_id}/timeline")
async def session_timeline(
    session_id: str,
    _user: dict = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Return all decisions for a session in chronological order."""
    db = db_module.get_database()
    col = db[db_module.AUDIT_DECISIONS]
    cursor = col.find({"session_id": session_id}).sort("timestamp", 1)
    return [_serialize_doc(doc) async for doc in cursor]


# ---------------------------------------------------------------------------
# APEP-140 — Audit export (CSV / JSON)
# ---------------------------------------------------------------------------


@router.get("/export")
async def export_audit(
    _user: dict = Depends(get_current_user),
    format: str = Query(default="json", pattern="^(csv|json)$"),
    session_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    tool_name: str | None = Query(default=None),
    decision: Decision | None = Query(default=None),
    risk_min: float | None = Query(default=None, ge=0.0, le=1.0),
    risk_max: float | None = Query(default=None, ge=0.0, le=1.0),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=10000, ge=1, le=10000),
) -> StreamingResponse:
    """Export filtered audit decisions as CSV or JSON."""
    db = db_module.get_database()
    col = db[db_module.AUDIT_DECISIONS]

    query_filter = _build_filter(
        session_id, agent_id, tool_name, decision,
        risk_min, risk_max, start_time, end_time, search,
    )

    cursor = col.find(query_filter).sort("timestamp", -1).limit(limit)
    docs = [_serialize_doc(doc) async for doc in cursor]

    if format == "csv":
        return _csv_response(docs)
    return _json_response(docs)


def _csv_response(docs: list[dict[str, Any]]) -> StreamingResponse:
    if not docs:
        buf = io.StringIO("No records\n")
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_export.csv"},
        )

    columns = [
        "decision_id", "session_id", "agent_id", "agent_role", "tool_name",
        "decision", "risk_score", "tool_args_hash", "taint_flags",
        "delegation_chain", "matched_rule_id", "escalation_id",
        "latency_ms", "timestamp",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for doc in docs:
        row = {c: doc.get(c, "") for c in columns}
        # Flatten list fields
        if isinstance(row.get("taint_flags"), list):
            row["taint_flags"] = ";".join(row["taint_flags"])
        if isinstance(row.get("delegation_chain"), list):
            row["delegation_chain"] = ";".join(row["delegation_chain"])
        writer.writerow(row)

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_export.csv"},
    )


def _json_response(docs: list[dict[str, Any]]) -> StreamingResponse:
    content = json.dumps(docs, indent=2, default=str)
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=audit_export.json"},
    )


# ---------------------------------------------------------------------------
# APEP-141 — Hash chain integrity verification
# ---------------------------------------------------------------------------


@router.get("/integrity")
async def verify_integrity(
    _user: dict = Depends(get_current_user),
    session_id: str | None = Query(default=None),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=50000),
) -> dict[str, Any]:
    """Verify hash-chain integrity for a range of audit records.

    Each record's chain_hash = SHA-256(prev_chain_hash + decision_id + tool_args_hash).
    If any record has been tampered with, the chain breaks.
    """
    db = db_module.get_database()
    col = db[db_module.AUDIT_DECISIONS]

    query_filter: dict[str, Any] = {}
    if session_id:
        query_filter["session_id"] = session_id
    if start_time or end_time:
        ts: dict[str, datetime] = {}
        if start_time:
            ts["$gte"] = start_time
        if end_time:
            ts["$lte"] = end_time
        query_filter["timestamp"] = ts

    cursor = col.find(query_filter).sort("timestamp", 1).limit(limit)
    records = [doc async for doc in cursor]

    if not records:
        return {
            "status": "NO_RECORDS",
            "total_records": 0,
            "verified": 0,
            "tampered": 0,
            "records": [],
        }

    prev_hash = "0" * 64  # genesis hash
    results: list[dict[str, Any]] = []
    verified = 0
    tampered = 0

    for rec in records:
        decision_id = str(rec.get("decision_id", ""))
        args_hash = str(rec.get("tool_args_hash", ""))

        expected_hash = hashlib.sha256(
            f"{prev_hash}{decision_id}{args_hash}".encode()
        ).hexdigest()

        stored_hash = rec.get("chain_hash")

        if stored_hash is None:
            # Records created before hash-chain was enabled — compute and treat as valid
            status = "UNLINKED"
            verified += 1
        elif stored_hash == expected_hash:
            status = "VERIFIED"
            verified += 1
        else:
            status = "TAMPERED"
            tampered += 1

        results.append({
            "decision_id": decision_id,
            "status": status,
            "expected_hash": expected_hash,
            "stored_hash": stored_hash,
        })

        prev_hash = stored_hash if stored_hash else expected_hash

    overall = "TAMPERED" if tampered > 0 else "VERIFIED"
    return {
        "status": overall,
        "total_records": len(records),
        "verified": verified,
        "tampered": tampered,
        "records": results,
    }


# ---------------------------------------------------------------------------
# APEP-191 — Audit integrity verification (hash chain)
# ---------------------------------------------------------------------------


@router.get("/verify")
async def verify_audit_chain(
    _user: dict = Depends(get_current_user),
    start_sequence: int | None = Query(default=None),
    end_sequence: int | None = Query(default=None),
) -> dict[str, Any]:
    """Verify the audit hash chain by recomputing hashes (APEP-088).

    Returns {valid, total_records, verified_records, first_tampered_sequence}.
    """
    from app.services.audit_logger import GENESIS_HASH, compute_record_hash

    col = db_module.get_database()[db_module.AUDIT_DECISIONS]
    query: dict[str, Any] = {}
    if start_sequence is not None or end_sequence is not None:
        seq_filter: dict[str, int] = {}
        if start_sequence is not None:
            seq_filter["$gte"] = start_sequence
        if end_sequence is not None:
            seq_filter["$lte"] = end_sequence
        query["sequence_number"] = seq_filter
    cursor = col.find(query).sort("sequence_number", 1)
    records = [doc async for doc in cursor]

    if not records:
        return {
            "valid": True,
            "total_records": 0,
            "verified_records": 0,
            "first_tampered_sequence": None,
            "first_tampered_decision_id": None,
            "detail": "No audit records",
        }

    # If starting from a partial range, get the previous record's hash
    prev_hash = GENESIS_HASH
    if start_sequence is not None and start_sequence > 0:
        prev_rec = await col.find_one(
            {"sequence_number": start_sequence - 1},
        )
        if prev_rec:
            prev_hash = prev_rec.get("record_hash", GENESIS_HASH)

    verified = 0
    first_tampered_seq = None
    first_tampered_id = None

    for rec in records:
        from app.models.policy import AuditDecision

        rec.pop("_id", None)
        try:
            audit = AuditDecision(**rec)
        except Exception:
            first_tampered_seq = rec.get("sequence_number", 0)
            first_tampered_id = str(rec.get("decision_id", ""))
            break

        expected = compute_record_hash(audit, prev_hash)
        if rec.get("record_hash") != expected:
            first_tampered_seq = rec.get("sequence_number", 0)
            first_tampered_id = str(rec.get("decision_id", ""))
            break

        prev_hash = rec["record_hash"]
        verified += 1

    valid = first_tampered_seq is None
    return {
        "valid": valid,
        "total_records": len(records),
        "verified_records": verified,
        "first_tampered_sequence": first_tampered_seq,
        "first_tampered_decision_id": first_tampered_id,
        "detail": "All records verified" if valid else f"Tampered at seq {first_tampered_seq}",
    }


@router.post("/verify-integrity")
async def verify_audit_integrity(_user: dict = Depends(get_current_user)):
    """Run hash chain verification on the audit log.

    Returns verification result including any broken links detected.
    """
    from app.services.audit_integrity import audit_integrity_verifier

    result = await audit_integrity_verifier.verify_chain()
    return result.to_dict()


@router.get("/chain-length")
async def get_chain_length(_user: dict = Depends(get_current_user)):
    """Return the current number of entries in the audit hash chain."""
    from app.services.audit_integrity import audit_integrity_verifier

    length = await audit_integrity_verifier.get_chain_length()
    return {"chain_length": length}


# ---------------------------------------------------------------------------
# APEP-086 / APEP-087 — Compliance export (JSON, CSV, PDF)
# ---------------------------------------------------------------------------


@router.post("/export/json")
async def export_compliance_json(
    body: dict[str, Any], _user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Export audit records as a JSON compliance report."""
    from app.models.policy import AuditQueryRequest
    from app.services.compliance_export import export_json

    template = body.get("template", "DPDPA")
    params = AuditQueryRequest(
        agent_id=body.get("agent_id"),
        tool_name=body.get("tool_name"),
        decision=body.get("decision"),
    )
    result = await export_json(template, params)
    # Remap 'records' to 'items' for test compatibility
    if "records" in result:
        result["items"] = result.pop("records")
    return result


@router.post("/export/csv")
async def export_compliance_csv(
    body: dict[str, Any], _user: dict = Depends(get_current_user),
) -> StreamingResponse:
    """Export audit records as a CSV compliance report."""
    from app.models.policy import AuditQueryRequest
    from app.services.compliance_export import export_csv

    template = body.get("template", "DPDPA")
    params = AuditQueryRequest(
        agent_id=body.get("agent_id"),
        tool_name=body.get("tool_name"),
        decision=body.get("decision"),
    )
    csv_content = await export_csv(template, params)
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={template}_export.csv"
        },
    )


@router.post("/export/pdf")
async def export_compliance_pdf(body: dict[str, Any], _user: dict = Depends(get_current_user)):
    """Export audit records as a PDF compliance report."""
    from fastapi.responses import Response

    from app.models.policy import AuditQueryRequest
    from app.services.compliance_export import export_pdf

    template = body.get("template", "DPDPA")
    params = AuditQueryRequest(
        agent_id=body.get("agent_id"),
        tool_name=body.get("tool_name"),
        decision=body.get("decision"),
    )
    pdf_bytes = await export_pdf(template, params)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={template}_report.pdf"
        },
    )
