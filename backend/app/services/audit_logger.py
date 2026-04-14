"""AuditLogger — append-only audit log with SHA-256 hash chain.

Sprint 10:
  APEP-081: Append AuditDecision to MongoDB capped collection
  APEP-082: SHA-256 hash chain across sequential audit records

Sprint 39:
  APEP-309: Per-receipt Ed25519 signing — each audit record receives an
            individual Ed25519 signature covering its canonical fields.
"""

import asyncio
import base64
import hashlib
import json
import logging
from typing import Any

from app.db import mongodb as db_module
from app.models.policy import AuditDecision

logger = logging.getLogger(__name__)

# Genesis hash — seed for the very first record in the chain
GENESIS_HASH = hashlib.sha256(b"AGENTPEP_GENESIS").hexdigest()

# Check for optional Ed25519 support
_HAS_NACL = False
try:
    import nacl.signing  # type: ignore[import-untyped]

    _HAS_NACL = True
except ImportError:
    pass


def compute_record_hash(audit: AuditDecision, previous_hash: str) -> str:
    """Compute SHA-256 hash for an audit record chained to the previous hash.

    The hash covers all semantically meaningful fields to detect any tampering.
    """
    payload = json.dumps(
        {
            "previous_hash": previous_hash,
            "sequence_number": audit.sequence_number,
            "decision_id": str(audit.decision_id),
            "session_id": audit.session_id,
            "agent_id": audit.agent_id,
            "agent_role": audit.agent_role,
            "tool_name": audit.tool_name,
            "tool_args_hash": audit.tool_args_hash,
            "decision": audit.decision.value,
            "risk_score": audit.risk_score,
            "matched_rule_id": str(audit.matched_rule_id) if audit.matched_rule_id else None,
            "taint_flags": audit.taint_flags,
            "delegation_chain": audit.delegation_chain,
            "latency_ms": audit.latency_ms,
            "timestamp": audit.timestamp.isoformat(),
            # Sprint 39 — APEP-308: plan context fields
            "plan_id": str(audit.plan_id) if audit.plan_id else None,
            "parent_receipt_id": str(audit.parent_receipt_id) if audit.parent_receipt_id else None,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _canonical_receipt_payload(audit: AuditDecision) -> bytes:
    """Produce canonical bytes for per-receipt signing (APEP-309).

    Covers identity, decision, plan context, and chain linkage fields.
    """
    payload: dict[str, Any] = {
        "decision_id": str(audit.decision_id),
        "session_id": audit.session_id,
        "agent_id": audit.agent_id,
        "agent_role": audit.agent_role,
        "tool_name": audit.tool_name,
        "tool_args_hash": audit.tool_args_hash,
        "decision": audit.decision.value,
        "risk_score": audit.risk_score,
        "matched_rule_id": str(audit.matched_rule_id) if audit.matched_rule_id else None,
        "taint_flags": audit.taint_flags,
        "delegation_chain": audit.delegation_chain,
        "latency_ms": audit.latency_ms,
        "timestamp": audit.timestamp.isoformat(),
        "sequence_number": audit.sequence_number,
        "record_hash": audit.record_hash,
        "plan_id": str(audit.plan_id) if audit.plan_id else None,
        "parent_receipt_id": str(audit.parent_receipt_id) if audit.parent_receipt_id else None,
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


class ReceiptSigningKey:
    """Manages an Ed25519 signing key for per-receipt signatures (APEP-309).

    If PyNaCl is not installed, signing is a no-op (returns empty string).
    """

    def __init__(self, private_key: bytes | None = None) -> None:
        self._signing_key: Any = None
        if _HAS_NACL:
            if private_key:
                self._signing_key = nacl.signing.SigningKey(private_key)
            else:
                self._signing_key = nacl.signing.SigningKey.generate()

    @property
    def available(self) -> bool:
        return self._signing_key is not None

    def sign(self, data: bytes) -> str:
        """Sign data and return base64url-encoded signature."""
        if not self._signing_key:
            return ""
        signed = self._signing_key.sign(data)
        return base64.urlsafe_b64encode(signed.signature).decode()

    def get_verify_key_bytes(self) -> bytes:
        """Export the 32-byte Ed25519 verify (public) key."""
        if not self._signing_key:
            return b""
        return bytes(self._signing_key.verify_key)


class AuditLogger:
    """Append-only audit logger with SHA-256 hash chain.

    Thread-safe via a lock protecting the sequence counter and previous hash.

    Sprint 39 (APEP-309): Optionally signs each receipt with Ed25519 and
    stores the signature in ``receipt_signature``.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._sequence: int = 0
        self._previous_hash: str = GENESIS_HASH
        self._initialized: bool = False
        # Sprint 39 — per-receipt signing key (set via configure_receipt_signing)
        self._receipt_key: ReceiptSigningKey | None = None

    def configure_receipt_signing(self, private_key: bytes | None = None) -> None:
        """Enable per-receipt Ed25519 signing (APEP-309).

        If *private_key* is None a fresh keypair is generated.
        """
        self._receipt_key = ReceiptSigningKey(private_key)

    @property
    def receipt_signing_enabled(self) -> bool:
        return self._receipt_key is not None and self._receipt_key.available

    def get_receipt_verify_key(self) -> bytes:
        """Return the Ed25519 public verify key for receipt signature validation."""
        if self._receipt_key:
            return self._receipt_key.get_verify_key_bytes()
        return b""

    async def initialize(self) -> None:
        """Load the latest sequence number and hash from MongoDB to resume the chain."""
        db = db_module.get_database()
        last_record = await db[db_module.AUDIT_DECISIONS].find_one(
            sort=[("sequence_number", -1)]
        )
        if last_record:
            async with self._lock:
                self._sequence = last_record.get("sequence_number", 0)
                self._previous_hash = last_record.get("record_hash", GENESIS_HASH)
        self._initialized = True

    async def append(self, audit: AuditDecision) -> AuditDecision:
        """Append an audit record with hash chain fields and persist to MongoDB.

        Returns the audit record with populated sequence_number, previous_hash,
        record_hash, and (if enabled) receipt_signature fields.
        """
        if not self._initialized:
            await self.initialize()

        async with self._lock:
            self._sequence += 1
            audit.sequence_number = self._sequence
            audit.previous_hash = self._previous_hash
            audit.record_hash = compute_record_hash(audit, self._previous_hash)
            self._previous_hash = audit.record_hash

        # Sprint 39 — APEP-309: Per-receipt Ed25519 signature
        if self._receipt_key and self._receipt_key.available:
            canonical = _canonical_receipt_payload(audit)
            audit.receipt_signature = self._receipt_key.sign(canonical)

        db = db_module.get_database()
        try:
            await db[db_module.AUDIT_DECISIONS].insert_one(
                audit.model_dump(mode="json")
            )
        except Exception:
            logger.exception("Failed to write audit record seq=%d", audit.sequence_number)

        return audit

    def reset(self) -> None:
        """Reset internal state (used in tests)."""
        self._lock = asyncio.Lock()
        self._sequence = 0
        self._previous_hash = GENESIS_HASH
        self._initialized = False
        self._receipt_key = None


# Module-level singleton
audit_logger = AuditLogger()
