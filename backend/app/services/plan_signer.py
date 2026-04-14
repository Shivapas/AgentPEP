"""PlanSigner -- Ed25519 cryptographic signing for MissionPlans.

Sprint 37 -- APEP-293: Ed25519 plan signing using PyNaCl.
Signs canonical plan fields so integrity can be verified offline.
Falls back to HMAC-SHA256 when PyNaCl is not installed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
from typing import Any

from app.models.mission_plan import MissionPlan

logger = logging.getLogger(__name__)

_HAS_NACL = False
try:
    import nacl.signing  # type: ignore[import-untyped]

    _HAS_NACL = True
except ImportError:
    pass


class PlanSigner:
    """Sign and verify MissionPlan documents using Ed25519 or HMAC-SHA256.

    Ed25519 is preferred — the verify key can be distributed for offline
    verification.  If PyNaCl is unavailable the signer falls back to
    HMAC-SHA256.
    """

    def __init__(
        self,
        signing_method: str = "ed25519",
        private_key: bytes | None = None,
        key_id: str = "plan-default",
    ) -> None:
        self._key_id = key_id
        self._requested_method = signing_method.lower()

        if self._requested_method == "ed25519" and _HAS_NACL:
            self._method = "ed25519"
            if private_key:
                self._signing_key = nacl.signing.SigningKey(private_key)
            else:
                self._signing_key = nacl.signing.SigningKey.generate()
            self._hmac_key: bytes = b""
        else:
            if self._requested_method == "ed25519" and not _HAS_NACL:
                logger.warning(
                    "PyNaCl not installed -- falling back to hmac-sha256 for plan signing. "
                    "Install pynacl to enable Ed25519 signing."
                )
            self._method = "hmac-sha256"
            self._hmac_key = private_key or os.urandom(32)
            self._signing_key = None  # type: ignore[assignment]

    @property
    def method(self) -> str:
        return self._method

    @property
    def key_id(self) -> str:
        return self._key_id

    @staticmethod
    def canonicalize(plan: MissionPlan) -> bytes:
        """Produce a canonical byte representation of the signable plan fields.

        Only immutable fields are included -- runtime counters
        (delegation_count, accumulated_risk) and status are excluded.
        """
        data: dict[str, Any] = {
            "plan_id": str(plan.plan_id),
            "action": plan.action,
            "issuer": plan.issuer,
            "scope": sorted(plan.scope),
            "requires_checkpoint": sorted(plan.requires_checkpoint),
            "delegates_to": sorted(plan.delegates_to),
            "budget": {
                "max_delegations": plan.budget.max_delegations,
                "max_risk_total": plan.budget.max_risk_total,
                "ttl_seconds": plan.budget.ttl_seconds,
            },
            "issued_at": plan.issued_at.isoformat(),
            "expires_at": plan.expires_at.isoformat() if plan.expires_at else None,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign_plan(self, plan: MissionPlan) -> str:
        """Sign a MissionPlan and return a base64-encoded signature string.

        Format: ``agentpep-plan-v1|{key_id}|{algorithm}|{b64_content_hash}|{b64_signature}``
        """
        canonical = self.canonicalize(plan)
        content_hash = hashlib.sha256(canonical).digest()
        b64_hash = base64.urlsafe_b64encode(content_hash).decode()

        if self._method == "ed25519":
            signed = self._signing_key.sign(canonical)
            b64_sig = base64.urlsafe_b64encode(signed.signature).decode()
        else:
            sig = hmac.new(self._hmac_key, canonical, hashlib.sha256).digest()
            b64_sig = base64.urlsafe_b64encode(sig).decode()

        return f"agentpep-plan-v1|{self._key_id}|{self._method}|{b64_hash}|{b64_sig}"

    def verify_plan(self, plan: MissionPlan) -> bool:
        """Verify the signature on a MissionPlan.

        Returns True if the signature is valid, False otherwise.
        """
        if not plan.signature:
            return False

        try:
            parts = plan.signature.split("|")
            if len(parts) != 5 or parts[0] != "agentpep-plan-v1":
                return False

            canonical = self.canonicalize(plan)
            sig_bytes = base64.urlsafe_b64decode(parts[4])

            if self._method == "ed25519":
                verify_key = self._signing_key.verify_key
                verify_key.verify(canonical, sig_bytes)
                return True
            else:
                expected = hmac.new(self._hmac_key, canonical, hashlib.sha256).digest()
                return hmac.compare_digest(sig_bytes, expected)
        except Exception:
            logger.debug("Plan signature verification failed", exc_info=True)
            return False

    def get_verify_key_bytes(self) -> bytes:
        """Export the verification key for offline verification."""
        if self._method == "ed25519":
            return bytes(self._signing_key.verify_key)
        return self._hmac_key

    def reset(self) -> None:
        """Reset internal state (for testing)."""
        pass


# Module-level singleton (initialized from settings in main.py lifespan)
plan_signer: PlanSigner | None = None
