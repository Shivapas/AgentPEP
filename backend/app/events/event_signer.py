"""HMAC event signer — tamper-evident PostToolUse event stream.

Each OCSF event emitted by AgentPEP is signed with HMAC-SHA256 over its
canonical JSON representation (excluding the signature field itself).
The signature is stored in event["metadata"]["hmac_signature"].

TrustSOC consumers can verify signatures to detect any in-flight
modification of the event stream between AgentPEP and the SIEM.

Key source: settings.posttooluse_hmac_key (operator-configurable via
AGENTPEP_POSTTOOLUSE_HMAC_KEY environment variable).  If the key is not
configured, signing is skipped and a one-time WARNING is logged.

Sprint S-E07 (E07-T04)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

_UNSIGNED_WARNED: bool = False


def _canonical_bytes(event: dict[str, Any]) -> bytes:
    """Return a stable canonical byte representation of an event body.

    The metadata.hmac_signature and metadata.hmac_algorithm fields are
    excluded so the signature is computed over everything else.
    """
    body = dict(event)
    meta = dict(body.get("metadata", {}))
    meta.pop("hmac_signature", None)
    meta.pop("hmac_algorithm", None)
    body["metadata"] = meta
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_event(event: dict[str, Any], key: str) -> dict[str, Any]:
    """Sign an OCSF event dict with HMAC-SHA256.

    Mutates event in-place, adding 'hmac_signature' and 'hmac_algorithm'
    to event['metadata'].  Returns the same dict for chaining.

    Args:
        event: OCSF event dict (mutated in-place).
        key:   HMAC key string.  Must not be empty.

    Raises:
        ValueError: If key is empty.
    """
    if not key:
        raise ValueError("HMAC signing key must not be empty")

    canonical = _canonical_bytes(event)
    sig = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

    if "metadata" not in event:
        event["metadata"] = {}
    event["metadata"]["hmac_signature"] = sig
    event["metadata"]["hmac_algorithm"] = "HMAC-SHA256"

    return event


def verify_event(event: dict[str, Any], key: str) -> bool:
    """Verify the HMAC-SHA256 signature on a signed OCSF event.

    Returns True if the signature matches, False if invalid or absent.
    """
    if not key:
        return False

    metadata = event.get("metadata", {})
    stored_sig = metadata.get("hmac_signature", "")
    if not stored_sig:
        return False

    body = dict(event)
    meta = dict(metadata)
    meta.pop("hmac_signature", None)
    meta.pop("hmac_algorithm", None)
    body["metadata"] = meta

    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    expected = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

    return hmac.compare_digest(stored_sig, expected)


def try_sign_event(event: dict[str, Any]) -> dict[str, Any]:
    """Sign an event using the configured HMAC key from settings.

    If the key is absent, logs a one-time warning and returns the event
    unsigned.  Never raises — signing failure must not block event emission.
    """
    global _UNSIGNED_WARNED

    from app.core.config import settings

    key: str = getattr(settings, "posttooluse_hmac_key", "")
    if not key:
        if not _UNSIGNED_WARNED:
            logger.warning(
                "posttooluse_hmac_key not configured — PostToolUse events are unsigned. "
                "Set AGENTPEP_POSTTOOLUSE_HMAC_KEY to enable tamper-evident signing."
            )
            _UNSIGNED_WARNED = True
        return event

    try:
        return sign_event(event, key)
    except Exception:
        logger.exception("Failed to sign OCSF event")
        return event
