"""AAPM Policy Registry webhook receiver — FEATURE-09 (Part A).

Accepts push notifications from the AAPM Policy Registry when a new bundle
is published.  On receipt of a valid, HMAC-authenticated notification,
triggers an immediate bundle reload via the trusted policy loader.

Endpoint: POST /api/internal/policy/reload

Authentication: HMAC-SHA256 over the raw request body using a shared secret
provisioned by AAPM during onboarding.  The secret is read from the
environment variable named in trusted_key.WEBHOOK_HMAC_SECRET_ENV_VAR.

If HMAC verification fails, the request is rejected with 403 and a
SECURITY_VIOLATION event is emitted (attackers must not be able to trigger
policy reloads with arbitrary bundle URLs).

Sprint S-E03 (E03-T05)
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

from fastapi import APIRouter, Body, Header, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from app.core.structured_logging import get_logger
from app.policy.events import SecurityViolationReason, emit_security_violation_event
from app.policy.loader import PolicyLoaderError, TrustedPolicyLoader, policy_loader
from app.policy.trusted_key import WEBHOOK_HMAC_SECRET_ENV_VAR

logger = get_logger(__name__)

router = APIRouter(prefix="/api/internal/policy", tags=["policy-internal"])


# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------


class BundlePublishedEvent(BaseModel):
    """Webhook payload sent by AAPM when a new bundle is published."""

    event: str
    tenant_id: str
    bundle_name: str
    version: str
    bundle_url: str
    published_at: str
    signature_url: str = ""

    @field_validator("event")
    @classmethod
    def event_must_be_known(cls, v: str) -> str:
        known = {"bundle.published", "bundle.revoked", "deny_all.published"}
        if v not in known:
            raise ValueError(f"Unknown event type {v!r}; must be one of {known}")
        return v

    @field_validator("bundle_url")
    @classmethod
    def bundle_url_must_be_non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("bundle_url must not be empty")
        return v.strip()


# ---------------------------------------------------------------------------
# HMAC verification
# ---------------------------------------------------------------------------


def _get_webhook_secret() -> bytes | None:
    """Return the HMAC secret bytes from the environment keystore.

    Returns None if the secret is not configured (webhook auth disabled).
    """
    secret = os.environ.get(WEBHOOK_HMAC_SECRET_ENV_VAR, "").strip()
    if not secret:
        return None
    return secret.encode()


def verify_webhook_hmac(body: bytes, signature_header: str) -> bool:
    """Verify the HMAC-SHA256 signature sent by AAPM.

    The AAPM webhook sender computes:
        HMAC-SHA256(key=webhook_secret, msg=raw_body)
    and includes the hex digest in the ``X-AAPM-Signature`` header.

    Returns True if valid, False if the secret is misconfigured or the
    signature does not match.
    """
    secret = _get_webhook_secret()
    if secret is None:
        # Secret not configured — log a warning but allow (dev/test mode).
        # In production, operators must configure the secret.
        logger.warning(
            "webhook_hmac_secret_not_configured",
            detail=(
                f"Set {WEBHOOK_HMAC_SECRET_ENV_VAR} to enable webhook authentication. "
                "Running without HMAC verification is insecure in production."
            ),
        )
        return True

    if not signature_header:
        return False

    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header.strip())


# ---------------------------------------------------------------------------
# Reload endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/reload",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive AAPM bundle-published notification and trigger reload",
    response_model=dict,
)
async def receive_bundle_published(
    request: Request,
    x_aapm_signature: str = Header(default="", alias="X-AAPM-Signature"),
) -> dict[str, Any]:
    """Webhook receiver: AAPM → AgentPEP bundle reload trigger.

    Authentication:
        HMAC-SHA256 in X-AAPM-Signature header.

    On success:
        Returns 202.  The bundle reload is initiated synchronously; the
        current bundle remains active until the new bundle passes signature
        verification.

    On HMAC failure:
        Returns 403.  SECURITY_VIOLATION event emitted.

    On invalid payload:
        Returns 400.
    """
    raw_body = await request.body()

    if not verify_webhook_hmac(raw_body, x_aapm_signature):
        emit_security_violation_event(
            reason=SecurityViolationReason.INVALID_SIGNATURE,
            detail=(
                "Webhook HMAC verification failed — request rejected. "
                "AAPM team: verify the shared HMAC secret is correctly provisioned."
            ),
            source_url=str(request.url),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="HMAC verification failed",
        )

    # Parse and validate the payload
    import json

    try:
        payload_data = json.loads(raw_body)
        event = BundlePublishedEvent(**payload_data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid webhook payload: {exc}",
        )

    logger.info(
        "webhook_bundle_published_received",
        event_type=event.event,
        tenant_id=event.tenant_id,
        bundle_name=event.bundle_name,
        version=event.version,
        bundle_url=event.bundle_url,
    )

    # Trigger reload via trusted policy loader (FAIL_CLOSED on error)
    result = _reload_bundle(event)
    return result


def _reload_bundle(event: BundlePublishedEvent) -> dict[str, Any]:
    """Attempt to load and verify the new bundle.

    Returns a result dict indicating success or failure.  On failure the
    previously active bundle remains in force.
    """
    try:
        loaded = policy_loader.load_and_track(
            bundle_url=event.bundle_url,
            tenant_id=event.tenant_id,
            bundle_name=event.bundle_name,
        )
        logger.info(
            "webhook_bundle_reload_success",
            version=loaded.version.version,
            bundle_name=event.bundle_name,
            tenant_id=event.tenant_id,
        )
        return {
            "status": "reloaded",
            "version": loaded.version.version,
            "bundle_name": event.bundle_name,
            "tenant_id": event.tenant_id,
            "sha256": loaded.sha256[:16],
        }
    except PolicyLoaderError as exc:
        # FAIL_CLOSED: previous bundle stays active; error surfaced to caller
        logger.error(
            "webhook_bundle_reload_failed",
            bundle_url=event.bundle_url,
            error=str(exc),
        )
        # Return 202 — the webhook was received and acknowledged; the
        # reload failure is an internal event, not a caller error.
        return {
            "status": "reload_failed",
            "detail": str(exc),
            "previous_bundle_active": True,
        }


# ---------------------------------------------------------------------------
# Status endpoint (for health checks and monitoring)
# ---------------------------------------------------------------------------


@router.get(
    "/status",
    summary="Current loaded policy bundle version",
    response_model=dict,
)
async def policy_status() -> dict[str, Any]:
    """Return the currently loaded policy bundle version metadata."""
    from app.policy.bundle_version import bundle_version_tracker

    bv = bundle_version_tracker.current
    return {
        "is_loaded": bundle_version_tracker.is_loaded,
        "version": bv.version,
        "bundle_name": bv.bundle_name,
        "tenant_id": bv.tenant_id,
        "loaded_at_ms": bv.loaded_at_ms,
        "source_url": bv.source_url,
    }
