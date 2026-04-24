"""Unit tests for agentpep/policy/registry_webhook.py.

Sprint S-E03 — E03-T08c
Covers:
  - HMAC verification accepts valid signatures
  - HMAC verification rejects tampered signatures
  - HMAC verification allows when secret not configured (dev mode)
  - Webhook endpoint returns 202 on valid payload
  - Webhook endpoint returns 403 on HMAC failure + SECURITY_VIOLATION event
  - Webhook endpoint returns 400 on malformed payload
  - Webhook endpoint with unknown event type returns 400
  - Policy status endpoint returns bundle version metadata
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.policy.bundle_version import bundle_version_tracker
from app.policy.registry_webhook import (
    BundlePublishedEvent,
    router,
    verify_webhook_hmac,
)


# ---------------------------------------------------------------------------
# Test app fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def test_app():
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture()
def client(test_app):
    return TestClient(test_app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_tracker():
    bundle_version_tracker.reset()
    yield
    bundle_version_tracker.reset()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


SECRET = b"test-webhook-secret-key"
VALID_URL = (
    "https://registry.trustfabric.internal/agentpep/policies/"
    "global/core_enforcement/1.5.0/bundle.tar.gz"
)


def _make_payload(**overrides) -> dict:
    base = {
        "event": "bundle.published",
        "tenant_id": "global",
        "bundle_name": "core_enforcement",
        "version": "1.5.0",
        "bundle_url": VALID_URL,
        "published_at": "2026-04-24T12:00:00Z",
        "signature_url": VALID_URL + ".sig",
    }
    base.update(overrides)
    return base


def _sign_payload(body: bytes, secret: bytes = SECRET) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# verify_webhook_hmac
# ---------------------------------------------------------------------------


class TestVerifyWebhookHmac:
    def test_valid_hmac_returns_true(self, monkeypatch):
        from app.policy import registry_webhook as wh

        monkeypatch.setattr(wh, "_get_webhook_secret", lambda: SECRET)
        body = b'{"event": "bundle.published"}'
        sig = _sign_payload(body)
        assert verify_webhook_hmac(body, sig) is True

    def test_wrong_hmac_returns_false(self, monkeypatch):
        from app.policy import registry_webhook as wh

        monkeypatch.setattr(wh, "_get_webhook_secret", lambda: SECRET)
        body = b'{"event": "bundle.published"}'
        assert verify_webhook_hmac(body, "deadbeef" * 8) is False

    def test_empty_signature_returns_false(self, monkeypatch):
        from app.policy import registry_webhook as wh

        monkeypatch.setattr(wh, "_get_webhook_secret", lambda: SECRET)
        body = b'{"event": "bundle.published"}'
        assert verify_webhook_hmac(body, "") is False

    def test_no_secret_configured_returns_true(self, monkeypatch):
        """When secret not configured, verification is skipped (dev mode)."""
        from app.policy import registry_webhook as wh

        monkeypatch.setattr(wh, "_get_webhook_secret", lambda: None)
        assert verify_webhook_hmac(b"anything", "") is True

    def test_tampered_body_returns_false(self, monkeypatch):
        from app.policy import registry_webhook as wh

        monkeypatch.setattr(wh, "_get_webhook_secret", lambda: SECRET)
        original = b'{"event": "bundle.published"}'
        sig = _sign_payload(original)
        tampered = b'{"event": "bundle.revoked"}'
        assert verify_webhook_hmac(tampered, sig) is False


# ---------------------------------------------------------------------------
# BundlePublishedEvent validation
# ---------------------------------------------------------------------------


class TestBundlePublishedEvent:
    def test_valid_event(self):
        event = BundlePublishedEvent(**_make_payload())
        assert event.event == "bundle.published"
        assert event.bundle_url == VALID_URL

    def test_unknown_event_type_raises(self):
        with pytest.raises(Exception):
            BundlePublishedEvent(**_make_payload(event="unknown.event"))

    def test_empty_bundle_url_raises(self):
        with pytest.raises(Exception):
            BundlePublishedEvent(**_make_payload(bundle_url=""))

    def test_deny_all_event_accepted(self):
        event = BundlePublishedEvent(**_make_payload(event="deny_all.published"))
        assert event.event == "deny_all.published"

    def test_bundle_revoked_accepted(self):
        event = BundlePublishedEvent(**_make_payload(event="bundle.revoked"))
        assert event.event == "bundle.revoked"


# ---------------------------------------------------------------------------
# /api/internal/policy/reload endpoint
# ---------------------------------------------------------------------------


class TestReloadEndpoint:
    def _post(self, client, payload: dict, secret: bytes | None = None, extra_headers: dict | None = None):
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if secret is not None:
            headers["X-AAPM-Signature"] = _sign_payload(body, secret)
        if extra_headers:
            headers.update(extra_headers)
        return client.post("/api/internal/policy/reload", content=body, headers=headers)

    def test_valid_payload_no_secret_returns_202(self, client, monkeypatch):
        from app.policy import registry_webhook as wh

        # Disable HMAC (secret not configured)
        monkeypatch.setattr(wh, "_get_webhook_secret", lambda: None)

        from app.policy.loader import PolicyLoaderError
        with patch("app.policy.registry_webhook.policy_loader") as mock_loader:
            mock_result = MagicMock()
            mock_result.version.version = "1.5.0"
            mock_result.sha256 = "deadbeef" * 8
            mock_loader.load_and_track.return_value = mock_result

            resp = self._post(client, _make_payload())

        assert resp.status_code == 202

    def test_valid_payload_with_hmac_returns_202(self, client, monkeypatch):
        from app.policy import registry_webhook as wh

        monkeypatch.setattr(wh, "_get_webhook_secret", lambda: SECRET)

        with patch("app.policy.registry_webhook.policy_loader") as mock_loader:
            mock_result = MagicMock()
            mock_result.version.version = "1.5.0"
            mock_result.sha256 = "deadbeef" * 8
            mock_loader.load_and_track.return_value = mock_result

            resp = self._post(client, _make_payload(), secret=SECRET)

        assert resp.status_code == 202
        body = resp.json()
        assert body["status"] == "reloaded"

    def test_wrong_hmac_returns_403(self, client, monkeypatch):
        from app.policy import registry_webhook as wh

        monkeypatch.setattr(wh, "_get_webhook_secret", lambda: SECRET)

        payload = _make_payload()
        body = json.dumps(payload).encode()
        resp = client.post(
            "/api/internal/policy/reload",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-AAPM-Signature": "badhash",
            },
        )
        assert resp.status_code == 403

    def test_wrong_hmac_emits_security_violation(self, client, monkeypatch, caplog):
        from app.policy import registry_webhook as wh

        monkeypatch.setattr(wh, "_get_webhook_secret", lambda: SECRET)

        payload = _make_payload()
        body = json.dumps(payload).encode()
        with caplog.at_level(logging.ERROR):
            client.post(
                "/api/internal/policy/reload",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-AAPM-Signature": "badhash",
                },
            )
        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records)

    def test_malformed_json_returns_400(self, client, monkeypatch):
        from app.policy import registry_webhook as wh

        monkeypatch.setattr(wh, "_get_webhook_secret", lambda: None)
        resp = client.post(
            "/api/internal/policy/reload",
            content=b"not json at all",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_missing_required_field_returns_400(self, client, monkeypatch):
        from app.policy import registry_webhook as wh

        monkeypatch.setattr(wh, "_get_webhook_secret", lambda: None)
        payload = {"event": "bundle.published"}  # missing required fields
        body = json.dumps(payload).encode()
        resp = client.post(
            "/api/internal/policy/reload",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_loader_failure_returns_202_with_reload_failed(self, client, monkeypatch):
        """Even if reload fails, webhook is acknowledged; fail info in body."""
        from app.policy import registry_webhook as wh
        from app.policy.loader import PolicyLoaderError

        monkeypatch.setattr(wh, "_get_webhook_secret", lambda: None)

        with patch("app.policy.registry_webhook.policy_loader") as mock_loader:
            mock_loader.load_and_track.side_effect = PolicyLoaderError("sig verification failed")
            resp = self._post(client, _make_payload())

        assert resp.status_code == 202
        body = resp.json()
        assert body["status"] == "reload_failed"
        assert body["previous_bundle_active"] is True


# ---------------------------------------------------------------------------
# /api/internal/policy/status endpoint
# ---------------------------------------------------------------------------


class TestPolicyStatusEndpoint:
    def test_status_returns_unloaded_before_any_bundle(self, client):
        resp = client.get("/api/internal/policy/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["is_loaded"] is False
        assert body["version"] == "unloaded"

    def test_status_reflects_loaded_bundle(self, client):
        from app.policy.bundle_version import BundleVersion

        bv = BundleVersion(version="2.0.0", bundle_name="core", tenant_id="global")
        bundle_version_tracker.update(bv)

        resp = client.get("/api/internal/policy/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["is_loaded"] is True
        assert body["version"] == "2.0.0"
        assert body["bundle_name"] == "core"
