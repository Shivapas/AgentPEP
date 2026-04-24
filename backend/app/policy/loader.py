"""Trusted policy loader — FEATURE-02 (AAPM Consumer Interface).

Loads Rego policy bundles exclusively from the AAPM Policy Registry.

Security invariants enforced here:
  1. Source allowlist: only the compile-time AAPM_REGISTRY_BASE_URL is
     accepted.  Any other URL → FAIL_CLOSED + SECURITY_VIOLATION event.
  2. Signature verification: every bundle is verified against the pinned
     AAPM Ed25519 public key before it is accepted.  Verification failure
     → FAIL_CLOSED + SECURITY_VIOLATION event.
  3. No runtime override: there is no operator configuration, environment
     variable, or CLI flag that can change the allowlisted source or the
     pinned key.  The debug-mode dev key override is the only exception and
     is controlled by trusted_key.py, not by user input.

FAIL_CLOSED definition: on any error during load or verification, the
previously loaded bundle (if any) remains in force; no partially-loaded
or unverified bundle is ever used by the evaluator.

Sprint S-E03 (E03-T01, E03-T02)
"""

from __future__ import annotations

import hashlib
import io
import tarfile
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.structured_logging import get_logger
from app.policy.bundle_version import BundleVersion, bundle_version_tracker
from app.policy.events import SecurityViolationReason, emit_security_violation_event
from app.policy.trusted_key import AAPM_REGISTRY_BASE_URL, get_pinned_public_key

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Bundle data model
# ---------------------------------------------------------------------------


@dataclass
class LoadedBundle:
    """An immutable snapshot of a successfully loaded and verified bundle."""

    version: BundleVersion
    raw_bytes: bytes
    rego_files: dict[str, bytes] = field(default_factory=dict)
    data_json: bytes = b""
    manifest: dict[str, Any] = field(default_factory=dict)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Loader errors
# ---------------------------------------------------------------------------


class PolicyLoaderError(Exception):
    """Raised when a bundle cannot be loaded or verified."""


class UntrustedSourceError(PolicyLoaderError):
    """Source URL is not on the AAPM registry allowlist."""


class SignatureVerificationError(PolicyLoaderError):
    """Bundle signature is absent, invalid, or unverifiable."""


# ---------------------------------------------------------------------------
# Core loader
# ---------------------------------------------------------------------------


class TrustedPolicyLoader:
    """Loads and verifies AAPM Rego policy bundles.

    Only accepts bundles fetched from AAPM_REGISTRY_BASE_URL.  Verifies
    the Ed25519 signature (provided as a companion ``.sig`` file) against
    the pinned public key before accepting any bundle.

    All failures are FAIL_CLOSED: the loader raises ``PolicyLoaderError``
    and the caller retains the previously loaded bundle unchanged.
    """

    def __init__(
        self,
        http_timeout_s: float = 30.0,
        _public_key_override: Ed25519PublicKey | None = None,
    ) -> None:
        """
        Args:
            http_timeout_s: HTTP request timeout for bundle/signature fetches.
            _public_key_override: For testing only — bypasses get_pinned_public_key().
        """
        self._http_timeout_s = http_timeout_s
        self._public_key_override = _public_key_override

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_bundle(
        self,
        bundle_url: str,
        tenant_id: str = "global",
        bundle_name: str = "core_enforcement",
    ) -> LoadedBundle:
        """Fetch, verify, and return a policy bundle.

        Source validation, signature verification, and bundle parsing are
        performed in sequence.  Any failure raises ``PolicyLoaderError``
        (FAIL_CLOSED — caller must not substitute an unverified bundle).

        Args:
            bundle_url: Full URL of the bundle tar.gz on the AAPM registry.
            tenant_id:  Tenant identifier embedded in the bundle path.
            bundle_name: Logical bundle name (e.g. "core_enforcement").

        Returns:
            A ``LoadedBundle`` snapshot.  After a successful return the
            caller should call ``bundle_version_tracker.update(bundle.version)``
            to make the new version visible to the enforcement decision log.

        Raises:
            UntrustedSourceError: URL not allowlisted.
            SignatureVerificationError: Signature absent or invalid.
            PolicyLoaderError: Any other load / parse failure.
        """
        self._validate_source_url(bundle_url)

        sig_url = bundle_url + ".sig"
        start = time.monotonic()

        try:
            bundle_bytes = self._fetch(bundle_url)
            sig_bytes = self._fetch(sig_url)
        except httpx.HTTPError as exc:
            raise PolicyLoaderError(
                f"HTTP error fetching bundle from {bundle_url!r}: {exc}"
            ) from exc

        self._verify_signature(bundle_bytes, sig_bytes, source_url=bundle_url)

        version_str, etag = self._parse_version_from_url(bundle_url)
        rego_files, data_json, manifest = self._unpack_bundle(bundle_bytes, bundle_url)

        bv = BundleVersion(
            version=version_str,
            bundle_name=bundle_name,
            tenant_id=tenant_id,
            loaded_at_ms=int(time.time() * 1000),
            source_url=bundle_url,
            etag=etag,
        )
        loaded = LoadedBundle(
            version=bv,
            raw_bytes=bundle_bytes,
            rego_files=rego_files,
            data_json=data_json,
            manifest=manifest,
        )

        elapsed = time.monotonic() - start
        logger.info(
            "policy_bundle_loaded",
            bundle_url=bundle_url,
            version=version_str,
            tenant_id=tenant_id,
            bundle_name=bundle_name,
            rego_file_count=len(rego_files),
            bundle_sha256=loaded.sha256[:16],
            elapsed_s=round(elapsed, 3),
        )

        return loaded

    def load_and_track(
        self,
        bundle_url: str,
        tenant_id: str = "global",
        bundle_name: str = "core_enforcement",
    ) -> LoadedBundle:
        """Load a bundle and immediately update the global version tracker.

        Convenience wrapper over ``load_bundle`` that also calls
        ``bundle_version_tracker.update()``.
        """
        loaded = self.load_bundle(bundle_url, tenant_id=tenant_id, bundle_name=bundle_name)
        bundle_version_tracker.update(loaded.version)
        return loaded

    # ------------------------------------------------------------------
    # Source validation (E03-T01)
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_source_url(url: str) -> None:
        """Reject any URL that is not on the AAPM registry allowlist.

        Checks:
          - Scheme must be https (or http for localhost dev)
          - Host + path prefix must match AAPM_REGISTRY_BASE_URL
          - No user-info (no embedded credentials)
          - No path traversal sequences

        Emits SECURITY_VIOLATION and raises UntrustedSourceError on failure.
        """
        parsed = urlparse(url)
        allowlist_parsed = urlparse(AAPM_REGISTRY_BASE_URL)

        # Allow http only for localhost (mock registry in dev/test)
        is_localhost = parsed.hostname in ("localhost", "127.0.0.1", "::1")

        if parsed.scheme not in ("https", "http"):
            _reject_untrusted(url, f"scheme {parsed.scheme!r} not allowed")

        if parsed.scheme == "http" and not is_localhost:
            _reject_untrusted(url, "http is only permitted for localhost (dev/test)")

        if parsed.username or parsed.password:
            _reject_untrusted(url, "embedded credentials in URL are not permitted")

        # Path traversal guard
        if ".." in url or "%2e%2e" in url.lower() or "%2f" in url.lower():
            _reject_untrusted(url, "path traversal sequence detected in URL")

        # Allowlist check (skip for localhost)
        if not is_localhost:
            if parsed.scheme != allowlist_parsed.scheme:
                _reject_untrusted(url, f"scheme mismatch vs allowlist ({allowlist_parsed.scheme})")
            if parsed.netloc != allowlist_parsed.netloc:
                _reject_untrusted(
                    url,
                    f"host {parsed.netloc!r} not allowlisted "
                    f"(expected {allowlist_parsed.netloc!r})",
                )
            if not parsed.path.startswith(allowlist_parsed.path):
                _reject_untrusted(
                    url,
                    f"path does not start with allowlisted prefix {allowlist_parsed.path!r}",
                )

    # ------------------------------------------------------------------
    # Signature verification (E03-T02)
    # ------------------------------------------------------------------

    def _verify_signature(
        self,
        bundle_bytes: bytes,
        sig_bytes: bytes,
        source_url: str = "",
    ) -> None:
        """Verify the Ed25519 signature of *bundle_bytes*.

        The signature file is raw Ed25519 signature bytes (64 bytes).
        The signed message is the SHA-256 digest of the bundle bytes.

        Emits SECURITY_VIOLATION and raises SignatureVerificationError on
        any failure (absent key, wrong key, corrupted bytes).
        """
        if not sig_bytes:
            emit_security_violation_event(
                reason=SecurityViolationReason.INVALID_SIGNATURE,
                detail="Signature file is empty",
                source_url=source_url,
            )
            raise SignatureVerificationError(
                f"Empty signature for bundle at {source_url!r}"
            )

        public_key = self._get_public_key()
        digest = hashlib.sha256(bundle_bytes).digest()

        try:
            public_key.verify(sig_bytes, digest)
        except InvalidSignature:
            emit_security_violation_event(
                reason=SecurityViolationReason.INVALID_SIGNATURE,
                detail="Ed25519 signature does not match bundle digest",
                source_url=source_url,
            )
            raise SignatureVerificationError(
                f"Invalid Ed25519 signature for bundle at {source_url!r}"
            )
        except Exception as exc:
            emit_security_violation_event(
                reason=SecurityViolationReason.SIGNATURE_VERIFICATION_ERROR,
                detail=f"Signature verification raised unexpected error: {exc}",
                source_url=source_url,
            )
            raise SignatureVerificationError(
                f"Signature verification error for {source_url!r}: {exc}"
            ) from exc

    def _get_public_key(self) -> Ed25519PublicKey:
        if self._public_key_override is not None:
            return self._public_key_override
        return get_pinned_public_key()

    # ------------------------------------------------------------------
    # HTTP fetch
    # ------------------------------------------------------------------

    def _fetch(self, url: str) -> bytes:
        """Perform a synchronous GET and return the response body bytes."""
        with httpx.Client(timeout=self._http_timeout_s, follow_redirects=False) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.content

    def fetch_with_etag(self, url: str, current_etag: str = "") -> tuple[bytes | None, str]:
        """Conditional GET using ETag for the polling fallback.

        Returns:
            ``(None, current_etag)`` if the server returns 304 (unchanged).
            ``(body_bytes, new_etag)`` if the server returns 200 with a new body.

        Raises:
            httpx.HTTPError: On any HTTP error other than 304.
            UntrustedSourceError: If *url* is not allowlisted.
        """
        self._validate_source_url(url)

        headers: dict[str, str] = {}
        if current_etag:
            headers["If-None-Match"] = current_etag

        with httpx.Client(timeout=self._http_timeout_s, follow_redirects=False) as client:
            response = client.get(url, headers=headers)

        if response.status_code == 304:
            return None, current_etag

        response.raise_for_status()
        new_etag = response.headers.get("ETag", "")
        return response.content, new_etag

    # ------------------------------------------------------------------
    # Bundle parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _unpack_bundle(
        raw: bytes,
        source_url: str,
    ) -> tuple[dict[str, bytes], bytes, dict[str, Any]]:
        """Extract Rego files, data.json, and .manifest from a tar.gz bundle.

        Returns:
            ``(rego_files, data_json, manifest)`` where *rego_files* is a
            dict mapping relative path → file bytes.

        Raises:
            PolicyLoaderError: If the tar.gz cannot be read.
        """
        rego_files: dict[str, bytes] = {}
        data_json: bytes = b""
        manifest: dict[str, Any] = {}

        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
                for member in tf.getmembers():
                    if member.isdir():
                        continue
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    content = f.read()

                    # Strip leading "./" (tar convention) but preserve dotfiles like .manifest
                    name = member.name
                    if name.startswith("./"):
                        name = name[2:]
                    elif name.startswith("/"):
                        name = name.lstrip("/")
                    if name.endswith(".rego"):
                        rego_files[name] = content
                    elif name == "data.json":
                        data_json = content
                    elif name == ".manifest":
                        import json as _json
                        try:
                            manifest = _json.loads(content)
                        except Exception:
                            manifest = {}
        except tarfile.TarError as exc:
            raise PolicyLoaderError(
                f"Failed to unpack bundle from {source_url!r}: {exc}"
            ) from exc

        return rego_files, data_json, manifest

    # ------------------------------------------------------------------
    # Version extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_version_from_url(url: str) -> tuple[str, str]:
        """Extract a version string from the bundle URL path.

        Expected format: ``.../policies/{tenant}/{name}/{version}/bundle.tar.gz``

        Returns ``(version, "")`` — ETag is populated after the HTTP
        response headers are inspected (see ``fetch_with_etag``).
        """
        parts = url.rstrip("/").split("/")
        # Walk backwards past "bundle.tar.gz" to find the version segment
        for i in range(len(parts) - 1, -1, -1):
            if parts[i] not in ("bundle.tar.gz", "bundle.tar.gz.sig"):
                version = parts[i]
                return version, ""
        return "unknown", ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reject_untrusted(url: str, reason_detail: str) -> None:
    """Emit SECURITY_VIOLATION and raise UntrustedSourceError."""
    emit_security_violation_event(
        reason=SecurityViolationReason.UNTRUSTED_SOURCE,
        detail=reason_detail,
        source_url=url,
    )
    raise UntrustedSourceError(
        f"Policy bundle source rejected — {reason_detail}: {url!r}"
    )


# ---------------------------------------------------------------------------
# Environment variable override detection (E03-T04)
# ---------------------------------------------------------------------------

_BLOCKED_ENV_VARS: tuple[str, ...] = (
    "AGENTPEP_POLICY_URL",
    "AGENTPEP_POLICY_SOURCE",
    "AGENTPEP_POLICY_PATH",
    "AGENTPEP_POLICY_DIR",
    "OPA_BUNDLE_URL",
    "OPA_POLICY_URL",
)


def detect_env_var_override_attempt() -> list[str]:
    """Detect and report any attempt to override the policy source via env var.

    Returns a list of offending variable names.  Callers should emit a
    SECURITY_VIOLATION event for each detected variable.

    This is checked at application startup to catch misconfigured deployments
    before any bundle is loaded.
    """
    import os

    offending: list[str] = []
    for var in _BLOCKED_ENV_VARS:
        if os.environ.get(var, "").strip():
            offending.append(var)

    return offending


def check_and_report_env_var_overrides() -> None:
    """Emit SECURITY_VIOLATION events for any env var override attempts.

    Called at startup.  Does not raise — the application continues to
    start; the SECURITY_VIOLATION event is the alerting mechanism.
    """
    offending = detect_env_var_override_attempt()
    for var in offending:
        import os
        emit_security_violation_event(
            reason=SecurityViolationReason.ENV_VAR_OVERRIDE_ATTEMPT,
            detail=(
                f"Environment variable {var!r} attempts to override the "
                f"policy source. This variable is blocked; the AAPM registry "
                f"URL is a compile-time constant and cannot be redirected."
            ),
            source_url=os.environ.get(var, ""),
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

def _build_loader() -> TrustedPolicyLoader:
    from app.core.config import settings

    return TrustedPolicyLoader(
        http_timeout_s=getattr(settings, "policy_loader_http_timeout_s", 30.0),
    )


class _LazyLoader:
    """Lazy singleton; test code can call ``reconfigure()`` to reset."""

    _instance: TrustedPolicyLoader | None = None

    def __getattr__(self, name: str) -> Any:
        if self._instance is None:
            self._instance = _build_loader()
        return getattr(self._instance, name)

    def reconfigure(self) -> None:
        self._instance = None


policy_loader = _LazyLoader()
