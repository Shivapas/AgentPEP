"""Rule Bundle Loader — Sprint 51 (APEP-404/405).

Loads, verifies, and manages Ed25519-signed community rule bundles in
YAML format.  Bundles package DLP patterns, injection signatures, URL
blocklist entries, and chain detection patterns with cryptographic
integrity verification.

Ed25519 signing reuses the PyNaCl infrastructure from Sprint 32
(receipt signing).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import yaml  # type: ignore[import-untyped]

from app.models.rule_bundle import (
    BundleRule,
    BundleRuleType,
    BundleStatus,
    RuleBundle,
    RuleBundleListResponse,
    RuleBundleLoadRequest,
    RuleBundleLoadResponse,
    RuleBundleManifest,
)

logger = logging.getLogger(__name__)

# Check for optional Ed25519 support (PyNaCl)
_HAS_NACL = False
try:
    import nacl.encoding  # type: ignore[import-untyped]
    import nacl.signing  # type: ignore[import-untyped]

    _HAS_NACL = True
except ImportError:
    pass


def _canonical_bundle_bytes(manifest: dict[str, Any], rules: list[dict[str, Any]]) -> bytes:
    """Produce a canonical JSON representation for signature verification.

    The canonical form deterministically serializes manifest + rules
    (sorted keys, no whitespace) to ensure the same content always
    produces the same bytes.
    """
    canonical = {
        "manifest": {k: v for k, v in sorted(manifest.items()) if k != "created_at"},
        "rules": sorted(
            [{k: v for k, v in sorted(r.items())} for r in rules],
            key=lambda r: r.get("rule_id", ""),
        ),
    }
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str).encode()


class RuleBundleLoader:
    """Loads, verifies, and manages Ed25519-signed rule bundles.

    Bundles are YAML files containing a manifest header and a list of
    detection rules.  Each bundle is signed with Ed25519 for integrity
    verification.  Trusted public keys are registered via
    ``register_trusted_key``.

    Example YAML bundle::

        manifest:
          name: community-dlp-v1
          version: 1.0.0
          author: AgentPEP Community
          description: Community DLP patterns
        signature: <base64-encoded Ed25519 signature>
        signing_key_id: community-key-1
        rules:
          - rule_id: DLP-COMMUNITY-001
            rule_type: DLP
            pattern: "(?i)sk-[a-z0-9]{48}"
            severity: HIGH
            description: OpenAI API Key
    """

    def __init__(self) -> None:
        self._bundles: dict[UUID, RuleBundle] = {}
        self._trusted_keys: dict[str, bytes] = {}  # key_id -> Ed25519 verify key bytes

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def register_trusted_key(self, key_id: str, public_key_bytes: bytes) -> None:
        """Register an Ed25519 public key for bundle signature verification."""
        self._trusted_keys[key_id] = public_key_bytes
        logger.info("bundle_key_registered", extra={"key_id": key_id})

    def list_trusted_keys(self) -> list[str]:
        """Return list of registered trusted key IDs."""
        return list(self._trusted_keys.keys())

    # ------------------------------------------------------------------
    # Bundle loading
    # ------------------------------------------------------------------

    def load_from_yaml(
        self,
        yaml_content: str,
        *,
        verify_signature: bool = True,
        activate: bool = False,
        source_path: str = "",
    ) -> RuleBundleLoadResponse:
        """Parse and optionally verify a rule bundle from YAML content.

        Args:
            yaml_content: Raw YAML string of the bundle.
            verify_signature: Whether to check the Ed25519 signature.
            activate: Whether to set status to ACTIVE immediately.
            source_path: File path for audit trail.

        Returns:
            RuleBundleLoadResponse with the loaded bundle and stats.
        """
        warnings: list[str] = []
        rules_skipped = 0

        try:
            raw = yaml.safe_load(yaml_content)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML: {exc}") from exc

        if not isinstance(raw, dict):
            raise ValueError("Bundle YAML must be a mapping at top level")

        # Parse manifest
        manifest_raw = raw.get("manifest", {})
        if not manifest_raw or not isinstance(manifest_raw, dict):
            raise ValueError("Bundle must contain a 'manifest' section")
        if "name" not in manifest_raw:
            raise ValueError("Bundle manifest must contain a 'name' field")

        manifest = RuleBundleManifest(**manifest_raw)

        # Parse rules
        rules_raw = raw.get("rules", [])
        if not isinstance(rules_raw, list):
            raise ValueError("Bundle 'rules' must be a list")

        rules: list[BundleRule] = []
        for i, rule_raw in enumerate(rules_raw):
            if not isinstance(rule_raw, dict):
                warnings.append(f"Rule at index {i} is not a mapping, skipped")
                rules_skipped += 1
                continue
            if "rule_id" not in rule_raw:
                warnings.append(f"Rule at index {i} missing 'rule_id', skipped")
                rules_skipped += 1
                continue
            if "rule_type" not in rule_raw:
                warnings.append(f"Rule at index {i} missing 'rule_type', skipped")
                rules_skipped += 1
                continue
            try:
                rule = BundleRule(**rule_raw)
                rules.append(rule)
            except Exception as exc:
                warnings.append(f"Rule at index {i} invalid: {exc}")
                rules_skipped += 1

        # Verify signature
        signature = raw.get("signature", "")
        signing_key_id = raw.get("signing_key_id", "")
        verified = False

        if verify_signature and signature and signing_key_id:
            verified = self._verify_signature(
                manifest_raw=manifest_raw,
                rules_raw=rules_raw,
                signature_b64=signature,
                key_id=signing_key_id,
            )
            if not verified:
                warnings.append("Ed25519 signature verification FAILED")
        elif verify_signature and not signature:
            warnings.append("No signature present in bundle; verification skipped")

        # Determine status
        if verified and activate:
            status = BundleStatus.ACTIVE
        elif verified:
            status = BundleStatus.PENDING_REVIEW
        elif not verify_signature and activate:
            status = BundleStatus.ACTIVE
            warnings.append("Bundle activated without signature verification")
        else:
            status = BundleStatus.INVALID if (verify_signature and signature) else BundleStatus.PENDING_REVIEW

        bundle = RuleBundle(
            manifest=manifest,
            rules=rules,
            status=status,
            signature=signature,
            signing_key_id=signing_key_id,
            verified=verified,
            loaded_at=datetime.now(UTC),
            file_path=source_path,
        )

        self._bundles[bundle.bundle_id] = bundle

        logger.info(
            "bundle_loaded",
            extra={
                "bundle_id": str(bundle.bundle_id),
                "bundle_name": manifest.name,
                "rules_loaded": len(rules),
                "rules_skipped": rules_skipped,
                "verified": verified,
                "status": status,
            },
        )

        return RuleBundleLoadResponse(
            bundle=bundle,
            rules_loaded=len(rules),
            rules_skipped=rules_skipped,
            warnings=warnings,
        )

    def load_from_file(
        self,
        file_path: str,
        *,
        verify_signature: bool = True,
        activate: bool = False,
    ) -> RuleBundleLoadResponse:
        """Load a rule bundle from a YAML file on disk."""
        with open(file_path) as f:
            content = f.read()
        return self.load_from_yaml(
            content,
            verify_signature=verify_signature,
            activate=activate,
            source_path=file_path,
        )

    # ------------------------------------------------------------------
    # Bundle management
    # ------------------------------------------------------------------

    def get_bundle(self, bundle_id: UUID) -> RuleBundle | None:
        """Retrieve a loaded bundle by ID."""
        return self._bundles.get(bundle_id)

    def list_bundles(self, status: BundleStatus | None = None) -> RuleBundleListResponse:
        """List all loaded bundles, optionally filtered by status."""
        bundles = list(self._bundles.values())
        if status is not None:
            bundles = [b for b in bundles if b.status == status]
        return RuleBundleListResponse(bundles=bundles, total=len(bundles))

    def activate_bundle(self, bundle_id: UUID) -> RuleBundle | None:
        """Activate a bundle (make its rules effective)."""
        bundle = self._bundles.get(bundle_id)
        if bundle is None:
            return None
        bundle.status = BundleStatus.ACTIVE
        logger.info("bundle_activated", extra={"bundle_id": str(bundle_id)})
        return bundle

    def deactivate_bundle(self, bundle_id: UUID) -> RuleBundle | None:
        """Deactivate a bundle (suspend its rules)."""
        bundle = self._bundles.get(bundle_id)
        if bundle is None:
            return None
        bundle.status = BundleStatus.INACTIVE
        logger.info("bundle_deactivated", extra={"bundle_id": str(bundle_id)})
        return bundle

    def remove_bundle(self, bundle_id: UUID) -> bool:
        """Remove a bundle entirely."""
        removed = self._bundles.pop(bundle_id, None)
        if removed:
            logger.info("bundle_removed", extra={"bundle_id": str(bundle_id)})
        return removed is not None

    def get_active_rules(self, rule_type: BundleRuleType | None = None) -> list[BundleRule]:
        """Return all rules from active bundles, optionally filtered by type."""
        rules: list[BundleRule] = []
        for bundle in self._bundles.values():
            if bundle.status != BundleStatus.ACTIVE:
                continue
            for rule in bundle.rules:
                if not rule.enabled:
                    continue
                if rule_type is not None and rule.rule_type != rule_type:
                    continue
                rules.append(rule)
        return rules

    def stats(self) -> dict[str, Any]:
        """Return summary statistics about loaded bundles."""
        total = len(self._bundles)
        active = sum(1 for b in self._bundles.values() if b.status == BundleStatus.ACTIVE)
        total_rules = sum(len(b.rules) for b in self._bundles.values())
        active_rules = len(self.get_active_rules())
        return {
            "total_bundles": total,
            "active_bundles": active,
            "total_rules": total_rules,
            "active_rules": active_rules,
            "trusted_keys": len(self._trusted_keys),
        }

    # ------------------------------------------------------------------
    # Signature verification
    # ------------------------------------------------------------------

    def _verify_signature(
        self,
        manifest_raw: dict[str, Any],
        rules_raw: list[dict[str, Any]],
        signature_b64: str,
        key_id: str,
    ) -> bool:
        """Verify the Ed25519 signature of a bundle."""
        if not _HAS_NACL:
            logger.warning("nacl_not_available", extra={"detail": "PyNaCl not installed; cannot verify Ed25519 signatures"})
            return False

        public_key_bytes = self._trusted_keys.get(key_id)
        if public_key_bytes is None:
            logger.warning("bundle_unknown_key", extra={"key_id": key_id})
            return False

        try:
            verify_key = nacl.signing.VerifyKey(public_key_bytes)
            canonical = _canonical_bundle_bytes(manifest_raw, rules_raw)
            sig_bytes = base64.b64decode(signature_b64)
            verify_key.verify(canonical, sig_bytes)
            return True
        except Exception:
            logger.warning("bundle_signature_invalid", extra={"key_id": key_id}, exc_info=True)
            return False

    # ------------------------------------------------------------------
    # Signing (for bundle authors)
    # ------------------------------------------------------------------

    @staticmethod
    def sign_bundle(
        manifest_raw: dict[str, Any],
        rules_raw: list[dict[str, Any]],
        signing_key_bytes: bytes,
    ) -> str:
        """Sign a bundle's canonical content with an Ed25519 private key.

        Returns the base64-encoded signature.
        """
        if not _HAS_NACL:
            raise RuntimeError("PyNaCl is required for Ed25519 bundle signing")
        signing_key = nacl.signing.SigningKey(signing_key_bytes)
        canonical = _canonical_bundle_bytes(manifest_raw, rules_raw)
        signed = signing_key.sign(canonical)
        return base64.b64encode(signed.signature).decode()


# Module-level singleton
rule_bundle_loader = RuleBundleLoader()
