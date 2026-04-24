#!/usr/bin/env python3
"""Mock AAPM Policy Registry — local development and testing.

Sprint S-E03 (E03-T10)

Serves a pre-signed test bundle over HTTP so that AgentPEP's trusted
policy loader can be exercised without a real AAPM registry deployment.

Usage:
    python scripts/mock_aapm_registry.py [--port 8099] [--dump-public-key]

What it does:
  1. Generates a fresh Ed25519 keypair (or loads one from disk if it
     already exists at .dev_keys/).
  2. Builds a minimal valid Rego bundle (tar.gz).
  3. Signs the bundle digest with the private key.
  4. Starts an HTTP server at http://localhost:<port>/ that serves:
       GET /agentpep/policies/<tenant>/<name>/<version>/bundle.tar.gz
       GET /agentpep/policies/<tenant>/<name>/<version>/bundle.tar.gz.sig
       GET /agentpep/policies/<tenant>/<name>/latest/bundle.tar.gz
       GET /agentpep/policies/<tenant>/<name>/latest/bundle.tar.gz.sig
       POST /agentpep/policies/publish  (simulate bundle update)
       GET  /health

To use with AgentPEP in dev mode:
  1. Start this server: python scripts/mock_aapm_registry.py --port 8099
  2. Copy the printed public key PEM to a file, e.g. .dev_keys/pub.pem
  3. Set env vars:
       AGENTPEP_DEBUG=true
       AGENTPEP_POLICY_DEV_PUBLIC_KEY_PATH=.dev_keys/pub.pem
       AGENTPEP_POLICY_REGISTRY_BUNDLE_URL=http://localhost:8099/agentpep/policies/global/core_enforcement/latest/bundle.tar.gz
       AGENTPEP_POLICY_POLL_INTERVAL_S=10

The server also accepts POST /agentpep/policies/publish with a JSON body
to trigger a new bundle generation, allowing you to test the full
webhook+polling reload cycle locally.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import http.server
import io
import json
import os
import pathlib
import sys
import tarfile
import threading
import time
from typing import Any

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("ERROR: cryptography library is required. Run: pip install cryptography")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

KEY_DIR = pathlib.Path(".dev_keys")
PRIVATE_KEY_PATH = KEY_DIR / "mock_aapm_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "mock_aapm_public.pem"


def _generate_or_load_keypair() -> tuple[Ed25519PrivateKey, Any]:
    """Return (private_key, public_key), persisting to .dev_keys/."""
    KEY_DIR.mkdir(exist_ok=True)

    if PRIVATE_KEY_PATH.exists():
        pem = PRIVATE_KEY_PATH.read_bytes()
        private_key = serialization.load_pem_private_key(pem, password=None)
    else:
        private_key = Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        PRIVATE_KEY_PATH.write_bytes(pem)
        PRIVATE_KEY_PATH.chmod(0o600)
        print(f"[mock-registry] Generated new private key → {PRIVATE_KEY_PATH}")

    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PUBLIC_KEY_PATH.write_bytes(pub_pem)
    return private_key, public_key


# ---------------------------------------------------------------------------
# Bundle builder
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Bundle type: dev-stub (original development bundle)
# ---------------------------------------------------------------------------

REGO_POLICY_DEV_STUB = """\
package agentpep.core

import rego.v1

# Default deny (development stub — replace with real rules in production)
default allow := false

# Allow reads in dev mode
allow if {
    input.tool in {"read_file", "list_dir", "search_code"}
    input.deployment_tier == "HOMEGROWN"
}
"""

# ---------------------------------------------------------------------------
# Bundle type: v1-parity
#
# First AAPM-compiled bundle (Sprint S-E05).  Rego compiled from APDL source
# agentpep-core-v1.0.0.apdl.  Produces decisions identical to the Python
# RegoNativeEvaluator stub that it supersedes.
#
# Rules (must match RegoNativeEvaluator exactly for parity test to pass):
#   1. Default deny
#   2. Deny tainted inputs  → reason TAINTED_INPUT
#   3. Deny trust < 0.0     → reason INSUFFICIENT_TRUST  (effectively unreachable)
#   4. Allow read-only tools on HOMEGROWN with CLEAN taint and trust >= 0.0
# ---------------------------------------------------------------------------

REGO_POLICY_V1_PARITY = """\
package agentpep.core

import rego.v1

# ---------------------------------------------------------------------------
# AgentPEP Core Enforcement Policy — v1.0.0
# Source: AgentPEP rule inventory (docs/operations/rule_inventory.md §Class 9)
# Compiled by AAPM from APDL: agentpep-core-v1.0.0.apdl
# Do not edit directly; submit change requests through AAPM PCR workflow.
# ---------------------------------------------------------------------------

# Tools permitted under the v1 policy
# Mirrors RegoNativeEvaluator._READ_ONLY_TOOLS
_permitted_tools := {
    "read_file",
    "list_dir",
    "search_code",
    "get_file_contents",
    "list_files",
}

# Default deny — Evaluation Guarantee Invariant
default allow := false

# Gate 1: Tainted inputs are unconditionally denied.
# Mirrors: RegoNativeEvaluator taint check (taint_level != "CLEAN" → DENY)
allow := false if {
    input.taint_level != "CLEAN"
}

# Gate 2: Insufficient trust score.
# Mirrors: RegoNativeEvaluator trust check (trust_score < 0.0 → DENY)
# Note: 0.0 is the effective floor; this gate is preserved for defence-in-depth.
allow := false if {
    input.trust_score < 0.0
}

# Allow rule: read-only tools, HOMEGROWN tier, clean taint, sufficient trust.
# Mirrors: RegoNativeEvaluator allow path.
allow if {
    input.tool_name in _permitted_tools
    input.deployment_tier == "HOMEGROWN"
    input.taint_level == "CLEAN"
    input.trust_score >= 0.0
}
"""

# ---------------------------------------------------------------------------
# Bundle type: emergency-deny-all
#
# Emergency deny-all bundle published by AAPM when a critical security event
# requires immediate halt of all agent tool calls.  AgentPEP must enforce this
# within the 5-minute SLA defined in the AAPM–AgentPEP integration contract.
#
# All tool calls → DENY regardless of input.  No allow rules.
# ---------------------------------------------------------------------------

REGO_POLICY_EMERGENCY_DENY_ALL = """\
package agentpep.core

import rego.v1

# ---------------------------------------------------------------------------
# AgentPEP Emergency Deny-All Bundle
# Published by AAPM in response to a critical security event.
# All tool call evaluation returns DENY until a normal bundle is restored.
# ---------------------------------------------------------------------------

# Default deny — no allow rules present.
default allow := false
"""


# ---------------------------------------------------------------------------
# Bundle metadata templates
# ---------------------------------------------------------------------------

def _make_data_json(bundle_type: str, version: str) -> str:
    descriptions = {
        "dev-stub": "Mock AgentPEP development bundle — not for production",
        "v1-parity": "AgentPEP Core Enforcement Policy v1.0.0 — first AAPM-compiled bundle",
        "emergency-deny-all": "EMERGENCY DENY-ALL — all agent tool calls denied pending security review",
    }
    return json.dumps(
        {
            "version": version,
            "bundle_type": bundle_type,
            "description": descriptions.get(bundle_type, "AgentPEP policy bundle"),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "aapm_compiled": bundle_type != "dev-stub",
        },
        indent=2,
    )


def _make_manifest(bundle_type: str, version: str) -> str:
    revisions = {
        "dev-stub": "mock-dev",
        "v1-parity": f"aapm-v1-parity-{version}",
        "emergency-deny-all": f"aapm-emergency-deny-all-{version}",
    }
    return json.dumps(
        {
            "revision": revisions.get(bundle_type, version),
            "roots": ["agentpep"],
            "bundle_type": bundle_type,
        },
        indent=2,
    )


def _rego_for_bundle_type(bundle_type: str) -> str:
    """Return the Rego policy source for the given bundle type."""
    policies = {
        "dev-stub": REGO_POLICY_DEV_STUB,
        "v1-parity": REGO_POLICY_V1_PARITY,
        "emergency-deny-all": REGO_POLICY_EMERGENCY_DENY_ALL,
    }
    if bundle_type not in policies:
        raise ValueError(f"Unknown bundle type {bundle_type!r}. Valid types: {list(policies)}")
    return policies[bundle_type]


# Legacy alias kept for backwards compatibility
REGO_POLICY = REGO_POLICY_DEV_STUB

DATA_JSON = json.dumps(
    {
        "version": "dev",
        "description": "Mock AgentPEP development bundle — not for production",
        "generated_at": "",
    },
    indent=2,
)

MANIFEST = json.dumps(
    {
        "revision": "mock-dev",
        "roots": ["agentpep"],
    },
    indent=2,
)


def _build_bundle(version: str = "0.0.1-dev", bundle_type: str = "dev-stub") -> bytes:
    """Build a bundle.tar.gz in memory for the given bundle type."""
    rego_source = _rego_for_bundle_type(bundle_type)
    data = _make_data_json(bundle_type, version)
    manifest = _make_manifest(bundle_type, version)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in [
            ("policies/core.rego", rego_source.encode()),
            ("data.json", data.encode()),
            (".manifest", manifest.encode()),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _sign_bundle(private_key: Ed25519PrivateKey, bundle_bytes: bytes) -> bytes:
    """Sign the SHA-256 digest of the bundle and return the raw signature bytes."""
    digest = hashlib.sha256(bundle_bytes).digest()
    return private_key.sign(digest)


# ---------------------------------------------------------------------------
# Server state
# ---------------------------------------------------------------------------

_state: dict[str, Any] = {
    "version": "0.0.1-dev",
    "bundle_type": "dev-stub",
    "bundle_bytes": b"",
    "sig_bytes": b"",
    "private_key": None,
    "public_key": None,
    "etag": "",
}


def _rebuild_bundle() -> None:
    """Regenerate bundle + signature with the current state version and bundle type."""
    bundle = _build_bundle(_state["version"], _state["bundle_type"])
    sig = _sign_bundle(_state["private_key"], bundle)
    _state["bundle_bytes"] = bundle
    _state["sig_bytes"] = sig
    _state["etag"] = f'"{hashlib.sha256(bundle).hexdigest()[:16]}"'
    print(
        f"[mock-registry] Bundle rebuilt: version={_state['version']}  "
        f"type={_state['bundle_type']}  "
        f"size={len(bundle)}B  etag={_state['etag']}"
    )


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------


class MockRegistryHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D102
        print(f"[mock-registry] {self.address_string()} {fmt % args}")

    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_bytes(self, data: bytes, content_type: str, etag: str = "") -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if etag:
            self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]

        if path == "/health":
            self._send_json(200, {"status": "ok", "version": _state["version"]})
            return

        if path.endswith("/bundle.tar.gz"):
            # ETag-based conditional GET
            if_none_match = self.headers.get("If-None-Match", "")
            if if_none_match and if_none_match == _state["etag"]:
                self.send_response(304)
                self.end_headers()
                return
            self._send_bytes(
                _state["bundle_bytes"],
                "application/octet-stream",
                etag=_state["etag"],
            )
            return

        if path.endswith("/bundle.tar.gz.sig"):
            self._send_bytes(_state["sig_bytes"], "application/octet-stream")
            return

        self._send_json(404, {"error": f"Not found: {path}"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]

        if path == "/agentpep/policies/publish":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                payload = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._send_json(400, {"error": "invalid JSON"})
                return

            new_version = payload.get("version", _state["version"])
            new_bundle_type = payload.get("bundle_type", _state["bundle_type"])
            _state["version"] = new_version
            _state["bundle_type"] = new_bundle_type
            _rebuild_bundle()
            self._send_json(
                200,
                {
                    "status": "published",
                    "version": new_version,
                    "bundle_type": new_bundle_type,
                    "etag": _state["etag"],
                },
            )
            return

        self._send_json(404, {"error": f"No POST handler for {path}"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _dump_public_key(public_key: Any) -> None:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    print("\n--- AAPM Development Public Key PEM ---")
    print(pem)
    print(
        "Copy this into backend/app/policy/trusted_key.py as AAPM_POLICY_PUBLIC_KEY_PEM\n"
        "or point AGENTPEP_POLICY_DEV_PUBLIC_KEY_PATH to:\n"
        f"  {PUBLIC_KEY_PATH.absolute()}\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock AAPM Policy Registry")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument(
        "--bundle-type",
        choices=["dev-stub", "v1-parity", "emergency-deny-all"],
        default="dev-stub",
        help=(
            "Bundle type to serve at startup. "
            "'dev-stub': original development stub (default). "
            "'v1-parity': first AAPM-compiled bundle, decision-identical to the Python stub. "
            "'emergency-deny-all': deny-all bundle for emergency testing."
        ),
    )
    parser.add_argument(
        "--dump-public-key",
        action="store_true",
        help="Print the development public key PEM and exit",
    )
    args = parser.parse_args()

    private_key, public_key = _generate_or_load_keypair()
    _state["private_key"] = private_key
    _state["public_key"] = public_key
    _state["bundle_type"] = args.bundle_type
    _state["version"] = (
        "0.0.1-dev" if args.bundle_type == "dev-stub"
        else "1.0.0" if args.bundle_type == "v1-parity"
        else "emergency-1.0.0"
    )

    _rebuild_bundle()

    if args.dump_public_key:
        _dump_public_key(public_key)
        sys.exit(0)

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    print(f"\n[mock-registry] Starting on http://localhost:{args.port}/")
    print(f"[mock-registry] Bundle type: {args.bundle_type}")
    print(f"[mock-registry] Bundle URL (for polling config):")
    print(
        f"  http://localhost:{args.port}/agentpep/policies/global/core_enforcement/latest/bundle.tar.gz"
    )
    print(f"\n[mock-registry] Set these env vars to use this registry:")
    print(f"  AGENTPEP_DEBUG=true")
    print(f"  AGENTPEP_POLICY_DEV_PUBLIC_KEY_PATH={PUBLIC_KEY_PATH.absolute()}")
    print(
        f"  AGENTPEP_POLICY_REGISTRY_BUNDLE_URL=http://localhost:{args.port}/agentpep/policies/global/core_enforcement/latest/bundle.tar.gz"
    )
    print(f"  AGENTPEP_POLICY_POLL_INTERVAL_S=10\n")
    print(f"[mock-registry] To publish a new bundle version:")
    print(
        f'  curl -X POST http://localhost:{args.port}/agentpep/policies/publish'
        f' -H "Content-Type: application/json" -d \'{"version": "0.0.2-dev"}\'\n'
    )
    _dump_public_key(public_key)

    server = http.server.HTTPServer(("localhost", args.port), MockRegistryHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[mock-registry] Stopped.")


if __name__ == "__main__":
    main()
