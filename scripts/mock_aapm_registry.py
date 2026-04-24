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

REGO_POLICY = """\
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


def _build_bundle(version: str = "0.0.1-dev") -> bytes:
    """Build a minimal valid bundle.tar.gz in memory."""
    data = DATA_JSON.replace('"generated_at": ""', f'"generated_at": "{time.strftime("%Y-%m-%dT%H:%M:%SZ")}"')
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in [
            ("policies/core.rego", REGO_POLICY.encode()),
            ("data.json", data.encode()),
            (".manifest", MANIFEST.encode()),
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
    "bundle_bytes": b"",
    "sig_bytes": b"",
    "private_key": None,
    "public_key": None,
    "etag": "",
}


def _rebuild_bundle() -> None:
    """Regenerate bundle + signature with the current state version."""
    bundle = _build_bundle(_state["version"])
    sig = _sign_bundle(_state["private_key"], bundle)
    _state["bundle_bytes"] = bundle
    _state["sig_bytes"] = sig
    _state["etag"] = f'"{hashlib.sha256(bundle).hexdigest()[:16]}"'
    print(
        f"[mock-registry] Bundle rebuilt: version={_state['version']}  "
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
            _state["version"] = new_version
            _rebuild_bundle()
            self._send_json(
                200,
                {
                    "status": "published",
                    "version": new_version,
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
        "--dump-public-key",
        action="store_true",
        help="Print the development public key PEM and exit",
    )
    args = parser.parse_args()

    private_key, public_key = _generate_or_load_keypair()
    _state["private_key"] = private_key
    _state["public_key"] = public_key

    _rebuild_bundle()

    if args.dump_public_key:
        _dump_public_key(public_key)
        sys.exit(0)

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    print(f"\n[mock-registry] Starting on http://localhost:{args.port}/")
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
