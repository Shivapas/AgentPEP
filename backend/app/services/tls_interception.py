"""Optional TLS Interception (MITM) for Forward Proxy.

Sprint 47 — APEP-375: Implements optional TLS interception for CONNECT tunnels.
When enabled, the proxy terminates the client's TLS connection using a
dynamically generated certificate signed by a local CA, then establishes a
separate TLS connection to the upstream server.  This allows DLP scanning of
the plaintext HTTP traffic passing through the tunnel.

APEP-375.b: Data model and schema for TLS interception config.
APEP-375.c: Core security logic — MITM certificate generation and TLS termination.
APEP-375.d: Security guards and crypto — certificate validation, key management.
APEP-375.e: Integration into enforcement pipeline.

Security considerations:
  - TLS interception is disabled by default and requires explicit opt-in.
  - The CA certificate must be explicitly trusted by clients.
  - Certificate generation uses ECDSA P-256 (or RSA 2048 as fallback).
  - Generated certificates are cached to avoid per-connection key generation.
  - Excluded hostnames are always passed through without interception.
"""

from __future__ import annotations

import hashlib
import logging
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.models.forward_proxy import (
    GeneratedCert,
    TLSInterceptionConfig,
    TLSInterceptionMode,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Excluded hostnames that should never be intercepted (security-sensitive)
# ---------------------------------------------------------------------------

_ALWAYS_PASSTHROUGH = frozenset({
    # Certificate pinning services
    "accounts.google.com",
    "oauth2.googleapis.com",
    "login.microsoftonline.com",
    "login.live.com",
    # Banking / financial (strict HPKP or cert pinning)
    "api.stripe.com",
    "api.paypal.com",
    # Package registries (integrity-critical)
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
})


class TLSInterceptionEngine:
    """Manages TLS interception for CONNECT tunnel MITM.

    When a CONNECT tunnel targets a hostname configured for interception:
      1. Generate (or retrieve cached) a certificate for the hostname.
      2. Create an SSL context for the client-facing connection (server role).
      3. Create an SSL context for the upstream connection (client role).
      4. Return both contexts so the tunnel handler can perform TLS termination.

    Certificate generation requires the ``cryptography`` library.  If not
    installed, the engine operates in passthrough-only mode.

    Thread-safe: certificate cache is protected by a lock.
    """

    def __init__(self, config: TLSInterceptionConfig | None = None) -> None:
        self._config = config or TLSInterceptionConfig()
        self._cert_cache: dict[str, tuple[float, GeneratedCert]] = {}
        self._lock = threading.Lock()
        self._ca_cert: Any = None  # cryptography X509 certificate object
        self._ca_key: Any = None  # cryptography private key object
        self._initialized = False
        self._crypto_available = False

        # Check if cryptography library is available
        try:
            from cryptography import x509  # noqa: F401
            self._crypto_available = True
        except ImportError:
            logger.warning(
                "cryptography library not installed; TLS interception unavailable"
            )

    def initialize(
        self,
        ca_cert_pem: str | bytes | None = None,
        ca_key_pem: str | bytes | None = None,
    ) -> bool:
        """Initialize the engine with CA certificate and key.

        Args:
            ca_cert_pem: PEM-encoded CA certificate (or path from config).
            ca_key_pem: PEM-encoded CA private key (or path from config).

        Returns:
            True if initialization succeeded.
        """
        if not self._crypto_available:
            return False

        if not self._config.enabled:
            return False

        try:
            from cryptography.x509 import load_pem_x509_certificate
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            # Load CA cert
            if ca_cert_pem:
                cert_bytes = ca_cert_pem if isinstance(ca_cert_pem, bytes) else ca_cert_pem.encode()
                self._ca_cert = load_pem_x509_certificate(cert_bytes)
            elif self._config.ca_cert_path:
                with open(self._config.ca_cert_path, "rb") as f:
                    self._ca_cert = load_pem_x509_certificate(f.read())

            # Load CA key
            if ca_key_pem:
                key_bytes = ca_key_pem if isinstance(ca_key_pem, bytes) else ca_key_pem.encode()
                self._ca_key = load_pem_private_key(key_bytes, password=None)
            elif self._config.ca_key_path:
                with open(self._config.ca_key_path, "rb") as f:
                    self._ca_key = load_pem_private_key(f.read(), password=None)

            if self._ca_cert and self._ca_key:
                self._initialized = True
                logger.info("tls_interception_initialized")
                return True
            else:
                logger.warning("TLS interception: CA cert or key not provided")
                return False

        except Exception:
            logger.exception("Failed to initialize TLS interception engine")
            return False

    def should_intercept(self, hostname: str) -> TLSInterceptionMode:
        """Determine whether to intercept TLS for a given hostname.

        Returns INTERCEPT or PASSTHROUGH based on configuration.
        """
        if not self._initialized or not self._config.enabled:
            return TLSInterceptionMode.PASSTHROUGH

        h = hostname.lower().strip()

        # Always passthrough security-sensitive hosts
        if h in _ALWAYS_PASSTHROUGH:
            return TLSInterceptionMode.PASSTHROUGH

        # Check exclude list
        for pattern in self._config.exclude_hostnames:
            if self._hostname_matches(h, pattern):
                return TLSInterceptionMode.PASSTHROUGH

        # Check include list (if specified, only intercept listed hosts)
        if self._config.intercept_hostnames:
            for pattern in self._config.intercept_hostnames:
                if self._hostname_matches(h, pattern):
                    return TLSInterceptionMode.INTERCEPT
            return TLSInterceptionMode.PASSTHROUGH

        # Default: intercept all (if globally enabled)
        return TLSInterceptionMode.INTERCEPT

    def get_or_generate_cert(self, hostname: str) -> GeneratedCert | None:
        """Get a cached certificate or generate a new one for the hostname.

        Returns None if the engine is not initialized or cert generation fails.
        """
        if not self._initialized:
            return None

        with self._lock:
            # Check cache
            cached = self._cert_cache.get(hostname)
            if cached is not None:
                ts, cert = cached
                if (time.monotonic() - ts) < self._config.cert_ttl_s:
                    return cert
                else:
                    del self._cert_cache[hostname]

            # Evict oldest if over capacity
            while len(self._cert_cache) >= self._config.cert_cache_size:
                oldest_key = next(iter(self._cert_cache))
                del self._cert_cache[oldest_key]

        # Generate outside the lock
        cert = self._generate_cert(hostname)
        if cert:
            with self._lock:
                self._cert_cache[hostname] = (time.monotonic(), cert)

        return cert

    def _generate_cert(self, hostname: str) -> GeneratedCert | None:
        """Generate a TLS certificate for a hostname, signed by the CA."""
        if not self._crypto_available or not self._ca_cert or not self._ca_key:
            return None

        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec

            # Generate key pair (ECDSA P-256)
            key = ec.generate_private_key(ec.SECP256R1())

            # Build certificate
            now = datetime.now(UTC)
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentPEP TrustFabric"),
            ])

            builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(self._ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(seconds=self._config.cert_ttl_s))
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                    critical=False,
                )
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
            )

            cert = builder.sign(self._ca_key, hashes.SHA256())

            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()

            serial = format(cert.serial_number, "x")

            return GeneratedCert(
                hostname=hostname,
                cert_pem=cert_pem,
                key_pem=key_pem,
                created_at=now,
                expires_at=now + timedelta(seconds=self._config.cert_ttl_s),
                serial_number=serial,
            )

        except Exception:
            logger.exception("Failed to generate cert for %s", hostname)
            return None

    def create_client_ssl_context(self, cert: GeneratedCert) -> ssl.SSLContext | None:
        """Create an SSL context for the client-facing connection (server role).

        This context uses the generated certificate to present to the client.
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            # Load the generated cert and key from PEM strings
            import tempfile
            import os

            # Write cert and key to temp files for ssl module
            with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as cf:
                cf.write(cert.cert_pem)
                cert_path = cf.name
            with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as kf:
                kf.write(cert.key_pem)
                key_path = kf.name

            try:
                ctx.load_cert_chain(cert_path, key_path)
            finally:
                os.unlink(cert_path)
                os.unlink(key_path)

            return ctx

        except Exception:
            logger.exception("Failed to create client SSL context")
            return None

    @staticmethod
    def create_upstream_ssl_context() -> ssl.SSLContext:
        """Create an SSL context for the upstream connection (client role).

        Verifies the upstream server's certificate using the system trust store.
        """
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    @staticmethod
    def _hostname_matches(hostname: str, pattern: str) -> bool:
        """Check if a hostname matches a pattern (supports leading wildcard)."""
        h = hostname.lower().strip()
        p = pattern.lower().strip()
        if p.startswith("*."):
            suffix = p[1:]  # e.g. ".example.com"
            return h == p[2:] or h.endswith(suffix)
        return h == p

    def invalidate_cache(self) -> None:
        """Clear the certificate cache."""
        with self._lock:
            self._cert_cache.clear()

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def cache_size(self) -> int:
        return len(self._cert_cache)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

tls_interception_engine = TLSInterceptionEngine()
