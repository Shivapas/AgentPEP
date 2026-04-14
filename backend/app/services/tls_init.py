"""ToolTrust tls init Equivalent — CA Certificate Bootstrap.

Sprint 47 — APEP-376: Generates and manages the root CA certificate used
for TLS interception.  This is the equivalent of ``tooltrust tls init``
that bootstraps the local CA for MITM proxying.

APEP-376.b: Core logic — CA generation, storage, fingerprint computation.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.models.forward_proxy import TLSInitConfig, TLSInitResult

try:
    from app.core.structured_logging import get_logger
    logger = get_logger(__name__)
except ImportError:
    logger = logging.getLogger(__name__)


class TLSInitService:
    """Generates and manages the root CA certificate for TLS interception.

    Equivalent to ``tooltrust tls init``:
      1. Generates an ECDSA P-256 (or RSA 2048) CA key pair.
      2. Creates a self-signed CA certificate.
      3. Writes CA cert and key to the configured output directory.
      4. Computes the CA certificate fingerprint for trust verification.

    The CA certificate must be added to the client's trust store for
    TLS interception to work without certificate errors.
    """

    def __init__(self) -> None:
        self._crypto_available = False
        try:
            from cryptography import x509  # noqa: F401
            self._crypto_available = True
        except ImportError:
            logger.warning(
                "cryptography library not installed; tls init unavailable"
            )

    def init_ca(self, config: TLSInitConfig | None = None) -> TLSInitResult:
        """Generate a new CA certificate and key, or return existing ones.

        Args:
            config: TLS initialization configuration.

        Returns:
            TLSInitResult with paths to generated files and fingerprint.
        """
        config = config or TLSInitConfig()

        if not self._crypto_available:
            return TLSInitResult(
                message="cryptography library not installed",
            )

        output_dir = Path(config.output_dir)
        ca_cert_path = output_dir / "agentpep-ca.crt"
        ca_key_path = output_dir / "agentpep-ca.key"

        # Check if CA already exists
        if (
            ca_cert_path.exists()
            and ca_key_path.exists()
            and not config.force_regenerate
        ):
            fingerprint = self._compute_fingerprint(ca_cert_path)
            return TLSInitResult(
                ca_cert_path=str(ca_cert_path),
                ca_key_path=str(ca_key_path),
                ca_fingerprint=fingerprint,
                created=False,
                message="CA certificate already exists",
            )

        # Generate new CA
        try:
            return self._generate_ca(config, output_dir, ca_cert_path, ca_key_path)
        except Exception:
            logger.exception("Failed to generate CA certificate")
            return TLSInitResult(message="CA generation failed")

    def _generate_ca(
        self,
        config: TLSInitConfig,
        output_dir: Path,
        ca_cert_path: Path,
        ca_key_path: Path,
    ) -> TLSInitResult:
        """Generate a new CA certificate and private key."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate key pair
        if config.key_algorithm == "RSA_2048":
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            signing_hash = hashes.SHA256()
        else:
            # Default: ECDSA P-256
            key = ec.generate_private_key(ec.SECP256R1())
            signing_hash = hashes.SHA256()

        # Build self-signed CA certificate
        now = datetime.now(UTC)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.organization),
            x509.NameAttribute(NameOID.COMMON_NAME, config.common_name),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=config.validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, signing_hash)
        )

        # Write cert
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        ca_cert_path.write_bytes(cert_pem)
        os.chmod(ca_cert_path, 0o644)

        # Write key (restrictive permissions)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        ca_key_path.write_bytes(key_pem)
        os.chmod(ca_key_path, 0o600)

        # Compute fingerprint
        fingerprint = self._compute_fingerprint_from_cert(cert)

        logger.info(
            "ca_certificate_generated",
            cert_path=str(ca_cert_path),
            key_path=str(ca_key_path),
            fingerprint=fingerprint,
            algorithm=config.key_algorithm,
            validity_days=config.validity_days,
        )

        return TLSInitResult(
            ca_cert_path=str(ca_cert_path),
            ca_key_path=str(ca_key_path),
            ca_fingerprint=fingerprint,
            created=True,
            message="CA certificate generated successfully",
        )

    def _compute_fingerprint(self, cert_path: Path) -> str:
        """Compute SHA-256 fingerprint of a PEM certificate file."""
        if not self._crypto_available:
            return ""
        try:
            from cryptography.x509 import load_pem_x509_certificate

            cert_data = cert_path.read_bytes()
            cert = load_pem_x509_certificate(cert_data)
            return self._compute_fingerprint_from_cert(cert)
        except Exception:
            return ""

    @staticmethod
    def _compute_fingerprint_from_cert(cert: object) -> str:
        """Compute SHA-256 fingerprint from a cryptography X509 certificate."""
        from cryptography.hazmat.primitives import hashes

        fingerprint_bytes = cert.fingerprint(hashes.SHA256())  # type: ignore[union-attr]
        return ":".join(f"{b:02X}" for b in fingerprint_bytes)

    def verify_ca(self, cert_path: str, key_path: str) -> bool:
        """Verify that a CA cert and key are a matching pair."""
        if not self._crypto_available:
            return False
        try:
            from cryptography.x509 import load_pem_x509_certificate
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            with open(cert_path, "rb") as f:
                cert = load_pem_x509_certificate(f.read())
            with open(key_path, "rb") as f:
                key = load_pem_private_key(f.read(), password=None)

            # Verify the public keys match
            cert_pub = cert.public_key().public_bytes(
                encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM,
                format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo,
            )
            key_pub = key.public_key().public_bytes(
                encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.PEM,
                format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo,
            )
            return cert_pub == key_pub
        except Exception:
            logger.exception("CA verification failed")
            return False


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

tls_init_service = TLSInitService()
