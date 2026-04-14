"""SSRF Guard — Server-Side Request Forgery prevention.

Sprint 44 — APEP-353: Validates URLs against SSRF attack vectors by resolving
hostnames and checking resolved IPs against RFC 1918 private ranges, loopback,
link-local, and other reserved address spaces.  Also detects DNS rebinding by
requiring resolution before allowing requests.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

from app.models.network_scan import ScanFinding, ScanSeverity, SSRFCheckResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dangerous URL schemes
# ---------------------------------------------------------------------------

_ALLOWED_SCHEMES = {"http", "https"}

_DANGEROUS_SCHEMES = {
    "file",
    "ftp",
    "gopher",
    "dict",
    "ldap",
    "tftp",
    "jar",
    "data",
    "javascript",
}

# ---------------------------------------------------------------------------
# Private / reserved IP ranges
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

_LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

_LINK_LOCAL_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

_RESERVED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),    # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    ipaddress.ip_network("ff00::/8"),          # IPv6 multicast
]

# Cloud metadata endpoints (SSRF targets)
_CLOUD_METADATA_HOSTS = {
    "169.254.169.254",          # AWS/GCP/Azure metadata
    "metadata.google.internal", # GCP metadata
    "metadata.internal",        # Generic cloud metadata
}


# ---------------------------------------------------------------------------
# SSRFGuard
# ---------------------------------------------------------------------------


class SSRFGuard:
    """Validates URLs against SSRF attack vectors.

    Checks:
    1. URL scheme validation (only http/https allowed)
    2. Hostname resolution to IP addresses
    3. IP address range checks (private, loopback, link-local, reserved)
    4. Cloud metadata endpoint blocking
    5. DNS rebinding prevention (resolve before allowing)

    Thread-safe: no mutable state.
    """

    def __init__(
        self,
        *,
        allow_private: bool = False,
        allow_loopback: bool = False,
        allowed_hosts: set[str] | None = None,
    ) -> None:
        self._allow_private = allow_private
        self._allow_loopback = allow_loopback
        self._allowed_hosts: set[str] = allowed_hosts or set()

    def check_url(self, url: str) -> SSRFCheckResult:
        """Validate a URL against SSRF attack vectors.

        Returns an SSRFCheckResult with blocked=True if the URL is dangerous.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme.lower()

        # 1. Scheme validation
        if scheme not in _ALLOWED_SCHEMES:
            reason = f"Blocked scheme: {scheme}"
            if scheme in _DANGEROUS_SCHEMES:
                reason = f"Dangerous scheme blocked: {scheme}"
            return SSRFCheckResult(
                url=url, hostname=hostname, blocked=True, reason=reason,
            )

        if not hostname:
            return SSRFCheckResult(
                url=url, hostname="", blocked=True, reason="Empty hostname",
            )

        # 2. Check allowlisted hosts (bypass further checks)
        if hostname in self._allowed_hosts:
            return SSRFCheckResult(url=url, hostname=hostname, blocked=False)

        # 3. Cloud metadata endpoint check
        if hostname in _CLOUD_METADATA_HOSTS:
            return SSRFCheckResult(
                url=url,
                hostname=hostname,
                blocked=True,
                reason=f"Cloud metadata endpoint blocked: {hostname}",
            )

        # 4. Resolve hostname to IPs
        resolved_ips: list[str] = []
        try:
            addr_infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved_ips = list({info[4][0] for info in addr_infos})
        except socket.gaierror:
            # If DNS resolution fails, block conservatively
            return SSRFCheckResult(
                url=url,
                hostname=hostname,
                blocked=True,
                reason=f"DNS resolution failed for {hostname}",
            )

        if not resolved_ips:
            return SSRFCheckResult(
                url=url,
                hostname=hostname,
                blocked=True,
                reason="No IP addresses resolved",
            )

        # 5. Check each resolved IP
        is_private = False
        is_loopback = False
        is_link_local = False

        for ip_str in resolved_ips:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            # Loopback
            if any(ip in net for net in _LOOPBACK_NETWORKS):
                is_loopback = True
                if not self._allow_loopback:
                    return SSRFCheckResult(
                        url=url,
                        hostname=hostname,
                        resolved_ips=resolved_ips,
                        is_loopback=True,
                        blocked=True,
                        reason=f"Loopback address blocked: {ip_str}",
                    )

            # Link-local
            if any(ip in net for net in _LINK_LOCAL_NETWORKS):
                is_link_local = True
                return SSRFCheckResult(
                    url=url,
                    hostname=hostname,
                    resolved_ips=resolved_ips,
                    is_link_local=True,
                    blocked=True,
                    reason=f"Link-local address blocked: {ip_str}",
                )

            # Private networks
            if any(ip in net for net in _PRIVATE_NETWORKS):
                is_private = True
                if not self._allow_private:
                    return SSRFCheckResult(
                        url=url,
                        hostname=hostname,
                        resolved_ips=resolved_ips,
                        is_private=True,
                        blocked=True,
                        reason=f"Private network address blocked: {ip_str}",
                    )

            # Other reserved ranges
            if any(ip in net for net in _RESERVED_NETWORKS):
                return SSRFCheckResult(
                    url=url,
                    hostname=hostname,
                    resolved_ips=resolved_ips,
                    blocked=True,
                    reason=f"Reserved address blocked: {ip_str}",
                )

        return SSRFCheckResult(
            url=url,
            hostname=hostname,
            resolved_ips=resolved_ips,
            is_private=is_private,
            is_loopback=is_loopback,
            is_link_local=is_link_local,
            blocked=False,
        )

    def scan(self, url: str) -> list[ScanFinding]:
        """Scan a URL for SSRF risks. Returns findings list.

        Used as a layer in the URL scanner pipeline.
        """
        result = self.check_url(url)
        if not result.blocked:
            return []
        return [
            ScanFinding(
                rule_id="SSRF-001",
                scanner="SSRFGuard",
                severity=ScanSeverity.CRITICAL,
                description=result.reason,
                matched_text=url[:200],
                mitre_technique_id="T1190",
                metadata={
                    "hostname": result.hostname,
                    "resolved_ips": result.resolved_ips,
                    "is_private": result.is_private,
                    "is_loopback": result.is_loopback,
                    "is_link_local": result.is_link_local,
                },
            )
        ]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

ssrf_guard = SSRFGuard()
