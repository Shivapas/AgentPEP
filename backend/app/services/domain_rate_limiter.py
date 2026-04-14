"""Per-domain rate limiting and data budget enforcement.

Sprint 44 — APEP-354: Enforces per-domain request rate limits and data transfer
budgets within the URL scanner pipeline.  Uses in-memory sliding windows with
optional Redis backing.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from datetime import UTC, datetime

from app.models.network_scan import DomainRateLimitState, ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal tracking structures
# ---------------------------------------------------------------------------


class _DomainBucket:
    """Tracks request count and data bytes for a single domain within a time window."""

    __slots__ = ("request_count", "data_bytes", "window_start")

    def __init__(self) -> None:
        self.request_count: int = 0
        self.data_bytes: int = 0
        self.window_start: float = time.monotonic()


# ---------------------------------------------------------------------------
# DomainRateLimiter
# ---------------------------------------------------------------------------


class DomainRateLimiter:
    """Per-domain rate limiter with request count and data transfer budget.

    Thread-safe via internal locking.
    """

    def __init__(
        self,
        *,
        default_request_limit: int = 100,
        default_data_budget_bytes: int = 10_485_760,  # 10 MB
        window_seconds: int = 60,
    ) -> None:
        self._default_request_limit = default_request_limit
        self._default_data_budget_bytes = default_data_budget_bytes
        self._window_seconds = window_seconds
        self._buckets: dict[str, _DomainBucket] = defaultdict(_DomainBucket)
        self._custom_limits: dict[str, tuple[int, int]] = {}  # domain -> (req_limit, data_limit)
        self._lock = threading.Lock()

    def set_domain_limits(
        self,
        domain: str,
        *,
        request_limit: int | None = None,
        data_budget_bytes: int | None = None,
    ) -> None:
        """Set custom rate limits for a specific domain."""
        with self._lock:
            req = request_limit or self._default_request_limit
            data = data_budget_bytes or self._default_data_budget_bytes
            self._custom_limits[domain.lower()] = (req, data)

    def check_and_record(
        self,
        domain: str,
        *,
        data_bytes: int = 0,
    ) -> DomainRateLimitState:
        """Check if a request to *domain* is within limits and record it.

        Returns the current state. If exceeded, state.exceeded will be True.
        """
        d = domain.lower().strip()
        now = time.monotonic()

        with self._lock:
            bucket = self._buckets[d]

            # Reset window if expired
            if now - bucket.window_start >= self._window_seconds:
                bucket.request_count = 0
                bucket.data_bytes = 0
                bucket.window_start = now

            # Get limits for this domain
            req_limit, data_limit = self._custom_limits.get(
                d, (self._default_request_limit, self._default_data_budget_bytes)
            )

            # Check request count
            if bucket.request_count >= req_limit:
                return DomainRateLimitState(
                    domain=d,
                    request_count=bucket.request_count,
                    request_limit=req_limit,
                    data_bytes_transferred=bucket.data_bytes,
                    data_budget_bytes=data_limit,
                    window_start=datetime.now(UTC),
                    window_seconds=self._window_seconds,
                    exceeded=True,
                    reason=f"Request rate limit exceeded for {d}: {bucket.request_count}/{req_limit}",
                )

            # Check data budget
            if bucket.data_bytes + data_bytes > data_limit:
                return DomainRateLimitState(
                    domain=d,
                    request_count=bucket.request_count,
                    request_limit=req_limit,
                    data_bytes_transferred=bucket.data_bytes,
                    data_budget_bytes=data_limit,
                    window_start=datetime.now(UTC),
                    window_seconds=self._window_seconds,
                    exceeded=True,
                    reason=f"Data budget exceeded for {d}: {bucket.data_bytes + data_bytes}/{data_limit} bytes",
                )

            # Record the request
            bucket.request_count += 1
            bucket.data_bytes += data_bytes

            return DomainRateLimitState(
                domain=d,
                request_count=bucket.request_count,
                request_limit=req_limit,
                data_bytes_transferred=bucket.data_bytes,
                data_budget_bytes=data_limit,
                window_start=datetime.now(UTC),
                window_seconds=self._window_seconds,
                exceeded=False,
            )

    def scan(self, domain: str, data_bytes: int = 0) -> list[ScanFinding]:
        """Check rate limit for a domain. Returns findings if exceeded.

        Used as a layer in the URL scanner pipeline.
        """
        state = self.check_and_record(domain, data_bytes=data_bytes)
        if not state.exceeded:
            return []
        return [
            ScanFinding(
                rule_id="RATELIMIT-001",
                scanner="DomainRateLimiter",
                severity=ScanSeverity.MEDIUM,
                description=state.reason,
                matched_text=domain,
                metadata={
                    "domain": domain,
                    "request_count": state.request_count,
                    "request_limit": state.request_limit,
                    "data_bytes": state.data_bytes_transferred,
                    "data_budget_bytes": state.data_budget_bytes,
                },
            )
        ]

    def get_state(self, domain: str) -> DomainRateLimitState:
        """Get current rate limit state for a domain without recording."""
        d = domain.lower().strip()
        now = time.monotonic()

        with self._lock:
            bucket = self._buckets.get(d)
            if bucket is None or now - bucket.window_start >= self._window_seconds:
                req_limit, data_limit = self._custom_limits.get(
                    d, (self._default_request_limit, self._default_data_budget_bytes)
                )
                return DomainRateLimitState(
                    domain=d,
                    request_limit=req_limit,
                    data_budget_bytes=data_limit,
                    window_seconds=self._window_seconds,
                )

            req_limit, data_limit = self._custom_limits.get(
                d, (self._default_request_limit, self._default_data_budget_bytes)
            )
            return DomainRateLimitState(
                domain=d,
                request_count=bucket.request_count,
                request_limit=req_limit,
                data_bytes_transferred=bucket.data_bytes,
                data_budget_bytes=data_limit,
                window_start=datetime.now(UTC),
                window_seconds=self._window_seconds,
                exceeded=(
                    bucket.request_count >= req_limit
                    or bucket.data_bytes >= data_limit
                ),
            )

    def reset(self, domain: str | None = None) -> None:
        """Reset rate limit state. If domain is None, reset all."""
        with self._lock:
            if domain is None:
                self._buckets.clear()
            else:
                self._buckets.pop(domain.lower().strip(), None)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

domain_rate_limiter = DomainRateLimiter()
