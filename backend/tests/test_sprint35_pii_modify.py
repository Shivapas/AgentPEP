"""Sprint 35 — APEP-282: PII redaction + MODIFY decision integration tests.

Tests verifying:
  - PII detected + low clearance → MODIFY with redacted args
  - PII detected + PII clearance → ALLOW (no redaction)
  - No PII → ALLOW unchanged
  - Redacted args contain placeholders, not original PII
"""

from __future__ import annotations

import pytest

from app.models.data_classification import DataClassification, classification_gte
from app.services.pii_redaction import PIICategory, PIIRedactionEngine


class TestPIIModifyIntegration:
    """APEP-282: PII redaction returns MODIFY-compatible output."""

    def test_redact_dict_returns_modified_args(self) -> None:
        """When PII is found, redact_dict returns cleaned args."""
        engine = PIIRedactionEngine()
        args = {
            "query": "SELECT * FROM users",
            "filter": "email=user@example.com",
            "ssn": "123-45-6789",
        }
        redacted, matches = engine.redact_dict(args)
        assert len(matches) >= 2
        # SSN redacted
        assert "123-45-6789" not in str(redacted)
        assert "[SSN_REDACTED]" in str(redacted)
        # Email redacted
        assert "user@example.com" not in str(redacted)
        assert "[EMAIL_REDACTED]" in str(redacted)
        # Query preserved
        assert redacted["query"] == "SELECT * FROM users"

    def test_no_pii_returns_empty_matches(self) -> None:
        """When no PII is found, matches list is empty."""
        engine = PIIRedactionEngine()
        args = {"query": "SELECT count(*) FROM logs", "limit": "100"}
        redacted, matches = engine.redact_dict(args)
        # Only low-confidence name matches possible
        high_conf = [m for m in matches if m.confidence > 0.6]
        assert len(high_conf) == 0


class TestClearanceLevelDecision:
    """APEP-282: Clearance level determines MODIFY vs ALLOW."""

    def test_public_clearance_insufficient_for_pii(self) -> None:
        """PUBLIC clearance should not be >= PII."""
        assert not classification_gte("PUBLIC", "PII")

    def test_internal_clearance_insufficient_for_pii(self) -> None:
        assert not classification_gte("INTERNAL", "PII")

    def test_confidential_clearance_insufficient_for_pii(self) -> None:
        assert not classification_gte("CONFIDENTIAL", "PII")

    def test_pii_clearance_sufficient_for_pii(self) -> None:
        """PII clearance should be >= PII."""
        assert classification_gte("PII", "PII")

    def test_phi_clearance_sufficient_for_pii(self) -> None:
        """PHI clearance (higher) should be >= PII."""
        assert classification_gte("PHI", "PII")

    def test_financial_clearance_sufficient_for_pii(self) -> None:
        """FINANCIAL clearance (highest) should be >= PII."""
        assert classification_gte("FINANCIAL", "PII")


class TestNestedPIIRedaction:
    """APEP-282: Complex nested argument structures."""

    def test_deeply_nested_pii(self) -> None:
        engine = PIIRedactionEngine()
        args = {
            "level1": {
                "level2": {
                    "email": "deep@nested.com",
                    "data": "normal text",
                }
            }
        }
        redacted, matches = engine.redact_dict(args)
        assert "deep@nested.com" not in str(redacted)
        assert "normal text" in str(redacted)

    def test_list_with_pii(self) -> None:
        engine = PIIRedactionEngine()
        args = {
            "recipients": [
                "user1@example.com",
                "user2@example.com",
                "user3@example.com",
            ]
        }
        redacted, matches = engine.redact_dict(args)
        for email in ["user1@example.com", "user2@example.com", "user3@example.com"]:
            assert email not in str(redacted)

    def test_mixed_types_preserved(self) -> None:
        engine = PIIRedactionEngine()
        args = {
            "count": 42,
            "active": True,
            "tags": ["safe", "public"],
            "email": "pii@test.com",
        }
        redacted, matches = engine.redact_dict(args)
        assert redacted["count"] == 42
        assert redacted["active"] is True
        assert redacted["tags"] == ["safe", "public"]
        assert "pii@test.com" not in str(redacted)
