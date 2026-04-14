"""Sprint 35 — APEP-281: PIIRedactionEngine tests.

Tests for the PII redaction engine covering:
  - Detection of each PII category
  - Category-specific redaction placeholders
  - Recursive dict redaction
  - Edge cases (empty text, no PII, nested dicts)
  - Non-PII preservation
"""

from __future__ import annotations

import pytest

from app.services.pii_redaction import (
    PIICategory,
    PIIMatch,
    PIIRedactionEngine,
    RedactionResult,
    pii_redaction_engine,
)


class TestPIIDetection:
    """APEP-281: PII detection for each category."""

    def test_detect_ssn(self) -> None:
        engine = PIIRedactionEngine()
        matches = engine.detect("My SSN is 123-45-6789.")
        assert any(m.category == PIICategory.SSN for m in matches)

    def test_detect_email(self) -> None:
        engine = PIIRedactionEngine()
        matches = engine.detect("Contact me at user@example.com please.")
        assert any(m.category == PIICategory.EMAIL for m in matches)

    def test_detect_phone(self) -> None:
        engine = PIIRedactionEngine()
        matches = engine.detect("Call me at 555-123-4567.")
        assert any(m.category == PIICategory.PHONE for m in matches)

    def test_detect_credit_card(self) -> None:
        engine = PIIRedactionEngine()
        matches = engine.detect("Card: 4111-1111-1111-1111")
        assert any(m.category == PIICategory.CREDIT_CARD for m in matches)

    def test_detect_credit_card_no_separator(self) -> None:
        engine = PIIRedactionEngine()
        matches = engine.detect("Card: 4111111111111111")
        assert any(m.category == PIICategory.CREDIT_CARD for m in matches)

    def test_detect_iban(self) -> None:
        engine = PIIRedactionEngine()
        matches = engine.detect("IBAN: GB29NWBK60161331926819")
        assert any(m.category == PIICategory.IBAN for m in matches)

    def test_detect_name(self) -> None:
        engine = PIIRedactionEngine()
        matches = engine.detect("The user is John Smith and they logged in.")
        assert any(m.category == PIICategory.NAME for m in matches)

    def test_detect_address(self) -> None:
        engine = PIIRedactionEngine()
        matches = engine.detect("Lives at 123 Main St in Springfield.")
        assert any(m.category == PIICategory.ADDRESS for m in matches)

    def test_no_pii_detected(self) -> None:
        engine = PIIRedactionEngine()
        matches = engine.detect("This is a benign string with no PII.")
        # NAME heuristic might match capitalised words, but "This" alone isn't two words
        name_matches = [m for m in matches if m.category == PIICategory.NAME]
        # Filter out low-confidence name matches
        high_confidence = [m for m in matches if m.confidence > 0.6]
        assert len(high_confidence) == 0

    def test_empty_text(self) -> None:
        engine = PIIRedactionEngine()
        matches = engine.detect("")
        assert matches == []

    def test_multiple_pii_types(self) -> None:
        engine = PIIRedactionEngine()
        text = "SSN: 123-45-6789, Email: user@test.com, Phone: 555-123-4567"
        matches = engine.detect(text)
        categories = {m.category for m in matches}
        assert PIICategory.SSN in categories
        assert PIICategory.EMAIL in categories


class TestPIIRedaction:
    """APEP-281: PII redaction with category-specific placeholders."""

    def test_redact_ssn(self) -> None:
        engine = PIIRedactionEngine()
        result = engine.redact("SSN: 123-45-6789")
        assert "[SSN_REDACTED]" in result.redacted_text
        assert "123-45-6789" not in result.redacted_text
        assert result.redaction_count >= 1

    def test_redact_email(self) -> None:
        engine = PIIRedactionEngine()
        result = engine.redact("Email: user@example.com")
        assert "[EMAIL_REDACTED]" in result.redacted_text
        assert "user@example.com" not in result.redacted_text

    def test_redact_preserves_non_pii(self) -> None:
        engine = PIIRedactionEngine()
        result = engine.redact("ID: abc123, SSN: 123-45-6789, Status: active")
        assert "abc123" in result.redacted_text
        assert "active" in result.redacted_text
        assert "123-45-6789" not in result.redacted_text

    def test_redact_no_pii(self) -> None:
        engine = PIIRedactionEngine()
        result = engine.redact("just a normal string")
        assert result.redacted_text == "just a normal string"
        assert result.redaction_count == 0

    def test_redact_result_categories(self) -> None:
        engine = PIIRedactionEngine()
        result = engine.redact("SSN: 123-45-6789, Email: user@test.com")
        assert PIICategory.SSN in result.categories_found
        assert PIICategory.EMAIL in result.categories_found

    def test_redact_original_preserved(self) -> None:
        engine = PIIRedactionEngine()
        original = "SSN: 123-45-6789"
        result = engine.redact(original)
        assert result.original_text == original


class TestDictRedaction:
    """APEP-281: Recursive dict redaction."""

    def test_simple_dict(self) -> None:
        engine = PIIRedactionEngine()
        data = {"name": "John Smith", "ssn": "123-45-6789", "age": 30}
        redacted, matches = engine.redact_dict(data)
        assert "123-45-6789" not in str(redacted)
        assert redacted["age"] == 30  # Non-string preserved

    def test_nested_dict(self) -> None:
        engine = PIIRedactionEngine()
        data = {
            "user": {
                "contact": {
                    "email": "user@example.com",
                    "phone": "555-123-4567",
                }
            }
        }
        redacted, matches = engine.redact_dict(data)
        assert "user@example.com" not in str(redacted)
        assert len(matches) >= 2

    def test_list_in_dict(self) -> None:
        engine = PIIRedactionEngine()
        data = {"emails": ["user1@test.com", "user2@test.com"]}
        redacted, matches = engine.redact_dict(data)
        assert "user1@test.com" not in str(redacted)
        assert "user2@test.com" not in str(redacted)

    def test_empty_dict(self) -> None:
        engine = PIIRedactionEngine()
        redacted, matches = engine.redact_dict({})
        assert redacted == {}
        assert matches == []

    def test_original_not_modified(self) -> None:
        engine = PIIRedactionEngine()
        data = {"ssn": "123-45-6789"}
        _redacted, _matches = engine.redact_dict(data)
        assert data["ssn"] == "123-45-6789"  # Original unchanged

    def test_no_pii_in_dict(self) -> None:
        engine = PIIRedactionEngine()
        data = {"key": "value", "count": 42}
        redacted, matches = engine.redact_dict(data)
        assert redacted["key"] == "value"
        # Only low-confidence NAME matches possible
        high_conf_matches = [m for m in matches if m.confidence > 0.6]
        assert len(high_conf_matches) == 0


class TestPIIMatch:
    """PIIMatch data class."""

    def test_fields(self) -> None:
        match = PIIMatch(
            category=PIICategory.SSN,
            original="123-45-6789",
            start=5,
            end=16,
            confidence=0.95,
        )
        assert match.category == PIICategory.SSN
        assert match.original == "123-45-6789"
        assert match.confidence == 0.95

    def test_immutable(self) -> None:
        match = PIIMatch(PIICategory.SSN, "123-45-6789", 0, 11, 0.95)
        with pytest.raises(AttributeError):
            match.category = PIICategory.EMAIL  # type: ignore[misc]


class TestSingleton:
    """Module-level singleton."""

    def test_singleton_exists(self) -> None:
        assert pii_redaction_engine is not None
        assert isinstance(pii_redaction_engine, PIIRedactionEngine)
