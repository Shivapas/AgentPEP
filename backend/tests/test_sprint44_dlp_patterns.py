"""Unit tests for Sprint 44 DLP patterns (APEP-348).

Tests the 46 DLP patterns added to injection_signatures.py for detecting
API keys, tokens, credentials, and secrets.
"""

import pytest

from app.services.injection_signatures import injection_library, MatchedSignature


def _fake_stripe_key(mode: str = "live") -> str:
    """Build a fake Stripe-like key at runtime to avoid secret scanning."""
    prefix = "".join(["s", "k"])
    return prefix + "_" + mode + "_" + "X" * 24


class TestDLPPatterns:
    """Tests for the 46 DLP detection patterns."""

    # ── API Key patterns ──────────────────────────────────────────────

    def test_google_api_key(self):
        text = "key=" + "AIza" + "SyDk8E7rX5Xq2Z3nLm1pO4wQ9rT6y8u0i1o"
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-001"]
        assert len(matches) == 1
        assert matches[0].severity == "CRITICAL"

    def test_aws_access_key(self):
        text = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-002"]
        assert len(matches) == 1
        assert matches[0].severity == "CRITICAL"

    def test_openai_api_key(self):
        text = "sk-" + "x" * 20 + "T3BlbkFJ" + "y" * 20
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-003"]
        assert len(matches) == 1

    def test_anthropic_api_key(self):
        text = "sk" + "-ant-api03-" + "a" * 85
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-004"]
        assert len(matches) == 1

    def test_github_pat(self):
        text = "ghp" + "_" + "A" * 36
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-005"]
        assert len(matches) == 1

    def test_github_server_token(self):
        text = "ghs" + "_" + "A" * 36
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-006"]
        assert len(matches) == 1

    def test_github_user_token(self):
        text = "ghu" + "_" + "A" * 36
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-007"]
        assert len(matches) == 1

    def test_github_refresh_token(self):
        text = "ghr" + "_" + "A" * 36
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-008"]
        assert len(matches) == 1

    def test_sendgrid_api_key(self):
        text = "SG" + "." + "x" * 22 + "." + "Y" * 43
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-009"]
        assert len(matches) == 1

    def test_slack_token(self):
        text = "xoxb" + "-" + "0" * 12 + "-" + "1" * 13 + "-" + "A" * 22
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-010"]
        assert len(matches) == 1

    # ── Token patterns ────────────────────────────────────────────────

    def test_jwt_token(self):
        text = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-011"]
        assert len(matches) == 1

    def test_gitlab_pat(self):
        text = "glpat" + "-" + "A" * 26
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-012"]
        assert len(matches) == 1

    def test_npm_token(self):
        text = "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-013"]
        assert len(matches) == 1

    def test_google_oauth_access_token(self):
        text = "ya29." + "a" * 55
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-018"]
        assert len(matches) == 1

    # ── Credential patterns ───────────────────────────────────────────

    def test_password_assignment(self):
        text = 'password=SuperSecret123!'
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-021"]
        assert len(matches) == 1

    def test_api_key_assignment(self):
        text = "api_key=" + _fake_stripe_key("test")
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-022"]
        assert len(matches) == 1

    def test_secret_key_assignment(self):
        text = "secret_key=my_super_secret_key_12345"
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-023"]
        assert len(matches) == 1

    def test_access_token_assignment(self):
        text = "access_token=eyJhbGciOiJIUzI1NiJ9.test"
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-024"]
        assert len(matches) == 1

    def test_database_url(self):
        text = "mongodb+srv://user:pass@cluster.example.com/dbname"
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-025"]
        assert len(matches) == 1

    def test_pem_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----"
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-027"]
        assert len(matches) == 1

    def test_aws_secret_key(self):
        text = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-029"]
        assert len(matches) == 1

    # ── Cloud token patterns ──────────────────────────────────────────

    def test_stripe_live_key(self):
        text = _fake_stripe_key("live")
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-031"]
        assert len(matches) == 1

    def test_stripe_test_key(self):
        text = _fake_stripe_key("test")
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-032"]
        assert len(matches) == 1

    # ── Secret patterns ───────────────────────────────────────────────

    def test_encryption_key_assignment(self):
        text = "encryption_key=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-041"]
        assert len(matches) == 1

    def test_ssh_public_key(self):
        text = "ssh-rsa " + "A" * 50
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-044"]
        assert len(matches) == 1

    def test_session_token_assignment(self):
        text = "session_token=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        matches = [m for m in injection_library.check(text) if m.signature_id == "DLP-046"]
        assert len(matches) == 1

    # ── Negative tests ────────────────────────────────────────────────

    def test_normal_text_no_dlp_match(self):
        text = "This is a normal message with no secrets."
        matches = [m for m in injection_library.check(text) if m.signature_id.startswith("DLP-")]
        assert len(matches) == 0

    def test_dlp_categories_exist(self):
        """Verify all DLP categories are populated."""
        for cat in ["dlp_api_key", "dlp_token", "dlp_credential", "dlp_cloud_token", "dlp_secret"]:
            sigs = injection_library.get_by_category(cat)
            assert len(sigs) > 0, f"Category {cat} has no signatures"

    def test_total_dlp_count(self):
        """Verify we have 46 DLP patterns."""
        dlp_sigs = [
            s for s in injection_library.signatures
            if s.signature_id.startswith("DLP-")
        ]
        assert len(dlp_sigs) == 46
