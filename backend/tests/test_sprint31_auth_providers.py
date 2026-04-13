"""Sprint 31 tests — Auth Providers & Registry.

APEP-241: OAuth2/OIDC AuthProvider — JWT validation, JWKS discovery, role mapping.
APEP-242: SAML AuthProvider — assertion parsing, role extraction, SSO redirect.
APEP-243: Auth provider registry — per-tenant provider selection with fallback chain.
"""

import base64
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.backends.auth import AuthProvider, AuthResult, TokenInfo
from app.backends.auth_registry import AuthProviderRegistry
from app.backends.saml_auth import SAMLAuthProvider


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---------------------------------------------------------------------------
# APEP-243: Auth Provider Registry
# ---------------------------------------------------------------------------


class MockProvider(AuthProvider):
    """Test auth provider that can be configured to succeed or fail."""

    def __init__(self, name: str, should_succeed: bool = False, roles: list[str] | None = None):
        self.name = name
        self._should_succeed = should_succeed
        self._roles = roles or []
        self.call_count = 0

    async def authenticate(self, request) -> AuthResult:
        self.call_count += 1
        if self._should_succeed:
            return AuthResult(
                authenticated=True,
                identity=f"user-from-{self.name}",
                tenant_id="test-tenant",
                roles=self._roles,
                metadata={"provider": self.name},
            )
        return AuthResult(
            authenticated=False,
            error_code=f"{self.name.upper()}_FAILED",
            error_message=f"{self.name} authentication failed",
        )

    async def validate_token(self, token: str) -> TokenInfo | None:
        return None

    async def get_roles(self, identity: str) -> list[str]:
        return self._roles


@pytest.mark.asyncio
async def test_registry_register_and_list():
    """Providers can be registered and listed."""
    registry = AuthProviderRegistry()
    p1 = MockProvider("p1")
    p2 = MockProvider("p2")

    registry.register("p1", p1)
    registry.register("p2", p2)

    assert set(registry.list_providers()) == {"p1", "p2"}


@pytest.mark.asyncio
async def test_registry_get_provider():
    """Registered providers can be retrieved by name."""
    registry = AuthProviderRegistry()
    p1 = MockProvider("p1")
    registry.register("p1", p1)

    assert registry.get_provider("p1") is p1
    assert registry.get_provider("nonexistent") is None


@pytest.mark.asyncio
async def test_registry_default_chain():
    """Default chain is used when no tenant-specific chain exists."""
    registry = AuthProviderRegistry()
    p1 = MockProvider("p1", should_succeed=True, roles=["admin"])
    registry.register("p1", p1)
    registry.set_default_chain(["p1"])

    assert registry.get_chain() == ["p1"]
    assert registry.get_chain("unknown-tenant") == ["p1"]


@pytest.mark.asyncio
async def test_registry_tenant_chain():
    """Tenant-specific chain overrides default."""
    registry = AuthProviderRegistry()
    p1 = MockProvider("p1")
    p2 = MockProvider("p2")
    registry.register("p1", p1)
    registry.register("p2", p2)

    registry.set_default_chain(["p1"])
    registry.set_tenant_chain("acme", ["p2", "p1"])

    assert registry.get_chain("acme") == ["p2", "p1"]
    assert registry.get_chain() == ["p1"]


@pytest.mark.asyncio
async def test_registry_authenticate_first_success():
    """Registry returns the first successful auth result."""
    registry = AuthProviderRegistry()
    p_fail = MockProvider("fail", should_succeed=False)
    p_success = MockProvider("success", should_succeed=True, roles=["reader"])
    p_also_success = MockProvider("also", should_succeed=True)

    registry.register("fail", p_fail)
    registry.register("success", p_success)
    registry.register("also", p_also_success)
    registry.set_default_chain(["fail", "success", "also"])

    mock_request = MagicMock()
    mock_request.headers = {}

    result = await registry.authenticate(mock_request)

    assert result.authenticated is True
    assert result.identity == "user-from-success"
    assert result.roles == ["reader"]
    assert p_fail.call_count == 1
    assert p_success.call_count == 1
    assert p_also_success.call_count == 0  # short-circuited


@pytest.mark.asyncio
async def test_registry_authenticate_all_fail():
    """Registry returns the last failure when all providers fail."""
    registry = AuthProviderRegistry()
    p1 = MockProvider("p1", should_succeed=False)
    p2 = MockProvider("p2", should_succeed=False)

    registry.register("p1", p1)
    registry.register("p2", p2)
    registry.set_default_chain(["p1", "p2"])

    mock_request = MagicMock()
    mock_request.headers = {}

    result = await registry.authenticate(mock_request)

    assert result.authenticated is False
    assert result.error_code == "P2_FAILED"


@pytest.mark.asyncio
async def test_registry_authenticate_empty_chain():
    """Registry returns error when no chain is configured."""
    registry = AuthProviderRegistry()
    mock_request = MagicMock()
    mock_request.headers = {}

    result = await registry.authenticate(mock_request)

    assert result.authenticated is False
    assert result.error_code == "NO_AUTH_CHAIN"


@pytest.mark.asyncio
async def test_registry_tenant_header_selection():
    """Registry uses X-Tenant-ID header to select tenant chain."""
    registry = AuthProviderRegistry()
    p_default = MockProvider("default", should_succeed=True)
    p_acme = MockProvider("acme", should_succeed=True, roles=["acme-admin"])

    registry.register("default", p_default)
    registry.register("acme", p_acme)
    registry.set_default_chain(["default"])
    registry.set_tenant_chain("acme-corp", ["acme"])

    mock_request = MagicMock()
    mock_request.headers = {"X-Tenant-ID": "acme-corp"}

    result = await registry.authenticate(mock_request)

    assert result.authenticated is True
    assert result.identity == "user-from-acme"
    assert result.roles == ["acme-admin"]


@pytest.mark.asyncio
async def test_registry_configure_tenant_chains_json():
    """Bulk configure tenant chains from JSON string."""
    registry = AuthProviderRegistry()
    registry.configure_tenant_chains('{"t1": ["oauth2", "apikey"], "t2": ["saml"]}')

    assert registry.get_chain("t1") == ["oauth2", "apikey"]
    assert registry.get_chain("t2") == ["saml"]


@pytest.mark.asyncio
async def test_registry_configure_invalid_json():
    """Invalid JSON is handled gracefully."""
    registry = AuthProviderRegistry()
    registry.configure_tenant_chains("not-json")
    assert registry.get_chain("any") == []


@pytest.mark.asyncio
async def test_registry_reset():
    """Reset clears all state."""
    registry = AuthProviderRegistry()
    registry.register("p1", MockProvider("p1"))
    registry.set_default_chain(["p1"])
    registry.set_tenant_chain("t1", ["p1"])

    registry.reset()

    assert registry.list_providers() == []
    assert registry.get_chain() == []
    assert registry.get_chain("t1") == []


@pytest.mark.asyncio
async def test_registry_provider_exception_handled():
    """Registry handles provider exceptions gracefully."""
    registry = AuthProviderRegistry()

    class FailingProvider(AuthProvider):
        async def authenticate(self, request):
            raise RuntimeError("boom")

        async def validate_token(self, token):
            return None

        async def get_roles(self, identity):
            return []

    p_fail = FailingProvider()
    p_success = MockProvider("ok", should_succeed=True)
    registry.register("fail", p_fail)
    registry.register("ok", p_success)
    registry.set_default_chain(["fail", "ok"])

    mock_request = MagicMock()
    mock_request.headers = {}

    result = await registry.authenticate(mock_request)
    assert result.authenticated is True
    assert result.identity == "user-from-ok"


# ---------------------------------------------------------------------------
# APEP-241: OAuth2/OIDC AuthProvider
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth2_extract_claim_nested():
    """Role extraction from nested claim paths works."""
    from app.backends.oauth2_auth import _extract_claim

    claims = {
        "realm_access": {
            "roles": ["admin", "reader"],
        },
        "simple": "value",
    }

    assert _extract_claim(claims, "realm_access.roles") == ["admin", "reader"]
    assert _extract_claim(claims, "simple") == "value"
    assert _extract_claim(claims, "nonexistent.path") is None
    assert _extract_claim(claims, "realm_access.nonexistent") is None


@pytest.mark.asyncio
async def test_oauth2_missing_bearer_token():
    """OAuth2 provider returns error when Bearer token is missing."""
    from app.backends.oauth2_auth import OAuth2OIDCAuthProvider

    provider = OAuth2OIDCAuthProvider(
        issuer_url="https://auth.example.com",
        audience="agentpep",
    )

    mock_request = MagicMock()
    mock_request.headers = {}

    result = await provider.authenticate(mock_request)
    assert result.authenticated is False
    assert result.error_code == "MISSING_BEARER_TOKEN"


@pytest.mark.asyncio
async def test_oauth2_invalid_jwt_header():
    """OAuth2 provider returns error for malformed JWT."""
    from app.backends.oauth2_auth import OAuth2OIDCAuthProvider

    provider = OAuth2OIDCAuthProvider(
        issuer_url="https://auth.example.com",
        audience="agentpep",
    )

    mock_request = MagicMock()
    mock_request.headers = {"Authorization": "Bearer not.a.valid.jwt"}

    result = await provider.authenticate(mock_request)
    assert result.authenticated is False
    assert result.error_code in ("INVALID_TOKEN", "JWT_VALIDATION_FAILED")


@pytest.mark.asyncio
async def test_oauth2_validate_token_invalid():
    """validate_token returns None for invalid tokens."""
    from app.backends.oauth2_auth import OAuth2OIDCAuthProvider

    provider = OAuth2OIDCAuthProvider(
        issuer_url="https://auth.example.com",
        audience="agentpep",
    )

    result = await provider.validate_token("invalid-token")
    assert result is None


@pytest.mark.asyncio
async def test_oauth2_get_roles_empty():
    """get_roles returns empty list (roles are extracted at auth time)."""
    from app.backends.oauth2_auth import OAuth2OIDCAuthProvider

    provider = OAuth2OIDCAuthProvider(
        issuer_url="https://auth.example.com",
        audience="agentpep",
    )

    roles = await provider.get_roles("any-identity")
    assert roles == []


# ---------------------------------------------------------------------------
# APEP-242: SAML AuthProvider
# ---------------------------------------------------------------------------


def _make_saml_assertion(
    subject: str = "test-user@example.com",
    issuer: str = "https://idp.example.com",
    roles: list[str] | None = None,
    audience: str = "https://agentpep.example.com",
    not_before: str | None = None,
    not_on_or_after: str | None = None,
    tenant_id: str | None = None,
) -> str:
    """Build a minimal SAML assertion XML and Base64-encode it."""
    now = datetime.now(UTC)
    if not_before is None:
        not_before = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not_on_or_after is None:
        not_on_or_after = (now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

    role_attrs = ""
    if roles:
        values = "".join(
            f'<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"'
            f' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            f' xsi:type="xs:string">{r}</saml:AttributeValue>'
            for r in roles
        )
        name_fmt = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        role_attrs = (
            f'<saml:Attribute Name="Role" NameFormat="{name_fmt}">'
            f"{values}</saml:Attribute>"
        )

    tenant_attrs = ""
    if tenant_id:
        name_fmt = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        tenant_attrs = (
            f'<saml:Attribute Name="TenantID" NameFormat="{name_fmt}">'
            f'<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"'
            f' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            f' xsi:type="xs:string">{tenant_id}</saml:AttributeValue>'
            f"</saml:Attribute>"
        )

    xml = (
        f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        f' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        f"<saml:Assertion>"
        f"<saml:Issuer>{issuer}</saml:Issuer>"
        f"<saml:Subject>"
        f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
        f"{subject}</saml:NameID>"
        f"</saml:Subject>"
        f'<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">'
        f"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>"
        f"</saml:AudienceRestriction></saml:Conditions>"
        f"<saml:AttributeStatement>{role_attrs}{tenant_attrs}</saml:AttributeStatement>"
        f'<saml:AuthnStatement SessionIndex="session-123" AuthnInstant="{not_before}"/>'
        f"</saml:Assertion></samlp:Response>"
    )
    return base64.b64encode(xml.encode()).decode()


@pytest.mark.asyncio
async def test_saml_valid_assertion():
    """SAML provider authenticates with a valid assertion."""
    provider = SAMLAuthProvider(
        sp_entity_id="https://agentpep.example.com",
        role_attribute="Role",
    )

    encoded = _make_saml_assertion(
        subject="alice@example.com",
        roles=["admin", "reader"],
        tenant_id="acme-corp",
    )

    mock_request = MagicMock()
    mock_request.headers = {"X-SAML-Assertion": encoded}

    result = await provider.authenticate(mock_request)

    assert result.authenticated is True
    assert result.identity == "alice@example.com"
    assert result.roles == ["admin", "reader"]
    assert result.tenant_id == "acme-corp"
    assert result.metadata["auth_method"] == "saml"


@pytest.mark.asyncio
async def test_saml_expired_assertion():
    """SAML provider rejects expired assertions."""
    provider = SAMLAuthProvider(sp_entity_id="https://agentpep.example.com")

    past = datetime.now(UTC) - timedelta(hours=2)
    encoded = _make_saml_assertion(
        not_before=(past - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        not_on_or_after=past.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    mock_request = MagicMock()
    mock_request.headers = {"X-SAML-Assertion": encoded}

    result = await provider.authenticate(mock_request)

    assert result.authenticated is False
    assert result.error_code == "SAML_CONDITION_FAILED"
    assert "expired" in result.error_message.lower()


@pytest.mark.asyncio
async def test_saml_audience_mismatch():
    """SAML provider rejects assertions with wrong audience."""
    provider = SAMLAuthProvider(sp_entity_id="https://agentpep.example.com")

    encoded = _make_saml_assertion(audience="https://wrong-audience.com")

    mock_request = MagicMock()
    mock_request.headers = {"X-SAML-Assertion": encoded}

    result = await provider.authenticate(mock_request)

    assert result.authenticated is False
    assert result.error_code == "SAML_CONDITION_FAILED"
    assert "audience" in result.error_message.lower()


@pytest.mark.asyncio
async def test_saml_missing_assertion():
    """SAML provider returns error when no assertion is provided."""
    provider = SAMLAuthProvider()

    mock_request = MagicMock()
    mock_request.headers = {"Content-Type": "application/json"}

    result = await provider.authenticate(mock_request)

    assert result.authenticated is False
    assert result.error_code == "MISSING_SAML_ASSERTION"


@pytest.mark.asyncio
async def test_saml_invalid_base64():
    """SAML provider handles invalid Base64 gracefully."""
    provider = SAMLAuthProvider()

    mock_request = MagicMock()
    mock_request.headers = {"X-SAML-Assertion": "not-valid-base64!!!"}

    result = await provider.authenticate(mock_request)

    assert result.authenticated is False
    assert result.error_code == "INVALID_SAML_ASSERTION"


@pytest.mark.asyncio
async def test_saml_missing_subject():
    """SAML provider rejects assertions without a subject."""
    provider = SAMLAuthProvider()

    encoded = _make_saml_assertion(subject="")

    mock_request = MagicMock()
    mock_request.headers = {"X-SAML-Assertion": encoded}

    result = await provider.authenticate(mock_request)

    assert result.authenticated is False
    assert result.error_code == "MISSING_SUBJECT"


@pytest.mark.asyncio
async def test_saml_validate_token():
    """validate_token works with Base64-encoded assertion."""
    provider = SAMLAuthProvider(
        sp_entity_id="https://agentpep.example.com",
        role_attribute="Role",
    )

    encoded = _make_saml_assertion(
        subject="bob@example.com",
        roles=["viewer"],
    )

    result = await provider.validate_token(encoded)

    assert result is not None
    assert result.subject == "bob@example.com"
    assert result.roles == ["viewer"]


@pytest.mark.asyncio
async def test_saml_validate_token_invalid():
    """validate_token returns None for invalid tokens."""
    provider = SAMLAuthProvider()

    result = await provider.validate_token("invalid")
    assert result is None


@pytest.mark.asyncio
async def test_saml_sso_redirect_url():
    """SSO redirect URL is generated correctly."""
    provider = SAMLAuthProvider(
        sp_entity_id="https://agentpep.example.com",
        sp_acs_url="https://agentpep.example.com/saml/acs",
    )
    provider._idp_sso_url = "https://idp.example.com/sso"

    url = provider.get_sso_redirect_url(relay_state="/dashboard")

    assert "https://idp.example.com/sso?" in url
    assert "SAMLRequest=" in url
    assert "RelayState=%2Fdashboard" in url


@pytest.mark.asyncio
async def test_saml_get_roles_empty():
    """get_roles returns empty list (roles extracted at auth time)."""
    provider = SAMLAuthProvider()
    roles = await provider.get_roles("any-identity")
    assert roles == []
