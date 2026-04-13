"""SAMLAuthProvider — SAML 2.0 assertion parsing and authentication.

Sprint 31 — APEP-242: Implements SAML assertion parsing, role extraction,
SSO redirect flow, and time-window enforcement.
"""

from __future__ import annotations

import base64
import logging
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from typing import Any

from fastapi import Request

from app.backends.auth import AuthProvider, AuthResult, TokenInfo

logger = logging.getLogger(__name__)

# SAML 2.0 XML namespaces
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

NS = {
    "saml": SAML_NS,
    "samlp": SAMLP_NS,
    "ds": DSIG_NS,
}


class SAMLAuthProvider(AuthProvider):
    """Authenticates requests via SAML 2.0 assertions.

    Features:
    - SAML assertion XML parsing from Base64-encoded SAMLResponse
    - Attribute extraction for identity and roles
    - Audience restriction validation
    - NotBefore/NotOnOrAfter time-window enforcement
    - Role mapping from configurable SAML attribute name
    - SSO redirect URL generation for IdP-initiated flows
    """

    def __init__(
        self,
        idp_metadata_url: str = "",
        sp_entity_id: str = "",
        sp_acs_url: str = "",
        role_attribute: str = "Role",
        certificate_path: str = "",
        tenant_attribute: str = "TenantID",
        clock_skew_seconds: int = 120,
    ) -> None:
        self._idp_metadata_url = idp_metadata_url
        self._sp_entity_id = sp_entity_id
        self._sp_acs_url = sp_acs_url
        self._role_attribute = role_attribute
        self._certificate_path = certificate_path
        self._tenant_attribute = tenant_attribute
        self._clock_skew_seconds = clock_skew_seconds

        # Cached IdP metadata
        self._idp_sso_url: str = ""
        self._idp_certificate: str = ""

    # --- Assertion parsing ---

    @staticmethod
    def _decode_saml_response(saml_response: str) -> str:
        """Decode a Base64-encoded SAMLResponse to XML string."""
        try:
            decoded = base64.b64decode(saml_response)
            return decoded.decode("utf-8")
        except Exception as exc:
            raise ValueError(f"Failed to decode SAMLResponse: {exc}") from exc

    def _parse_assertion(self, xml_str: str) -> dict[str, Any]:
        """Parse a SAML assertion XML and extract key fields.

        Returns a dict with keys: subject, issuer, attributes, conditions,
        session_index, authn_instant.
        """
        try:
            root = ET.fromstring(xml_str)  # noqa: S314
        except ET.ParseError as exc:
            raise ValueError(f"Invalid SAML XML: {exc}") from exc

        # Find the Assertion element (may be wrapped in Response)
        assertion = root.find(".//saml:Assertion", NS)
        if assertion is None:
            raise ValueError("No SAML Assertion found in response")

        # Extract issuer
        issuer_elem = assertion.find("saml:Issuer", NS)
        issuer = issuer_elem.text if issuer_elem is not None and issuer_elem.text else ""

        # Extract subject / NameID
        name_id_elem = assertion.find(".//saml:Subject/saml:NameID", NS)
        subject = name_id_elem.text if name_id_elem is not None and name_id_elem.text else ""

        # Extract conditions
        conditions: dict[str, str] = {}
        conditions_elem = assertion.find("saml:Conditions", NS)
        if conditions_elem is not None:
            conditions["not_before"] = conditions_elem.get("NotBefore", "")
            conditions["not_on_or_after"] = conditions_elem.get("NotOnOrAfter", "")

            # Audience restriction
            audience_elem = conditions_elem.find(
                ".//saml:AudienceRestriction/saml:Audience", NS
            )
            if audience_elem is not None and audience_elem.text:
                conditions["audience"] = audience_elem.text

        # Extract attributes
        attributes: dict[str, list[str]] = {}
        attr_statement = assertion.find("saml:AttributeStatement", NS)
        if attr_statement is not None:
            for attr_elem in attr_statement.findall("saml:Attribute", NS):
                attr_name = attr_elem.get("Name", "")
                values = []
                for val_elem in attr_elem.findall("saml:AttributeValue", NS):
                    if val_elem.text:
                        values.append(val_elem.text)
                if attr_name:
                    attributes[attr_name] = values

        # Extract session index
        authn_stmt = assertion.find("saml:AuthnStatement", NS)
        session_index = ""
        authn_instant = ""
        if authn_stmt is not None:
            session_index = authn_stmt.get("SessionIndex", "")
            authn_instant = authn_stmt.get("AuthnInstant", "")

        return {
            "subject": subject,
            "issuer": issuer,
            "attributes": attributes,
            "conditions": conditions,
            "session_index": session_index,
            "authn_instant": authn_instant,
        }

    def _validate_conditions(self, conditions: dict[str, str]) -> tuple[bool, str]:
        """Validate time window and audience restrictions.

        Returns (valid, reason).
        """
        now = datetime.now(UTC)

        # Check NotBefore
        not_before = conditions.get("not_before", "")
        if not_before:
            try:
                nb_dt = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                from datetime import timedelta

                if now < nb_dt - timedelta(seconds=self._clock_skew_seconds):
                    return False, f"Assertion not yet valid (NotBefore: {not_before})"
            except ValueError:
                logger.warning("Invalid NotBefore format: %s", not_before)

        # Check NotOnOrAfter
        not_on_or_after = conditions.get("not_on_or_after", "")
        if not_on_or_after:
            try:
                noa_dt = datetime.fromisoformat(not_on_or_after.replace("Z", "+00:00"))
                from datetime import timedelta

                if now >= noa_dt + timedelta(seconds=self._clock_skew_seconds):
                    return False, f"Assertion expired (NotOnOrAfter: {not_on_or_after})"
            except ValueError:
                logger.warning("Invalid NotOnOrAfter format: %s", not_on_or_after)

        # Check audience
        audience = conditions.get("audience", "")
        if audience and self._sp_entity_id and audience != self._sp_entity_id:
            return False, (
                f"Audience mismatch: expected '{self._sp_entity_id}', got '{audience}'"
            )

        return True, ""

    def _extract_roles(self, attributes: dict[str, list[str]]) -> list[str]:
        """Extract roles from SAML attributes using the configured attribute name."""
        return attributes.get(self._role_attribute, [])

    # --- SSO Redirect ---

    def get_sso_redirect_url(self, relay_state: str = "") -> str:
        """Generate an SSO redirect URL for IdP-initiated login.

        Creates a SAML AuthnRequest and encodes it for HTTP-Redirect binding.
        """
        if not self._idp_sso_url:
            # Use metadata URL as fallback
            sso_url = self._idp_metadata_url
        else:
            sso_url = self._idp_sso_url

        if not sso_url:
            return ""

        request_id = f"_agentpep_{uuid.uuid4().hex}"
        issue_instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        authn_request = (
            f'<samlp:AuthnRequest xmlns:samlp="{SAMLP_NS}" '
            f'xmlns:saml="{SAML_NS}" '
            f'ID="{request_id}" '
            f'Version="2.0" '
            f'IssueInstant="{issue_instant}" '
            f'Destination="{sso_url}" '
            f'AssertionConsumerServiceURL="{self._sp_acs_url}" '
            f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
            f"<saml:Issuer>{self._sp_entity_id}</saml:Issuer>"
            f"</samlp:AuthnRequest>"
        )

        encoded = base64.b64encode(authn_request.encode()).decode()
        params = {"SAMLRequest": encoded}
        if relay_state:
            params["RelayState"] = relay_state

        return f"{sso_url}?{urllib.parse.urlencode(params)}"

    # --- AuthProvider interface ---

    async def authenticate(self, request: Request) -> AuthResult:
        """Authenticate via SAML assertion.

        Looks for the assertion in:
        1. ``X-SAML-Assertion`` header (Base64-encoded)
        2. ``SAMLResponse`` form field (POST binding)
        """
        saml_response = request.headers.get("X-SAML-Assertion", "")

        if not saml_response:
            # Try to read from form data (POST binding)
            content_type = request.headers.get("Content-Type", "")
            if "form" in content_type:
                try:
                    form = await request.form()
                    saml_response = form.get("SAMLResponse", "")
                except Exception:
                    pass

        if not saml_response:
            return AuthResult(
                authenticated=False,
                error_code="MISSING_SAML_ASSERTION",
                error_message=(
                    "SAML assertion required via X-SAML-Assertion header"
                    " or SAMLResponse form field"
                ),
            )

        try:
            xml_str = self._decode_saml_response(saml_response)
            assertion = self._parse_assertion(xml_str)
        except ValueError as exc:
            return AuthResult(
                authenticated=False,
                error_code="INVALID_SAML_ASSERTION",
                error_message=str(exc),
            )

        # Validate conditions
        conditions = assertion.get("conditions", {})
        valid, reason = self._validate_conditions(conditions)
        if not valid:
            return AuthResult(
                authenticated=False,
                error_code="SAML_CONDITION_FAILED",
                error_message=reason,
            )

        subject = assertion.get("subject", "")
        if not subject:
            return AuthResult(
                authenticated=False,
                error_code="MISSING_SUBJECT",
                error_message="SAML assertion missing NameID/Subject",
            )

        # Extract roles and tenant
        attributes = assertion.get("attributes", {})
        roles = self._extract_roles(attributes)
        tenant_values = attributes.get(self._tenant_attribute, [])
        tenant_id = tenant_values[0] if tenant_values else "default"

        return AuthResult(
            authenticated=True,
            identity=subject,
            tenant_id=tenant_id,
            roles=roles,
            metadata={
                "auth_method": "saml",
                "issuer": assertion.get("issuer", ""),
                "session_index": assertion.get("session_index", ""),
                "attributes": attributes,
            },
        )

    async def validate_token(self, token: str) -> TokenInfo | None:
        """Validate a SAML assertion passed as a token string (Base64-encoded)."""
        try:
            xml_str = self._decode_saml_response(token)
            assertion = self._parse_assertion(xml_str)
        except ValueError:
            return None

        conditions = assertion.get("conditions", {})
        valid, _ = self._validate_conditions(conditions)
        if not valid:
            return None

        subject = assertion.get("subject", "")
        if not subject:
            return None

        attributes = assertion.get("attributes", {})
        roles = self._extract_roles(attributes)
        tenant_values = attributes.get(self._tenant_attribute, [])
        tenant_id = tenant_values[0] if tenant_values else "default"

        return TokenInfo(
            subject=subject,
            tenant_id=tenant_id,
            roles=roles,
            metadata={
                "auth_method": "saml",
                "issuer": assertion.get("issuer", ""),
            },
        )

    async def get_roles(self, identity: str) -> list[str]:
        """Roles are extracted at authentication time; cannot look up by identity alone."""
        return []
