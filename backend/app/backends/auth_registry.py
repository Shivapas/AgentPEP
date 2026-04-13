"""AuthProviderRegistry — configurable per-tenant provider selection with fallback chain.

Sprint 31 — APEP-243: Enables per-tenant authentication provider selection.
Each tenant can have an ordered list of auth providers; the registry tries
each in sequence and returns the first successful result.
"""

from __future__ import annotations

import json
import logging

from fastapi import Request

from app.backends.auth import AuthProvider, AuthResult

logger = logging.getLogger(__name__)


class AuthProviderRegistry:
    """Per-tenant auth provider registry with ordered fallback chains.

    Providers are registered by name (e.g. ``"apikey"``, ``"oauth2"``,
    ``"saml"``, ``"mtls"``).  Each tenant can be assigned an ordered chain
    of provider names.  On ``authenticate(request)``, the registry resolves
    the tenant's chain (or the default chain) and tries each provider in
    order.  The first successful ``AuthResult`` is returned.  If all
    providers fail, the last failure is returned.

    Example configuration::

        registry.register("apikey", apikey_provider)
        registry.register("oauth2", oauth2_provider)
        registry.set_default_chain(["apikey"])
        registry.set_tenant_chain("acme", ["oauth2", "apikey"])
    """

    def __init__(self) -> None:
        self._providers: dict[str, AuthProvider] = {}
        self._tenant_chains: dict[str, list[str]] = {}
        self._default_chain: list[str] = []

    # --- Provider management ---

    def register(self, name: str, provider: AuthProvider) -> None:
        """Register an auth provider under a unique name."""
        self._providers[name] = provider
        logger.info("Auth provider registered: %s", name)

    def unregister(self, name: str) -> None:
        """Remove a registered provider."""
        self._providers.pop(name, None)

    def get_provider(self, name: str) -> AuthProvider | None:
        """Look up a registered provider by name."""
        return self._providers.get(name)

    def list_providers(self) -> list[str]:
        """Return names of all registered providers."""
        return list(self._providers.keys())

    # --- Chain configuration ---

    def set_default_chain(self, provider_names: list[str]) -> None:
        """Set the default fallback chain used when a tenant has no specific chain."""
        self._default_chain = list(provider_names)

    def set_tenant_chain(self, tenant_id: str, provider_names: list[str]) -> None:
        """Set a tenant-specific provider chain."""
        self._tenant_chains[tenant_id] = list(provider_names)

    def get_chain(self, tenant_id: str | None = None) -> list[str]:
        """Return the provider chain for a tenant, falling back to default."""
        if tenant_id and tenant_id in self._tenant_chains:
            return self._tenant_chains[tenant_id]
        return self._default_chain

    def configure_tenant_chains(self, chains_json: str) -> None:
        """Bulk-configure tenant chains from a JSON string.

        Expected format: ``{"tenant-id": ["provider1", "provider2"], ...}``
        """
        if not chains_json:
            return
        try:
            chains: dict[str, list[str]] = json.loads(chains_json)
            for tenant_id, provider_names in chains.items():
                self.set_tenant_chain(tenant_id, provider_names)
            logger.info("Configured tenant auth chains for %d tenants", len(chains))
        except (json.JSONDecodeError, TypeError):
            logger.warning("Invalid auth_provider_tenant_chains JSON — ignoring")

    # --- Authentication ---

    async def authenticate(self, request: Request) -> AuthResult:
        """Authenticate a request using the tenant's provider chain.

        Tries each provider in the chain in order.  Returns the first
        successful ``AuthResult``.  If all providers fail, returns the
        last failure result.

        Tenant is determined from:
        1. ``X-Tenant-ID`` header (if present)
        2. Falls back to default chain
        """
        tenant_hint = request.headers.get("X-Tenant-ID")
        chain = self.get_chain(tenant_hint)

        if not chain:
            return AuthResult(
                authenticated=False,
                error_code="NO_AUTH_CHAIN",
                error_message="No authentication provider chain configured",
            )

        last_result = AuthResult(
            authenticated=False,
            error_code="NO_PROVIDERS",
            error_message="No providers available in the chain",
        )

        for provider_name in chain:
            provider = self._providers.get(provider_name)
            if provider is None:
                logger.warning(
                    "Auth provider '%s' in chain but not registered — skipping",
                    provider_name,
                )
                continue

            try:
                result = await provider.authenticate(request)
                if result.authenticated:
                    logger.debug(
                        "Auth success via provider '%s' for tenant '%s'",
                        provider_name,
                        tenant_hint or "default",
                    )
                    return result
                last_result = result
            except Exception:
                logger.exception(
                    "Auth provider '%s' raised exception — trying next in chain",
                    provider_name,
                )
                last_result = AuthResult(
                    authenticated=False,
                    error_code="PROVIDER_ERROR",
                    error_message=f"Auth provider '{provider_name}' encountered an error",
                )

        return last_result

    def reset(self) -> None:
        """Clear all providers and chains (for testing)."""
        self._providers.clear()
        self._tenant_chains.clear()
        self._default_chain.clear()


# Module-level singleton
auth_registry = AuthProviderRegistry()
