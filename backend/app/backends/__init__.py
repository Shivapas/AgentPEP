"""Backend ABCs and plugin interfaces for AgentPEP.

Sprint 29 — ToolTrust: Backend ABCs & Async Architecture.
Sprint 31 — ToolTrust: Auth Provider Registry, OAuth2/OIDC, SAML, Redis Backend.
Provides abstract base classes for storage, authentication, and audit backends,
enabling pluggable backend implementations.
"""

from app.backends.audit import AuditBackend
from app.backends.auth import AuthProvider, AuthResult, TokenInfo
from app.backends.auth_registry import AuthProviderRegistry, auth_registry
from app.backends.storage import StorageBackend

__all__ = [
    "AuditBackend",
    "AuthProvider",
    "AuthProviderRegistry",
    "AuthResult",
    "StorageBackend",
    "TokenInfo",
    "auth_registry",
]
