"""APIKeyAuthProvider — API key authentication via StorageBackend.

Sprint 29 — APEP-228: Refactors the existing API key authentication
middleware as an AuthProvider implementation.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from typing import Any

from fastapi import Request

from app.backends.auth import AuthProvider, AuthResult, TokenInfo
from app.backends.storage import StorageBackend

logger = logging.getLogger(__name__)

# Collection name for API key records
API_KEYS_COLLECTION = "api_keys"


class APIKeyAuthProvider(AuthProvider):
    """Authenticates requests via X-API-Key header.

    Validates API keys against records in the storage backend.
    Supports both hashed (preferred) and plaintext (legacy) key lookup.
    """

    def __init__(self, storage: StorageBackend) -> None:
        self._storage = storage

    async def authenticate(self, request: Request) -> AuthResult:
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            return AuthResult(
                authenticated=False,
                error_code="MISSING_API_KEY",
                error_message="X-API-Key header is required",
            )

        # Look up by hash first (preferred)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        key_record = await self._storage.get(
            API_KEYS_COLLECTION,
            {"key_hash": key_hash, "enabled": True},
        )

        # Fall back to plaintext lookup for backward compatibility
        if key_record is None:
            key_record = await self._storage.get(
                API_KEYS_COLLECTION,
                {"key": api_key, "enabled": True},
            )
            if key_record is not None:
                stored_key = key_record.get("key", "")
                if not secrets.compare_digest(stored_key, api_key):
                    key_record = None

        if key_record is None:
            return AuthResult(
                authenticated=False,
                error_code="INVALID_API_KEY",
                error_message="Invalid or disabled API key",
            )

        tenant_id = key_record.get("tenant_id", "default")
        key_name = key_record.get("name", "")
        roles = key_record.get("roles", [])

        return AuthResult(
            authenticated=True,
            identity=key_name,
            tenant_id=tenant_id,
            roles=roles,
            metadata={"api_key_name": key_name},
        )

    async def validate_token(self, token: str) -> TokenInfo | None:
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        key_record = await self._storage.get(
            API_KEYS_COLLECTION,
            {"key_hash": key_hash, "enabled": True},
        )

        # Plaintext fallback
        if key_record is None:
            key_record = await self._storage.get(
                API_KEYS_COLLECTION,
                {"key": token, "enabled": True},
            )
            if key_record is not None:
                stored_key = key_record.get("key", "")
                if not secrets.compare_digest(stored_key, token):
                    return None

        if key_record is None:
            return None

        return TokenInfo(
            subject=key_record.get("name", ""),
            tenant_id=key_record.get("tenant_id", "default"),
            roles=key_record.get("roles", []),
        )

    async def get_roles(self, identity: str) -> list[str]:
        # Look up by key name
        key_record = await self._storage.get(
            API_KEYS_COLLECTION,
            {"name": identity, "enabled": True},
        )
        if key_record is None:
            return []
        return key_record.get("roles", [])
