"""Tests for Sprint 29 — ToolTrust: Backend ABCs & Async Architecture.

APEP-225: StorageBackend ABC
APEP-226: MongoDBStorageBackend
APEP-227: AuthProvider ABC
APEP-228: MTLSAuthProvider & APIKeyAuthProvider
APEP-229: AuditBackend ABC
APEP-230: MongoDBauditBackend & KafkaAuditBackend
APEP-231: ExecutionTokenManager
APEP-232: Execution token integration
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

# ---------------------------------------------------------------------------
# APEP-225: StorageBackend ABC
# ---------------------------------------------------------------------------


class TestStorageBackendABC:
    """Verify StorageBackend defines the required abstract interface."""

    def test_cannot_instantiate_abc(self):
        from app.backends.storage import StorageBackend

        with pytest.raises(TypeError):
            StorageBackend()

    def test_abc_has_required_methods(self):
        from app.backends.storage import StorageBackend
        import inspect

        abstract_methods = {
            name
            for name, _ in inspect.getmembers(StorageBackend)
            if getattr(getattr(StorageBackend, name, None), "__isabstractmethod__", False)
        }
        assert "get" in abstract_methods
        assert "put" in abstract_methods
        assert "delete" in abstract_methods
        assert "query" in abstract_methods
        assert "health_check" in abstract_methods


# ---------------------------------------------------------------------------
# APEP-226: MongoDBStorageBackend
# ---------------------------------------------------------------------------


class TestMongoDBStorageBackend:
    """Test MongoDBStorageBackend implements StorageBackend correctly."""

    @pytest.fixture
    def backend(self):
        from app.backends.mongodb_storage import MongoDBStorageBackend

        return MongoDBStorageBackend()

    @pytest.mark.asyncio
    async def test_put_and_get(self, backend, mock_mongodb):
        doc = {"rule_id": "test-123", "name": "Test Rule", "enabled": True}
        await backend.put("test_collection", doc)

        result = await backend.get("test_collection", {"rule_id": "test-123"})
        assert result is not None
        assert result["rule_id"] == "test-123"
        assert result["name"] == "Test Rule"
        # _id should be stripped
        assert "_id" not in result

    @pytest.mark.asyncio
    async def test_get_returns_none_when_not_found(self, backend, mock_mongodb):
        result = await backend.get("test_collection", {"rule_id": "nonexistent"})
        assert result is None

    @pytest.mark.asyncio
    async def test_delete(self, backend, mock_mongodb):
        doc = {"rule_id": "del-1", "name": "To Delete"}
        await backend.put("test_collection", doc)

        deleted = await backend.delete("test_collection", {"rule_id": "del-1"})
        assert deleted is True

        result = await backend.get("test_collection", {"rule_id": "del-1"})
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_returns_false(self, backend, mock_mongodb):
        deleted = await backend.delete("test_collection", {"rule_id": "nope"})
        assert deleted is False

    @pytest.mark.asyncio
    async def test_query_with_filter(self, backend, mock_mongodb):
        for i in range(5):
            await backend.put("test_collection", {
                "group": "A" if i < 3 else "B",
                "idx": i,
            })

        results = await backend.query("test_collection", {"group": "A"})
        assert len(results) == 3
        for r in results:
            assert "_id" not in r

    @pytest.mark.asyncio
    async def test_query_with_limit_and_offset(self, backend, mock_mongodb):
        for i in range(10):
            await backend.put("test_collection", {"idx": i})

        results = await backend.query("test_collection", {}, limit=3, offset=2)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_health_check(self, backend, mock_mongodb):
        result = await backend.health_check()
        # mongomock should respond to ping
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_put_with_upsert(self, backend, mock_mongodb):
        doc1 = {"rule_id": "upsert-1", "name": "Version 1"}
        await backend.put("test_collection", doc1)

        doc2 = {"rule_id": "upsert-1", "name": "Version 2"}
        await backend.put("test_collection", doc2, upsert=True)

        result = await backend.get("test_collection", {"rule_id": "upsert-1"})
        assert result is not None
        assert result["name"] == "Version 2"

    def test_implements_storage_backend(self, backend):
        from app.backends.storage import StorageBackend

        assert isinstance(backend, StorageBackend)


# ---------------------------------------------------------------------------
# APEP-227: AuthProvider ABC
# ---------------------------------------------------------------------------


class TestAuthProviderABC:
    """Verify AuthProvider defines the required abstract interface."""

    def test_cannot_instantiate_abc(self):
        from app.backends.auth import AuthProvider

        with pytest.raises(TypeError):
            AuthProvider()

    def test_abc_has_required_methods(self):
        from app.backends.auth import AuthProvider
        import inspect

        abstract_methods = {
            name
            for name, _ in inspect.getmembers(AuthProvider)
            if getattr(getattr(AuthProvider, name, None), "__isabstractmethod__", False)
        }
        assert "authenticate" in abstract_methods
        assert "validate_token" in abstract_methods
        assert "get_roles" in abstract_methods

    def test_auth_result_dataclass(self):
        from app.backends.auth import AuthResult

        result = AuthResult(authenticated=True, identity="test-user", tenant_id="t1")
        assert result.authenticated is True
        assert result.identity == "test-user"
        assert result.tenant_id == "t1"
        assert result.roles == []
        assert result.error_code == ""

    def test_token_info_dataclass(self):
        from app.backends.auth import TokenInfo

        info = TokenInfo(subject="sub-1", tenant_id="t1", roles=["admin"])
        assert info.subject == "sub-1"
        assert info.tenant_id == "t1"
        assert info.roles == ["admin"]
        assert info.expires_at is None


# ---------------------------------------------------------------------------
# APEP-228: MTLSAuthProvider & APIKeyAuthProvider
# ---------------------------------------------------------------------------


class TestAPIKeyAuthProvider:
    """Test APIKeyAuthProvider implements AuthProvider correctly."""

    @pytest.fixture
    def storage(self):
        from app.backends.mongodb_storage import MongoDBStorageBackend

        return MongoDBStorageBackend()

    @pytest.fixture
    def provider(self, storage):
        from app.backends.apikey_auth import APIKeyAuthProvider

        return APIKeyAuthProvider(storage)

    def _make_request(self, headers: dict[str, str] | None = None):
        request = MagicMock()
        request.headers = headers or {}
        return request

    @pytest.mark.asyncio
    async def test_missing_api_key(self, provider):
        request = self._make_request()
        result = await provider.authenticate(request)
        assert result.authenticated is False
        assert result.error_code == "MISSING_API_KEY"

    @pytest.mark.asyncio
    async def test_invalid_api_key(self, provider, mock_mongodb):
        request = self._make_request({"X-API-Key": "invalid-key"})
        result = await provider.authenticate(request)
        assert result.authenticated is False
        assert result.error_code == "INVALID_API_KEY"

    @pytest.mark.asyncio
    async def test_valid_api_key_by_hash(self, provider, storage, mock_mongodb):
        import hashlib

        api_key = "apk_test_valid_key"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        await storage.put("api_keys", {
            "key_hash": key_hash,
            "tenant_id": "tenant-abc",
            "name": "Test Key",
            "enabled": True,
        })

        request = self._make_request({"X-API-Key": api_key})
        result = await provider.authenticate(request)
        assert result.authenticated is True
        assert result.tenant_id == "tenant-abc"
        assert result.identity == "Test Key"

    @pytest.mark.asyncio
    async def test_valid_api_key_plaintext_fallback(self, provider, storage, mock_mongodb):
        api_key = "apk_plain_key"
        await storage.put("api_keys", {
            "key": api_key,
            "tenant_id": "tenant-xyz",
            "name": "Plain Key",
            "enabled": True,
        })

        request = self._make_request({"X-API-Key": api_key})
        result = await provider.authenticate(request)
        assert result.authenticated is True
        assert result.tenant_id == "tenant-xyz"

    @pytest.mark.asyncio
    async def test_validate_token(self, provider, storage, mock_mongodb):
        import hashlib

        api_key = "apk_token_test"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        await storage.put("api_keys", {
            "key_hash": key_hash,
            "tenant_id": "t1",
            "name": "Token Test",
            "enabled": True,
            "roles": ["reader"],
        })

        info = await provider.validate_token(api_key)
        assert info is not None
        assert info.subject == "Token Test"
        assert info.tenant_id == "t1"

    @pytest.mark.asyncio
    async def test_validate_token_invalid(self, provider, mock_mongodb):
        info = await provider.validate_token("invalid")
        assert info is None

    def test_implements_auth_provider(self, provider):
        from app.backends.auth import AuthProvider

        assert isinstance(provider, AuthProvider)


class TestMTLSAuthProvider:
    """Test MTLSAuthProvider implements AuthProvider correctly."""

    @pytest.fixture
    def provider(self):
        from app.backends.mtls_auth import MTLSAuthProvider

        return MTLSAuthProvider(
            role_mapping={"CN=agent-1,O=AgentPEP": ["admin", "reader"]}
        )

    def _make_request(self, headers: dict[str, str] | None = None):
        request = MagicMock()
        request.headers = headers or {}
        return request

    @pytest.mark.asyncio
    async def test_missing_cert(self, provider):
        request = self._make_request()
        result = await provider.authenticate(request)
        assert result.authenticated is False
        assert result.error_code == "MTLS_REQUIRED"

    @pytest.mark.asyncio
    async def test_failed_cert_verification(self, provider):
        request = self._make_request({"X-Client-Cert-Verified": "FAILED"})
        result = await provider.authenticate(request)
        assert result.authenticated is False

    @pytest.mark.asyncio
    async def test_valid_cert(self, provider):
        request = self._make_request({
            "X-Client-Cert-Verified": "SUCCESS",
            "X-Client-Cert-DN": "CN=agent-1,O=AgentPEP",
        })
        result = await provider.authenticate(request)
        assert result.authenticated is True
        assert result.identity == "CN=agent-1,O=AgentPEP"
        assert "admin" in result.roles
        assert "reader" in result.roles

    @pytest.mark.asyncio
    async def test_valid_cert_unknown_dn(self, provider):
        request = self._make_request({
            "X-Client-Cert-Verified": "SUCCESS",
            "X-Client-Cert-DN": "CN=unknown,O=Other",
        })
        result = await provider.authenticate(request)
        assert result.authenticated is True
        assert result.roles == []

    @pytest.mark.asyncio
    async def test_validate_token_returns_none(self, provider):
        info = await provider.validate_token("some-token")
        assert info is None

    @pytest.mark.asyncio
    async def test_get_roles(self, provider):
        roles = await provider.get_roles("CN=agent-1,O=AgentPEP")
        assert roles == ["admin", "reader"]

    @pytest.mark.asyncio
    async def test_get_roles_unknown(self, provider):
        roles = await provider.get_roles("CN=unknown")
        assert roles == []

    def test_implements_auth_provider(self, provider):
        from app.backends.auth import AuthProvider

        assert isinstance(provider, AuthProvider)


# ---------------------------------------------------------------------------
# APEP-229: AuditBackend ABC
# ---------------------------------------------------------------------------


class TestAuditBackendABC:
    """Verify AuditBackend defines the required abstract interface."""

    def test_cannot_instantiate_abc(self):
        from app.backends.audit import AuditBackend

        with pytest.raises(TypeError):
            AuditBackend()

    def test_abc_has_required_methods(self):
        from app.backends.audit import AuditBackend
        import inspect

        abstract_methods = {
            name
            for name, _ in inspect.getmembers(AuditBackend)
            if getattr(getattr(AuditBackend, name, None), "__isabstractmethod__", False)
        }
        assert "write_decision" in abstract_methods
        assert "query" in abstract_methods
        assert "verify_integrity" in abstract_methods

    def test_integrity_result_dataclass(self):
        from app.backends.audit import IntegrityResult

        result = IntegrityResult(valid=True, total_records=100, verified_records=100)
        assert result.valid is True
        assert result.total_records == 100
        assert result.first_tampered_sequence is None


# ---------------------------------------------------------------------------
# APEP-230: MongoDBauditBackend & KafkaAuditBackend
# ---------------------------------------------------------------------------


class TestMongoDBauditBackend:
    """Test MongoDBauditBackend implements AuditBackend correctly."""

    @pytest.fixture
    def backend(self):
        from app.backends.mongodb_audit import MongoDBauditBackend

        return MongoDBauditBackend()

    @pytest.mark.asyncio
    async def test_write_decision(self, backend, mock_mongodb):
        record = {
            "decision_id": str(uuid4()),
            "session_id": "sess-1",
            "agent_id": "agent-1",
            "tool_name": "file.read",
            "decision": "ALLOW",
            "risk_score": 0.1,
            "timestamp": "2026-01-01T00:00:00",
        }
        result = await backend.write_decision(record)
        assert result is True

    @pytest.mark.asyncio
    async def test_query(self, backend, mock_mongodb):
        for i in range(5):
            await backend.write_decision({
                "decision_id": str(uuid4()),
                "session_id": "sess-1",
                "agent_id": f"agent-{i}",
                "tool_name": "file.read",
                "decision": "ALLOW",
                "timestamp": f"2026-01-0{i + 1}T00:00:00",
            })

        results = await backend.query({"session_id": "sess-1"}, limit=3)
        assert len(results) == 3
        for r in results:
            assert "_id" not in r

    @pytest.mark.asyncio
    async def test_write_batch(self, backend, mock_mongodb):
        records = [
            {
                "decision_id": str(uuid4()),
                "session_id": "sess-batch",
                "agent_id": f"agent-{i}",
                "tool_name": "test",
                "decision": "ALLOW",
            }
            for i in range(10)
        ]
        written = await backend.write_batch(records)
        assert written == 10

    @pytest.mark.asyncio
    async def test_verify_integrity_empty(self, backend, mock_mongodb):
        result = await backend.verify_integrity()
        assert result.valid is True
        assert result.total_records == 0

    def test_implements_audit_backend(self, backend):
        from app.backends.audit import AuditBackend

        assert isinstance(backend, AuditBackend)


class TestKafkaAuditBackend:
    """Test KafkaAuditBackend implements AuditBackend correctly."""

    @pytest.fixture
    def backend(self):
        from app.backends.kafka_audit import KafkaAuditBackend

        return KafkaAuditBackend()

    @pytest.mark.asyncio
    async def test_write_decision_when_not_started(self, backend):
        record = {"decision_id": "test-1", "decision": "ALLOW"}
        result = await backend.write_decision(record)
        assert result is False  # Not started

    @pytest.mark.asyncio
    async def test_query_returns_empty(self, backend):
        results = await backend.query({"session_id": "s1"})
        assert results == []

    @pytest.mark.asyncio
    async def test_verify_integrity_always_valid(self, backend):
        result = await backend.verify_integrity()
        assert result.valid is True

    def test_is_running_when_not_started(self, backend):
        assert backend.is_running is False

    def test_implements_audit_backend(self, backend):
        from app.backends.audit import AuditBackend

        assert isinstance(backend, AuditBackend)


# ---------------------------------------------------------------------------
# APEP-231: ExecutionTokenManager
# ---------------------------------------------------------------------------


class TestExecutionTokenManager:
    """Test single-use cryptographic execution tokens."""

    @pytest.fixture
    def manager(self):
        from app.services.execution_token import ExecutionTokenManager

        return ExecutionTokenManager(ttl_seconds=60)

    def test_generate_returns_string(self, manager):
        token = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        assert isinstance(token, str)
        assert len(token) > 50

    def test_token_format(self, manager):
        token = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        parts = token.split("|")
        assert len(parts) == 9
        assert parts[0] == "v1"
        assert parts[1] == "dec-1"
        assert parts[2] == "sess-1"
        assert parts[3] == "agent-1"
        assert parts[4] == "file.read"

    @pytest.mark.asyncio
    async def test_validate_and_consume_valid_token(self, manager):
        token = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        payload = await manager.validate_and_consume(token)
        assert payload is not None
        assert payload.decision_id == "dec-1"
        assert payload.session_id == "sess-1"
        assert payload.agent_id == "agent-1"
        assert payload.tool_name == "file.read"

    @pytest.mark.asyncio
    async def test_single_use_token_cannot_be_reused(self, manager):
        token = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        # First consumption should succeed
        payload = await manager.validate_and_consume(token)
        assert payload is not None

        # Second consumption should fail
        payload2 = await manager.validate_and_consume(token)
        assert payload2 is None

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self):
        from app.services.execution_token import ExecutionTokenManager

        manager = ExecutionTokenManager(ttl_seconds=0)
        token = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        # Token should already be expired (TTL=0)
        await asyncio.sleep(0.01)
        payload = await manager.validate_and_consume(token)
        assert payload is None

    @pytest.mark.asyncio
    async def test_tampered_token_rejected(self, manager):
        token = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        # Tamper with the signature
        tampered = token[:-5] + "XXXXX"
        payload = await manager.validate_and_consume(tampered)
        assert payload is None

    @pytest.mark.asyncio
    async def test_invalid_format_rejected(self, manager):
        payload = await manager.validate_and_consume("invalid-token")
        assert payload is None

    @pytest.mark.asyncio
    async def test_wrong_version_rejected(self, manager):
        token = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        # Change version
        parts = token.split("|")
        parts[0] = "v99"
        tampered = "|".join(parts)
        payload = await manager.validate_and_consume(tampered)
        assert payload is None

    @pytest.mark.asyncio
    async def test_unique_tokens_per_call(self, manager):
        token1 = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        token2 = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        # Different nonces should produce different tokens
        assert token1 != token2

        # Both should be independently valid
        p1 = await manager.validate_and_consume(token1)
        p2 = await manager.validate_and_consume(token2)
        assert p1 is not None
        assert p2 is not None

    def test_reset(self, manager):
        manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        manager.reset()
        assert len(manager._consumed) == 0


# ---------------------------------------------------------------------------
# APEP-232: Execution Token in Intercept API Response
# ---------------------------------------------------------------------------


class TestExecutionTokenIntegration:
    """Test execution token integration with the Intercept API."""

    @pytest.mark.asyncio
    async def test_intercept_allow_includes_token(self, mock_mongodb):
        """ALLOW decisions should include an execution_token in the response."""
        from httpx import ASGITransport, AsyncClient

        from app.db import mongodb as db_module
        from app.main import app

        # Seed a permissive rule
        db = db_module.get_database()
        await db["policy_rules"].insert_one({
            "rule_id": str(uuid4()),
            "name": "allow-all",
            "agent_role": ["*"],
            "tool_pattern": "*",
            "action": "ALLOW",
            "priority": 1,
            "taint_check": False,
            "risk_threshold": 1.0,
            "rate_limit": None,
            "arg_validators": [],
            "enabled": True,
        })

        # Clear rule cache
        from app.services.rule_cache import rule_cache
        rule_cache.invalidate()

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post("/v1/intercept", json={
                "session_id": "test-session",
                "agent_id": "test-agent",
                "tool_name": "file.read",
                "tool_args": {"path": "/tmp/test"},
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["decision"] == "ALLOW"
            assert data.get("execution_token") is not None
            assert len(data["execution_token"]) > 50

    @pytest.mark.asyncio
    async def test_intercept_deny_has_no_token(self, mock_mongodb):
        """DENY decisions should not include an execution_token."""
        from httpx import ASGITransport, AsyncClient

        from app.db import mongodb as db_module
        from app.main import app

        # Seed a deny rule
        db = db_module.get_database()
        await db["policy_rules"].insert_one({
            "rule_id": str(uuid4()),
            "name": "deny-all",
            "agent_role": ["*"],
            "tool_pattern": "*",
            "action": "DENY",
            "priority": 1,
            "taint_check": False,
            "risk_threshold": 1.0,
            "rate_limit": None,
            "arg_validators": [],
            "enabled": True,
        })

        from app.services.rule_cache import rule_cache
        rule_cache.invalidate()

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.post("/v1/intercept", json={
                "session_id": "test-session",
                "agent_id": "test-agent",
                "tool_name": "file.read",
                "tool_args": {},
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["decision"] == "DENY"
            assert data.get("execution_token") is None


# ---------------------------------------------------------------------------
# SDK Execution Token Validator
# ---------------------------------------------------------------------------


class TestSDKExecutionTokenValidator:
    """Test SDK-side execution token validation."""

    @pytest.fixture
    def validator(self):
        from agentpep.execution_token import ExecutionTokenValidator

        return ExecutionTokenValidator()

    def test_validate_none_token(self, validator):
        result = validator.validate_and_consume(
            None,
            expected_tool_name="file.read",
            expected_agent_id="agent-1",
        )
        assert result is False

    def test_validate_valid_token(self, validator):
        from app.services.execution_token import ExecutionTokenManager

        manager = ExecutionTokenManager()
        token = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        result = validator.validate_and_consume(
            token,
            expected_tool_name="file.read",
            expected_agent_id="agent-1",
        )
        assert result is True

    def test_validate_consumed_token_rejected(self, validator):
        from app.services.execution_token import ExecutionTokenManager

        manager = ExecutionTokenManager()
        token = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        validator.validate_and_consume(
            token,
            expected_tool_name="file.read",
            expected_agent_id="agent-1",
        )
        # Second use should fail
        result = validator.validate_and_consume(
            token,
            expected_tool_name="file.read",
            expected_agent_id="agent-1",
        )
        assert result is False

    def test_validate_wrong_tool_rejected(self, validator):
        from app.services.execution_token import ExecutionTokenManager

        manager = ExecutionTokenManager()
        token = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        result = validator.validate_and_consume(
            token,
            expected_tool_name="file.write",
            expected_agent_id="agent-1",
        )
        assert result is False

    def test_validate_wrong_agent_rejected(self, validator):
        from app.services.execution_token import ExecutionTokenManager

        manager = ExecutionTokenManager()
        token = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        result = validator.validate_and_consume(
            token,
            expected_tool_name="file.read",
            expected_agent_id="agent-2",
        )
        assert result is False

    def test_validate_invalid_format(self, validator):
        result = validator.validate_and_consume(
            "not-a-valid-token",
            expected_tool_name="file.read",
            expected_agent_id="agent-1",
        )
        assert result is False

    def test_reset(self, validator):
        from app.services.execution_token import ExecutionTokenManager

        manager = ExecutionTokenManager()
        token = manager.generate(
            decision_id="dec-1",
            session_id="sess-1",
            agent_id="agent-1",
            tool_name="file.read",
        )
        validator.validate_and_consume(
            token,
            expected_tool_name="file.read",
            expected_agent_id="agent-1",
        )
        validator.reset()
        assert len(validator._consumed) == 0
