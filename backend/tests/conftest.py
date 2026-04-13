"""Shared test fixtures — patches MongoDB with mongomock-motor."""

import mongomock_motor
import pytest

import app.db.mongodb as mongodb_module


def make_auth_headers(roles: list[str] | None = None) -> dict[str, str]:
    """Create JWT auth headers for testing."""
    from app.services.jwt_auth import create_access_token

    token = create_access_token(
        {
            "sub": "test_user",
            "tenant_id": "default",
            "roles": roles or ["Admin"],
            "jti": "test-jti",
        }
    )
    return {"Authorization": f"Bearer {token}"}


# Default auth headers for all tests
AUTH_HEADERS = None


def _get_auth_headers() -> dict[str, str]:
    """Lazily create default auth headers (avoids import-time side effects)."""
    global AUTH_HEADERS
    if AUTH_HEADERS is None:
        AUTH_HEADERS = make_auth_headers()
    return AUTH_HEADERS


@pytest.fixture(autouse=True)
def mock_mongodb(monkeypatch):
    """Replace the real MongoDB client with mongomock-motor for all tests."""
    mock_client = mongomock_motor.AsyncMongoMockClient()
    mock_db = mock_client["agentpep_test"]

    monkeypatch.setattr(mongodb_module, "_client", mock_client)
    monkeypatch.setattr(mongodb_module, "_db", mock_db)
    monkeypatch.setattr(mongodb_module, "get_database", lambda: mock_db)
    monkeypatch.setattr(mongodb_module, "get_client", lambda: mock_client)

    # Also patch the middleware auth module's reference to get_database
    try:
        import app.middleware.auth as auth_module
        monkeypatch.setattr(auth_module, "get_database", lambda: mock_db)
    except (ImportError, AttributeError):
        pass

    # Reset AUTH_HEADERS cache so it uses the test-patched JWT secret
    global AUTH_HEADERS
    AUTH_HEADERS = None

    yield mock_db

    # Clear rule cache to prevent cross-test pollution
    try:
        from app.services.rule_cache import rule_cache

        rule_cache.invalidate()
    except ImportError:
        pass

    # Clear Sprint 6 singletons
    try:
        from app.services.taint_graph import sanitisation_gate_registry, taint_audit_logger

        taint_audit_logger.clear()
        for gate in list(sanitisation_gate_registry.list_gates()):
            sanitisation_gate_registry.remove(gate.gate_id)
    except ImportError:
        pass

    # Clear Sprint 7 singletons
    try:
        from app.services.confused_deputy import security_alert_emitter

        security_alert_emitter.clear()
    except ImportError:
        pass

    # Clear Sprint 8 singletons
    try:
        from app.services.risk_scoring import risk_engine

        risk_engine.aggregator._cached_config = None
    except ImportError:
        pass

    # Clear Sprint 9 singletons
    try:
        from app.services.escalation_manager import escalation_manager

        escalation_manager.clear()
        escalation_manager._notification_config = None
        escalation_manager._websocket_callback = None
    except (ImportError, AttributeError):
        pass

    # Clear Sprint 10 singletons
    try:
        from app.services.audit_logger import audit_logger

        audit_logger.reset()
    except ImportError:
        pass

    # Clear Sprint 11 global rate limit state by resetting config
    try:
        from app.core.config import settings

        settings.global_rate_limit_enabled = False
    except ImportError:
        pass

    # Clear Sprint 12 MCP singletons
    try:
        from app.services.mcp_session_tracker import mcp_session_tracker

        for sid in list(mcp_session_tracker._sessions.keys()):
            mcp_session_tracker._sessions.pop(sid, None)
    except ImportError:
        pass

    try:
        from app.api.v1.mcp import clear_active_proxies

        clear_active_proxies()
    except ImportError:
        pass

    # Clear Sprint 29 execution token state
    try:
        from app.services.execution_token import execution_token_manager

        execution_token_manager.reset()
    except ImportError:
        pass
