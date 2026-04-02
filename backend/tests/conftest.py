"""Shared test fixtures — patches MongoDB with mongomock-motor."""

import mongomock_motor
import pytest

import app.db.mongodb as mongodb_module


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

    yield mock_db

    # Clear rule cache to prevent cross-test pollution
    try:
        from app.services.rule_cache import rule_cache

        rule_cache.invalidate()
    except ImportError:
        pass

    # Clear Sprint 6 singletons
    try:
        from app.services.taint_graph import taint_audit_logger, sanitisation_gate_registry

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

    # Clear Sprint 9 singletons
    try:
        from app.services.escalation_manager import escalation_manager
        from app.models.policy import NotificationConfig

        escalation_manager._pending_futures.clear()
        escalation_manager._notification_config = NotificationConfig()
        escalation_manager._websocket_callback = None
    except ImportError:
        pass
