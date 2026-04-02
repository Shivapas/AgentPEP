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
