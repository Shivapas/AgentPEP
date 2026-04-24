"""AgentRT shared fixtures and path setup.

Adds the backend package to sys.path so that ``app.*`` modules are importable
when running AgentRT from the agentrt/ directory without a full install.
In CI the backend is installed as a package (``pip install -e ../backend``),
so the sys.path manipulation is a no-op safety net for local development.

Sprint S-E09 (E09-T01)
"""

from __future__ import annotations

import os
import sys

# Resolve agentrt/ → backend/ sibling path
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_BACKEND_DIR = os.path.join(_REPO_ROOT, "backend")

if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import mongomock_motor
import pytest

import app.db.mongodb as mongodb_module


@pytest.fixture(autouse=True)
def mock_mongodb(monkeypatch):
    """Replace the real MongoDB client with mongomock-motor for all AgentRT tests."""
    mock_client = mongomock_motor.AsyncMongoMockClient()
    mock_db = mock_client["agentpep_agentrt_test"]

    monkeypatch.setattr(mongodb_module, "_client", mock_client)
    monkeypatch.setattr(mongodb_module, "_db", mock_db)
    monkeypatch.setattr(mongodb_module, "get_database", lambda: mock_db)
    monkeypatch.setattr(mongodb_module, "get_client", lambda: mock_client)

    try:
        import app.middleware.auth as auth_module
        monkeypatch.setattr(auth_module, "get_database", lambda: mock_db)
    except (ImportError, AttributeError):
        pass

    yield mock_db
