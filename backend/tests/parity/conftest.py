"""Conftest for parity tests.

Parity tests only use app.pdp.engine — no MongoDB, no HTTP, no FastAPI.
Stub out MongoDB to avoid import-time errors from the parent conftest.py.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def stub_mongodb(monkeypatch):
    """Stub MongoDB for parity tests (no DB access required)."""
    mock_db = MagicMock()
    mock_client = MagicMock()

    try:
        import app.db.mongodb as mongodb_module
        monkeypatch.setattr(mongodb_module, "_client", mock_client)
        monkeypatch.setattr(mongodb_module, "_db", mock_db)
        monkeypatch.setattr(mongodb_module, "get_database", lambda: mock_db)
        monkeypatch.setattr(mongodb_module, "get_client", lambda: mock_client)
    except ImportError:
        pass

    yield mock_db
