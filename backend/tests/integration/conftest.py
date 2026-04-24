"""Conftest for PDP integration tests.

These tests do not use MongoDB, so we stub out the DB module directly
to avoid the mongomock-motor import that triggers a _cffi_backend error
in this environment.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture(autouse=True)
def stub_mongodb(monkeypatch):
    """Stub out MongoDB so PDP tests don't need a real DB."""
    mock_db = MagicMock()
    mock_client = MagicMock()

    import app.db.mongodb as mongodb_module
    monkeypatch.setattr(mongodb_module, "_client", mock_client)
    monkeypatch.setattr(mongodb_module, "_db", mock_db)
    monkeypatch.setattr(mongodb_module, "get_database", lambda: mock_db)
    monkeypatch.setattr(mongodb_module, "get_client", lambda: mock_client)

    yield mock_db
