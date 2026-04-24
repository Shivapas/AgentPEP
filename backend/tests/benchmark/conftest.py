"""Conftest for PDP benchmark tests — stubs MongoDB."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def stub_mongodb(monkeypatch):
    mock_db = MagicMock()
    mock_client = MagicMock()

    import app.db.mongodb as mongodb_module
    monkeypatch.setattr(mongodb_module, "_client", mock_client)
    monkeypatch.setattr(mongodb_module, "_db", mock_db)
    monkeypatch.setattr(mongodb_module, "get_database", lambda: mock_db)
    monkeypatch.setattr(mongodb_module, "get_client", lambda: mock_client)

    yield mock_db
