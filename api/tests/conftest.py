"""Shared pytest fixtures.

P0 Basic Auth 在環境變數未設時為 no-op,故 TestClient 不需注入認證。
"""
from __future__ import annotations

from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from cyberrange_api.main import app


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c
