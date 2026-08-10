"""Auth backend unit + integration tests."""
from __future__ import annotations

import bcrypt
import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from cyberrange_api.auth import (
    BasicAuthBackend,
    make_auth_dependency,
)


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode()


def test_backend_accepts_correct_credentials() -> None:
    backend = BasicAuthBackend("alice", _hash("s3cret"))
    creds = type("C", (), {"username": "alice", "password": "s3cret"})()
    assert backend.authenticate(creds) == "alice"


def test_backend_rejects_wrong_password() -> None:
    backend = BasicAuthBackend("alice", _hash("s3cret"))
    creds = type("C", (), {"username": "alice", "password": "wrong"})()
    with pytest.raises(HTTPException) as exc:
        backend.authenticate(creds)
    assert exc.value.status_code == 401


def test_backend_rejects_wrong_username() -> None:
    backend = BasicAuthBackend("alice", _hash("s3cret"))
    creds = type("C", (), {"username": "bob", "password": "s3cret"})()
    with pytest.raises(HTTPException) as exc:
        backend.authenticate(creds)
    assert exc.value.status_code == 401


def test_dependency_noop_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CYBERRANGE_BASIC_USER", raising=False)
    monkeypatch.delenv("CYBERRANGE_BASIC_PASS_BCRYPT", raising=False)
    dep = make_auth_dependency()

    app = FastAPI()

    @app.get("/secret")
    def secret(user: str = Depends(dep)) -> dict:
        return {"user": user}

    client = TestClient(app)
    r = client.get("/secret")
    assert r.status_code == 200
    assert r.json() == {"user": "dev"}


def test_dependency_requires_credentials_when_env_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CYBERRANGE_BASIC_USER", "alice")
    monkeypatch.setenv("CYBERRANGE_BASIC_PASS_BCRYPT", _hash("s3cret"))
    dep = make_auth_dependency()

    app = FastAPI()

    @app.get("/secret")
    def secret(user: str = Depends(dep)) -> dict:
        return {"user": user}

    client = TestClient(app)

    # Missing creds → 401
    r = client.get("/secret")
    assert r.status_code == 401
    assert "Basic" in r.headers.get("www-authenticate", "")

    # Wrong creds → 401
    r = client.get("/secret", auth=("alice", "wrong"))
    assert r.status_code == 401

    # Correct creds → 200
    r = client.get("/secret", auth=("alice", "s3cret"))
    assert r.status_code == 200
    assert r.json() == {"user": "alice"}
