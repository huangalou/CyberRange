"""Auth backends for the CyberRange API.

Phase 1: HTTP Basic via env-injected username + bcrypt password hash.
Phase 2 (planned): TOTP layered on top of Basic — same `AuthBackend` Protocol.

If `CYBERRANGE_BASIC_USER` / `CYBERRANGE_BASIC_PASS_BCRYPT` are unset, auth
is disabled (dev mode). In containerized prod both must be set.
"""
from __future__ import annotations

import os
import secrets
from typing import Callable, Protocol

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials


class AuthBackend(Protocol):
    """Protocol for swappable auth backends (Basic now, TOTP later)."""

    def authenticate(self, credentials: HTTPBasicCredentials) -> str: ...


class BasicAuthBackend:
    """Single-user HTTP Basic backed by env-injected bcrypt hash."""

    def __init__(self, username: str, password_bcrypt: str) -> None:
        self._username = username
        self._password_bcrypt = password_bcrypt.encode("utf-8")

    def authenticate(self, credentials: HTTPBasicCredentials) -> str:
        user_ok = secrets.compare_digest(credentials.username, self._username)
        pass_ok = bcrypt.checkpw(
            credentials.password.encode("utf-8"), self._password_bcrypt
        )
        if not (user_ok and pass_ok):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid credentials",
                headers={"WWW-Authenticate": 'Basic realm="cyberrange"'},
            )
        return credentials.username


_security = HTTPBasic(auto_error=False)


def _build_backend() -> BasicAuthBackend | None:
    username = os.environ.get("CYBERRANGE_BASIC_USER")
    password_bcrypt = os.environ.get("CYBERRANGE_BASIC_PASS_BCRYPT")
    if not username or not password_bcrypt:
        return None
    return BasicAuthBackend(username, password_bcrypt)


def make_auth_dependency() -> Callable[..., str]:
    """Return a FastAPI dependency that enforces auth based on env config."""
    backend = _build_backend()

    if backend is None:

        def _noop_auth() -> str:
            return "dev"

        return _noop_auth

    def _basic_auth(
        credentials: HTTPBasicCredentials | None = Depends(_security),
    ) -> str:
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authentication required",
                headers={"WWW-Authenticate": 'Basic realm="cyberrange"'},
            )
        return backend.authenticate(credentials)

    return _basic_auth


require_auth = make_auth_dependency()
