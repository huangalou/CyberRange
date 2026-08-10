"""Sink-policy enforcement at the /generate boundary."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cyberrange_api.main import app

client = TestClient(app)


def _gen_payload(sink: str) -> dict:
    return {
        "vendor": "linux",
        "product": "openssh",
        "version": "9.x",
        "log_type": "auth.failure",
        "count": 1,
        "sink": sink,
    }


def test_generate_rejects_disallowed_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CYBERRANGE_ALLOWED_SINK_SCHEMES", "udp,tcp")
    monkeypatch.delenv("CYBERRANGE_ALLOWED_SINK_HOSTS", raising=False)
    r = client.post("/generate", json=_gen_payload("stdout://"))
    assert r.status_code == 400
    assert "scheme" in r.json()["detail"]


def test_generate_rejects_host_off_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CYBERRANGE_ALLOWED_SINK_SCHEMES", "udp,tcp")
    monkeypatch.setenv("CYBERRANGE_ALLOWED_SINK_HOSTS", "192.0.2.10")
    r = client.post("/generate", json=_gen_payload("udp://8.8.8.8:514"))
    assert r.status_code == 400
    assert "allowlist" in r.json()["detail"]


def test_generate_accepts_allowed_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CYBERRANGE_ALLOWED_SINK_SCHEMES", "udp,tcp")
    monkeypatch.setenv("CYBERRANGE_ALLOWED_SINK_HOSTS", "127.0.0.1")
    # 127.0.0.1:1 is unlikely to be listening; UDP send still succeeds (fire-and-forget).
    r = client.post("/generate", json=_gen_payload("udp://127.0.0.1:1"))
    assert r.status_code == 202
