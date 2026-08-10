"""Sink policy unit tests."""
from __future__ import annotations

import pytest

from cyberrange_api.sink_policy import SinkNotAllowed, validate_sink


def test_default_allows_all_known_schemes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CYBERRANGE_ALLOWED_SINK_SCHEMES", raising=False)
    monkeypatch.delenv("CYBERRANGE_ALLOWED_SINK_HOSTS", raising=False)
    validate_sink("stdout://")
    validate_sink("file:///tmp/x.log")
    validate_sink("udp://10.0.0.1:514")
    validate_sink("tcp://10.0.0.1:514")


def test_unknown_scheme_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CYBERRANGE_ALLOWED_SINK_SCHEMES", raising=False)
    with pytest.raises(SinkNotAllowed):
        validate_sink("ftp://1.2.3.4")


def test_scheme_allowlist_excludes_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CYBERRANGE_ALLOWED_SINK_SCHEMES", "udp,tcp")
    monkeypatch.delenv("CYBERRANGE_ALLOWED_SINK_HOSTS", raising=False)
    validate_sink("udp://10.0.0.1:514")
    with pytest.raises(SinkNotAllowed):
        validate_sink("file:///tmp/leak.log")
    with pytest.raises(SinkNotAllowed):
        validate_sink("stdout://")


def test_host_allowlist_blocks_random_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CYBERRANGE_ALLOWED_SINK_SCHEMES", "udp,tcp")
    monkeypatch.setenv(
        "CYBERRANGE_ALLOWED_SINK_HOSTS", "192.0.2.10,192.0.2.18"
    )
    validate_sink("udp://192.0.2.10:514")
    validate_sink("tcp://192.0.2.18:5044")
    with pytest.raises(SinkNotAllowed):
        validate_sink("udp://8.8.8.8:53")
    with pytest.raises(SinkNotAllowed):
        validate_sink("tcp://10.0.0.99:514")


def test_udp_requires_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CYBERRANGE_ALLOWED_SINK_HOSTS", raising=False)
    with pytest.raises(SinkNotAllowed):
        validate_sink("udp://")
