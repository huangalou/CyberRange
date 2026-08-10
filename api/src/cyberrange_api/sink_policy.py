"""Sink URL policy: enforce scheme + host allowlist on `/generate` requests.

Engine-layer sinks (`cyberrange.sinks.open_sink`) accept any udp/tcp host:port.
In a publicly reachable deployment that turns the API into a UDP/TCP relay
(amplification, internal scan pivot). This module gates URLs at the API layer
before a job is dispatched.

Configured via env (read each call so tests can override):

- `CYBERRANGE_ALLOWED_SINK_SCHEMES` — comma-separated, default
  `stdout,file,udp,tcp` (dev). In prod set to `udp,tcp` to forbid local writes.
- `CYBERRANGE_ALLOWED_SINK_HOSTS` — comma-separated host allowlist for udp/tcp.
  If unset, no host restriction (dev). In prod set to your SOC ingress IPs.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse


class SinkNotAllowed(ValueError):
    """Raised when a sink URL violates configured policy."""


def _parse_csv_env(name: str) -> set[str] | None:
    raw = os.environ.get(name)
    if not raw:
        return None
    return {item.strip() for item in raw.split(",") if item.strip()}


def _allowed_schemes() -> set[str]:
    return _parse_csv_env("CYBERRANGE_ALLOWED_SINK_SCHEMES") or {
        "stdout",
        "file",
        "udp",
        "tcp",
    }


def _allowed_hosts() -> set[str] | None:
    return _parse_csv_env("CYBERRANGE_ALLOWED_SINK_HOSTS")


def validate_sink(sink_uri: str) -> None:
    parsed = urlparse(sink_uri)
    scheme = parsed.scheme or "stdout"

    schemes = _allowed_schemes()
    if scheme not in schemes:
        raise SinkNotAllowed(
            f"sink scheme {scheme!r} not allowed (allowed: {sorted(schemes)})"
        )

    if scheme in ("udp", "tcp"):
        host = parsed.hostname
        if not host:
            raise SinkNotAllowed(
                f"{scheme} sink requires a host, got {sink_uri!r}"
            )
        hosts = _allowed_hosts()
        if hosts is not None and host not in hosts:
            raise SinkNotAllowed(
                f"sink host {host!r} not in allowlist (allowed: {sorted(hosts)})"
            )
