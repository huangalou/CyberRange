"""Output sinks: stdout / file / UDP syslog / TCP syslog."""
from __future__ import annotations

import socket
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse


class _Sink:
    def write(self, line: str) -> None: ...
    def close(self) -> None: ...


class StdoutSink(_Sink):
    def write(self, line: str) -> None:
        sys.stdout.write(line.rstrip("\n") + "\n")
        sys.stdout.flush()


class FileSink(_Sink):
    def __init__(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._f = Path(path).open("a", encoding="utf-8")

    def write(self, line: str) -> None:
        self._f.write(line.rstrip("\n") + "\n")

    def close(self) -> None:
        self._f.close()


class UDPSink(_Sink):
    def __init__(self, host: str, port: int) -> None:
        self._addr = (host, port)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def write(self, line: str) -> None:
        self._sock.sendto(line.encode("utf-8"), self._addr)

    def close(self) -> None:
        self._sock.close()


class TCPSink(_Sink):
    def __init__(self, host: str, port: int) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((host, port))

    def write(self, line: str) -> None:
        payload = (line.rstrip("\n") + "\n").encode("utf-8")
        self._sock.sendall(payload)

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        self._sock.close()


@contextmanager
def open_sink(uri: str) -> Iterator[_Sink]:
    parsed = urlparse(uri)
    scheme = parsed.scheme or "stdout"
    sink: _Sink
    if scheme == "stdout":
        sink = StdoutSink()
    elif scheme == "file":
        # urlparse('file:///tmp/x') -> path='/tmp/x'
        path = parsed.path or uri[len("file://") :]
        sink = FileSink(path)
    elif scheme == "udp":
        if not parsed.hostname or parsed.port is None:
            raise ValueError(f"udp sink requires host:port, got {uri!r}")
        sink = UDPSink(parsed.hostname, parsed.port)
    elif scheme == "tcp":
        if not parsed.hostname or parsed.port is None:
            raise ValueError(f"tcp sink requires host:port, got {uri!r}")
        sink = TCPSink(parsed.hostname, parsed.port)
    else:
        raise ValueError(f"unknown sink scheme: {scheme!r}")

    try:
        yield sink
    finally:
        sink.close()
