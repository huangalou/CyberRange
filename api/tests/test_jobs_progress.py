"""Job 的 sent 進度:執行中即時回報,sink 中途失敗時保留已送筆數。"""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

import pytest
from fastapi.testclient import TestClient

from cyberrange_api import runner
from cyberrange_api.main import app

client = TestClient(app)

SPEC = {"vendor": "linux", "product": "openssh", "version": "9.x", "log_type": "auth.failure"}
FINISHED = ("completed", "failed")


def _wait_for(job_id: str, predicate: Callable[[dict], bool], timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    job: dict = {}
    while time.monotonic() < deadline:
        job = client.get(f"/jobs/{job_id}").json()
        if predicate(job):
            return job
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} never met the condition, last state: {job}")


def _patch_sink(monkeypatch: pytest.MonkeyPatch, write: Callable[[str], None]) -> None:
    class _Sink:
        def write(self, line: str) -> None:
            write(line)

    @contextmanager
    def _open(uri: str) -> Iterator[_Sink]:
        yield _Sink()

    monkeypatch.setattr(runner, "open_sink", _open)


def test_failed_job_keeps_sent_count_when_sink_fails_midway(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    written: list[str] = []

    def _write(line: str) -> None:
        if len(written) == 3:
            raise OSError("sink down")
        written.append(line)

    _patch_sink(monkeypatch, _write)

    r = client.post("/generate", json={**SPEC, "count": 10, "sink": f"file://{tmp_path / 'x.log'}"})
    final = _wait_for(r.json()["id"], lambda j: j["status"] in FINISHED)

    assert final["status"] == "failed", final
    assert final["sent"] == 3
    assert final["error"] == "OSError: sink down"


def test_running_job_reports_sent_per_event(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release = threading.Event()
    written: list[str] = []

    def _write(line: str) -> None:
        if written:  # 第 1 筆放行,之後卡住,讓 job 停在 running
            release.wait(timeout=10)
        written.append(line)

    _patch_sink(monkeypatch, _write)

    r = client.post("/generate", json={**SPEC, "count": 3, "sink": f"file://{tmp_path / 'x.log'}"})
    job_id = r.json()["id"]
    try:
        running = _wait_for(job_id, lambda j: j["sent"] == 1, timeout=2.0)
        assert running["status"] == "running"
    finally:
        release.set()

    final = _wait_for(job_id, lambda j: j["status"] in FINISHED)
    assert final["status"] == "completed", final
    assert final["sent"] == 3
