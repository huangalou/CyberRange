"""POST /generate 的 burst 節奏。"""
from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from cyberrange_api.main import app

client = TestClient(app)

SPEC = {"vendor": "linux", "product": "openssh", "version": "9.x", "log_type": "auth.failure"}


def _wait_job(job_id: str, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/jobs/{job_id}").json()
        if job["status"] in ("completed", "failed"):
            return job
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish")


def test_burst_job_sends_size_times_repeat(tmp_path: Path) -> None:
    out = tmp_path / "out.log"
    r = client.post("/generate", json={
        **SPEC,
        "count": 50,  # 有 burst 時忽略
        "burst": {"size": 2, "window_s": 0.02, "repeat": 2, "gap_s": 0.01},
        "sink": f"file://{out}",
    })
    assert r.status_code == 202
    job = r.json()
    assert job["count"] == 4
    assert job["burst"]["size"] == 2

    final = _wait_job(job["id"])
    assert final["status"] == "completed", final
    assert final["sent"] == 4
    assert len([l for l in out.read_text().splitlines() if l.strip()]) == 4


def test_burst_and_rate_are_mutually_exclusive(tmp_path: Path) -> None:
    r = client.post("/generate", json={
        **SPEC, "rate": 5, "burst": {"size": 2, "window_s": 1},
        "sink": f"file://{tmp_path / 'x.log'}",
    })
    assert r.status_code == 422
    assert "mutually exclusive" in r.text


def test_burst_invalid_size_rejected(tmp_path: Path) -> None:
    r = client.post("/generate", json={
        **SPEC, "burst": {"size": 0, "window_s": 1},
        "sink": f"file://{tmp_path / 'x.log'}",
    })
    assert r.status_code == 422


def test_rate_job_unchanged(tmp_path: Path) -> None:
    out = tmp_path / "out.log"
    r = client.post("/generate", json={**SPEC, "count": 3, "sink": f"file://{out}"})
    final = _wait_job(r.json()["id"])
    assert final["status"] == "completed"
    assert final["sent"] == 3
    assert final["burst"] is None
