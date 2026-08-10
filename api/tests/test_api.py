"""End-to-end API tests via fastapi.testclient."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cyberrange_api.main import app

client = TestClient(app)


def _wait_job(job_id: str, timeout: float = 5.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/jobs/{job_id}")
        assert r.status_code == 200
        data = r.json()
        if data["status"] in ("completed", "failed"):
            return data
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_list_catalog():
    r = client.get("/catalog")
    assert r.status_code == 200
    items = r.json()
    assert len(items) >= 6
    vendors = {i["vendor"] for i in items}
    assert {"fortinet", "microsoft", "paloalto", "cisco", "linux", "apache"}.issubset(
        vendors
    )


def test_catalog_filter_by_vendor():
    r = client.get("/catalog", params={"vendor": "cisco"})
    items = r.json()
    assert items, "expected at least one cisco entry"
    assert all(i["vendor"] == "cisco" for i in items)


def test_catalog_filter_by_product():
    r = client.get("/catalog", params={"vendor": "microsoft", "product": "windows"})
    items = r.json()
    assert items
    assert all(i["product"] == "windows" for i in items)


def test_catalog_detail():
    r = client.get("/catalog/fortinet/fortios/7.4/traffic.forward")
    assert r.status_code == 200
    detail = r.json()
    assert detail["format"] == "key_value"
    assert detail["log_type"] == "traffic.forward"
    assert len(detail["fields"]) > 10
    # extras must reflect generator config
    field_by_name = {f["name"]: f for f in detail["fields"]}
    assert field_by_name["dstport"]["type"] == "weighted_choice"
    assert "choices" in field_by_name["dstport"]["extras"]
    assert "src_cidr" in detail["params"]


def test_catalog_detail_404():
    r = client.get("/catalog/nope/missing/0.0/none")
    assert r.status_code == 404


def test_preview_returns_samples():
    r = client.post(
        "/preview",
        json={
            "vendor": "fortinet",
            "product": "fortios",
            "version": "7.4",
            "log_type": "traffic.forward",
            "count": 5,
        },
    )
    assert r.status_code == 200
    samples = r.json()["samples"]
    assert len(samples) == 5
    assert all('logid="0000000013"' in s for s in samples)


def test_preview_param_override():
    r = client.post(
        "/preview",
        json={
            "vendor": "fortinet",
            "product": "fortios",
            "version": "7.4",
            "log_type": "traffic.forward",
            "count": 3,
            "params": {"src_cidr": "192.168.77.0/24"},
        },
    )
    samples = r.json()["samples"]
    for s in samples:
        assert "srcip=192.168.77." in s


def test_preview_count_cap():
    r = client.post(
        "/preview",
        json={
            "vendor": "fortinet",
            "product": "fortios",
            "version": "7.4",
            "log_type": "traffic.forward",
            "count": 200,
        },
    )
    assert r.status_code == 400


def test_preview_404():
    r = client.post(
        "/preview",
        json={
            "vendor": "nope",
            "product": "missing",
            "version": "0.0",
            "log_type": "none",
            "count": 1,
        },
    )
    assert r.status_code == 404


def test_generate_to_file_completes(tmp_path: Path):
    out = tmp_path / "out.log"
    r = client.post(
        "/generate",
        json={
            "vendor": "apache",
            "product": "httpd",
            "version": "2.4",
            "log_type": "access.combined",
            "count": 7,
            "sink": f"file://{out}",
        },
    )
    assert r.status_code == 202
    job = r.json()
    assert job["status"] in ("pending", "running", "completed")
    assert job["spec"]["vendor"] == "apache"

    final = _wait_job(job["id"])
    assert final["status"] == "completed", final
    assert final["sent"] == 7
    assert out.exists()
    lines = [l for l in out.read_text().splitlines() if l.strip()]
    assert len(lines) == 7
    # combined log shape: first token is IP
    assert all(l.split()[0].count(".") == 3 for l in lines)


def test_generate_invalid_spec_marks_failed(tmp_path: Path):
    r = client.post(
        "/generate",
        json={
            "vendor": "nope",
            "product": "missing",
            "version": "0.0",
            "log_type": "none",
            "count": 1,
            "sink": f"file://{tmp_path / 'x.log'}",
        },
    )
    # endpoint accepts the job; failure surfaces in status
    assert r.status_code == 202
    final = _wait_job(r.json()["id"])
    assert final["status"] == "failed"
    assert "FileNotFoundError" in (final["error"] or "")


def test_jobs_list_grows():
    before = len(client.get("/jobs").json())
    client.post(
        "/generate",
        json={
            "vendor": "linux",
            "product": "openssh",
            "version": "9.x",
            "log_type": "auth.failure",
            "count": 2,
            "sink": "stdout://",
        },
    )
    after = len(client.get("/jobs").json())
    assert after >= before + 1
