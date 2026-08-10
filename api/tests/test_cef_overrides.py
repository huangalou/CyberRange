"""API-side tests for v4 CEF customizable mapping.

Covers Sprint B gates:
  1. GET catalog detail for PA traffic-cef → cef_header + cef_mapping non-null
  2. GET catalog detail for non-CEF catalog → both null
  3. POST /preview with overrides → 200 and body reflects override
  4. POST /generate with overrides → 202 + job_id, no engine error
  5. Override schema validation — severity non-int → 422

Auth bypassed via `client` fixture (conftest.py).
"""
from __future__ import annotations

import time

from fastapi.testclient import TestClient


PA_CEF = {
    "vendor": "paloalto",
    "product": "panos",
    "version": "10.0",
    "log_type": "traffic-cef",
}

# A non-CEF catalog known to exist
NON_CEF = {
    "vendor": "apache",
    "product": "httpd",
    "version": "2.4",
    "log_type": "access.combined",
}


def _wait_job(client: TestClient, job_id: str, timeout: float = 5.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/jobs/{job_id}")
        assert r.status_code == 200
        data = r.json()
        if data["status"] in ("completed", "failed"):
            return data
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


def test_catalog_detail_pa_cef_exposes_header_and_mapping(client: TestClient):
    r = client.get(
        f"/catalog/{PA_CEF['vendor']}/{PA_CEF['product']}"
        f"/{PA_CEF['version']}/{PA_CEF['log_type']}"
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cef_header"] is not None
    assert body["cef_header"]["device_vendor"] == "Palo Alto Networks"
    assert body["cef_header"]["name"] == "TRAFFIC"
    assert body["cef_mapping"] is not None
    assert len(body["cef_mapping"]) >= 30, "expected ~36 PA traffic CEF rows"
    # spot-check a couple of standard mappings
    keys = {row["pa_field"]: row["cef_key"] for row in body["cef_mapping"]}
    assert keys["src_ip"] == "src"
    assert keys["dst_port"] == "dpt"
    assert keys["application"] == "app"


def test_catalog_detail_non_cef_has_null_cef_fields(client: TestClient):
    r = client.get(
        f"/catalog/{NON_CEF['vendor']}/{NON_CEF['product']}"
        f"/{NON_CEF['version']}/{NON_CEF['log_type']}"
    )
    assert r.status_code == 200
    body = r.json()
    assert body["cef_header"] is None
    assert body["cef_mapping"] is None


def test_preview_with_overrides_reflects_in_samples(client: TestClient):
    payload = {
        **PA_CEF,
        "count": 3,
        "cef_header_overrides": {"device_version": "11.2.0", "name": "TRAFFIC-X"},
        "cef_extension_overrides": {
            "application": {"cef_key": "cs1"},
            "dst_ip":      {"value": "8.8.4.4"},
        },
    }
    r = client.post("/preview", json=payload)
    assert r.status_code == 200, r.text
    samples = r.json()["samples"]
    assert len(samples) == 3
    for line in samples:
        assert "|11.2.0|" in line
        assert "|TRAFFIC-X|" in line
        assert "cs1=" in line
        assert " app=" not in line
        assert "dst=8.8.4.4" in line


def test_generate_with_overrides_runs_to_completion(client: TestClient, tmp_path):
    """Job completes without engine error when CEF overrides are present."""
    out = tmp_path / "cef-out.log"
    payload = {
        **PA_CEF,
        "count": 5,
        "rate": 0.0,
        "sink": f"file://{out}",
        "cef_extension_overrides": {
            "action": {"cef_key": "cs2", "value": "drop"},
        },
    }
    r = client.post("/generate", json=payload)
    assert r.status_code == 202, r.text
    job_id = r.json()["id"]
    final = _wait_job(client, job_id)
    assert final["status"] == "completed", final
    assert final["sent"] == 5

    # Verify the rendered lines on disk really carry the override
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 5
    for ln in lines:
        assert "cs2=drop" in ln
        assert " act=" not in ln


def test_override_validation_rejects_bad_severity(client: TestClient):
    """Non-int severity in cef_header_overrides → Pydantic 422."""
    payload = {
        **PA_CEF,
        "count": 1,
        "cef_header_overrides": {"severity": "not-a-number"},
    }
    r = client.post("/preview", json=payload)
    assert r.status_code == 422, r.text
