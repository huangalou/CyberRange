"""POST /preview:param 型別錯誤回 400,而不是 500。"""
from __future__ import annotations

from fastapi.testclient import TestClient

from cyberrange_api.main import app

client = TestClient(app)

SPEC = {"vendor": "linux", "product": "openssh", "version": "9.x", "log_type": "auth.failure"}


def test_preview_bad_weighted_param_is_400() -> None:
    r = client.post("/preview", json={**SPEC, "count": 1, "params": {"kind_weights": "oops"}})
    assert r.status_code == 400
    assert "must be a mapping" in r.json()["detail"]
