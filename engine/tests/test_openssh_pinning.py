"""openssh auth-failure:live-fire 需要可釘住來源 IP 與樣態。"""
from __future__ import annotations

from cyberrange import find_spec, load_spec, render_one

SPEC = load_spec(find_spec("linux", "openssh", "9.x", "auth.failure"))


def test_kind_and_src_can_be_pinned() -> None:
    params = {"kind_weights": {"invalid_user": 1}, "src_pool": "203.0.113.5"}
    lines = [render_one(SPEC, params) for _ in range(50)]
    assert all("Failed password for invalid user" in l for l in lines)
    assert all("from 203.0.113.5 port" in l for l in lines)


def test_default_kind_weights_unchanged() -> None:
    assert SPEC.default_params()["kind_weights"] == {
        "invalid_user": 0.45,
        "failed_password": 0.30,
        "preauth_close": 0.15,
        "invalid_user_announce": 0.10,
    }
