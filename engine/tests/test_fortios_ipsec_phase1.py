"""FortiOS IPsec phase 1 協商失敗:37124 與 37128 成對出現,遠端位址與協商細節要一致、可指定。"""
from __future__ import annotations

import re

from cyberrange import find_spec, load_spec, render_one

P1 = load_spec(find_spec("fortinet", "fortios", "7.4", "event.vpn.ipsec_phase1"))


def _kv(line: str) -> dict[str, str]:
    return {k: v.strip('"') for k, v in re.findall(r'(\w+)=("[^"]*"|\S+)', line)}


def test_is_a_vpn_event_at_error_level() -> None:
    kv = _kv(render_one(P1))
    assert (kv["type"], kv["subtype"], kv["level"], kv["action"]) == (
        "event", "vpn", "error", "negotiate")
    assert kv["logid"] in ("0101037124", "0101037128")


def test_phase1_error_message_is_self_consistent() -> None:
    for _ in range(40):
        kv = _kv(render_one(P1, {"kind": "error"}))
        assert kv["logid"] == "0101037124"
        assert kv["logdesc"] == kv["msg"] == "IPsec phase 1 error"
        assert kv["status"] == "negotiate_error"
        assert "result" not in kv


def test_phase1_progress_message_is_self_consistent() -> None:
    for _ in range(40):
        kv = _kv(render_one(P1, {"kind": "progress"}))
        assert kv["logid"] == "0101037128"
        assert (kv["logdesc"], kv["msg"]) == ("Progress IPsec phase 1", "progress IPsec phase 1")
        assert (kv["status"], kv["result"], kv["role"], kv["dir"]) == (
            "failure", "ERROR", "responder", "inbound")


def test_ike_ports_and_cookie_shape() -> None:
    for _ in range(40):
        kv = _kv(render_one(P1))
        assert kv["locport"] in ("500", "4500")
        assert 1024 <= int(kv["remport"]) <= 65535
        assert re.fullmatch(r"[0-9a-f]{16}/0{16}", kv["cookies"])


def test_remote_peer_and_device_can_be_pinned() -> None:
    params = {"remip_pool": "198.51.100.50", "local_ip": "192.0.2.1",
              "devname": "FGT-DP-TEST", "outintf": "wan1"}
    for _ in range(20):
        kv = _kv(render_one(P1, params))
        assert (kv["remip"], kv["locip"], kv["devname"], kv["outintf"]) == (
            "198.51.100.50", "192.0.2.1", "FGT-DP-TEST", "wan1")


def test_default_emits_both_kinds() -> None:
    seen = {_kv(render_one(P1))["logid"] for _ in range(200)}
    assert seen == {"0101037124", "0101037128"}
