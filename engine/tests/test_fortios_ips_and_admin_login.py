"""FortiOS IPS 特徵事件與管理員登入:規則條件會用到的欄位要能指定,衍生欄位要跟著一致。"""
from __future__ import annotations

import re

from cyberrange import find_spec, load_spec, render_one

IPS = load_spec(find_spec("fortinet", "fortios", "7.4", "utm.ips.signature"))
LOGIN = load_spec(find_spec("fortinet", "fortios", "7.4", "event.system.admin_login"))


def _kv(line: str) -> dict[str, str]:
    return {k: v.strip('"') for k, v in re.findall(r'(\w+)=("[^"]*"|\S+)', line)}


def test_ips_is_a_utm_ips_signature_log() -> None:
    kv = _kv(render_one(IPS))
    assert (kv["logid"], kv["type"], kv["subtype"], kv["eventtype"]) == (
        "0419016384", "utm", "ips", "signature")


def test_ips_signature_name_id_and_reference_stay_paired() -> None:
    for _ in range(40):
        kv = _kv(render_one(IPS))
        pair = f'{kv["attackid"]}:{kv["attack"]}'
        assert pair in IPS.default_params()["signature_pool"]
        assert kv["ref"].endswith(f'VID{kv["attackid"]}')
        assert kv["crlevel"] == kv["severity"]


def test_ips_rule_conditions_can_be_pinned() -> None:
    params = {"action": "detected", "severity": "critical", "src_pool": "198.51.100.5",
              "dst_pool": "192.0.2.44",
              "signature_pool": ["90001:Example.Signature.Name"]}
    for _ in range(20):
        kv = _kv(render_one(IPS, params))
        assert (kv["action"], kv["severity"], kv["srcip"], kv["dstip"]) == (
            "detected", "critical", "198.51.100.5", "192.0.2.44")
        assert (kv["attackid"], kv["attack"]) == ("90001", "Example.Signature.Name")


def test_ips_dstport_follows_service() -> None:
    for _ in range(40):
        kv = _kv(render_one(IPS))
        assert (kv["service"], kv["dstport"]) in (("HTTPS", "443"), ("HTTP", "80"))


def test_login_failure_message_is_self_consistent() -> None:
    for _ in range(40):
        line = render_one(LOGIN, {"outcome": "failed"})
        kv = _kv(line)
        assert (kv["logid"], kv["level"], kv["status"]) == ("0100032002", "alert", "failed")
        assert kv["logdesc"] == "Admin login failed"
        assert kv["reason"] in ("passwd_invalid", "name_invalid")
        assert kv["ui"] == f'{kv["method"]}({kv["srcip"]})'
        expected = "invalid user name" if kv["reason"] == "name_invalid" else "invalid password"
        assert line.endswith(
            f'msg="Administrator {kv["user"]} login failed from {kv["ui"]} because of {expected}"')
        assert line.startswith("<185>") and "profile=" not in line


def test_login_success_message_is_self_consistent() -> None:
    line = render_one(LOGIN, {"outcome": "success", "user_pool": "netops",
                              "src_pool": "198.51.100.9", "method": "https"})
    kv = _kv(line)
    assert (kv["logid"], kv["level"], kv["status"], kv["reason"]) == (
        "0100032001", "information", "success", "none")
    assert kv["logdesc"] == "Admin login successful" and kv["profile"] == "super_admin"
    assert line.startswith("<190>")
    assert line.endswith(
        'msg="Administrator netops logged in successfully from https(198.51.100.9)"')


def test_login_emits_both_outcomes_by_default() -> None:
    seen = {_kv(render_one(LOGIN))["status"] for _ in range(200)}
    assert seen == {"success", "failed"}
