"""Check Point Log Exporter(syslog 版面)的防火牆連線紀錄與 IPS 防護事件:
版面固定、驅動欄位帶動的衍生欄位一致、規則條件會用到的欄位可以指定。"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from cyberrange import find_spec, load_spec, render_one

FW = load_spec(find_spec("checkpoint", "firewall", "r81", "firewall.security_log"))
IPS = load_spec(find_spec("checkpoint", "ips", "r81", "ips.protection_log"))

# <PRI>1 時間Z 主機 CheckPoint PID - [key:"value"; key:"value"]
LINE = re.compile(
    r'^<134>1 (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) (\S+) CheckPoint (\d+) - \[(.*)\]$')
PAIR = re.compile(r'([A-Za-z_]+):"((?:[^"\\]|\\.)*)"')

FW_KEYS = [
    "action", "flags", "ifdir", "ifname", "logid", "loguid", "origin", "originsicname",
    "sequencenum", "time", "version", "__policy_id_tag", "dst", "inzone", "layer_name",
    "layer_uuid", "match_id", "parent_rule", "rule_action", "rule_name", "rule_uid",
    "outzone", "product", "proto", "s_port", "service", "service_id", "src"]


def _parse(line: str) -> tuple[str, str, list[tuple[str, str]]]:
    m = LINE.match(line)
    assert m, line
    body = m.group(4)
    pairs = PAIR.findall(body)
    # 整個中括號內容只能由 key:"value" 以 "; " 串成,不留多餘文字或結尾分號
    assert "; ".join(f'{k}:"{v}"' for k, v in pairs) == body
    return m.group(1), m.group(2), pairs


def _kv(line: str) -> dict[str, str]:
    return dict(_parse(line)[2])


def test_firewall_layout_and_field_order() -> None:
    for _ in range(30):
        ts, host, pairs = _parse(render_one(FW))
        assert host == "cp-mgmt"
        assert [k for k, _ in pairs] == FW_KEYS
        kv = dict(pairs)
        assert kv["product"] == "VPN-1 & FireWall-1"
        assert re.fullmatch(r"\{0x[0-9a-f]+,0x0,0x[0-9a-f]+,0x[0-9a-f]+\}", kv["loguid"])


def test_firewall_action_drives_the_rule_fields() -> None:
    expected = {"Accept": ("Allow Published Services", "3"),
                "Drop": ("Cleanup rule", "12"),
                "Reject": ("Reject Ident", "9")}
    for action, (rule_name, match_id) in expected.items():
        for _ in range(10):
            kv = _kv(render_one(FW, {"action": action}))
            assert (kv["action"], kv["rule_action"]) == (action, action)
            assert (kv["rule_name"], kv["match_id"]) == (rule_name, match_id)
            assert kv["rule_uid"].endswith(match_id.zfill(12))


def test_firewall_emits_all_three_actions_by_default() -> None:
    seen = {_kv(render_one(FW))["action"] for _ in range(400)}
    assert seen == {"Accept", "Drop", "Reject"}


def test_firewall_service_port_and_protocol_stay_paired() -> None:
    pool = set(FW.default_params()["service_pool"])
    for _ in range(60):
        kv = _kv(render_one(FW))
        assert f'{kv["service_id"]}/{kv["proto"]}/{kv["service"]}' in pool


def test_firewall_rule_conditions_can_be_pinned() -> None:
    params = {"action": "Drop", "src_pool": "198.51.100.5", "dst_pool": "192.0.2.44",
              "svc": "telnet/6/23", "s_port": "40000", "rule_name": "Block Telnet",
              "match_id": "7", "ifname": "eth2", "ifdir": "outbound",
              "inzone": "Internal", "outzone": "External", "origin": "192.0.2.254"}
    for _ in range(10):
        kv = _kv(render_one(FW, params))
        assert (kv["action"], kv["rule_action"]) == ("Drop", "Drop")
        assert (kv["src"], kv["s_port"], kv["dst"]) == ("198.51.100.5", "40000", "192.0.2.44")
        assert (kv["service"], kv["service_id"], kv["proto"]) == ("23", "telnet", "6")
        assert (kv["rule_name"], kv["match_id"]) == ("Block Telnet", "7")
        assert (kv["ifname"], kv["ifdir"]) == ("eth2", "outbound")
        assert (kv["inzone"], kv["outzone"], kv["origin"]) == (
            "Internal", "External", "192.0.2.254")


def test_header_time_is_utc_and_matches_the_epoch_field() -> None:
    # Log Exporter 的標頭時間是 UTC(Z),本文的 time 是 epoch 秒,沒有設備時差
    at = datetime(2024, 5, 1, 8, 15, 30, tzinfo=timezone.utc)
    for spec in (FW, IPS):
        ts, _, pairs = _parse(render_one(spec, at=at))
        kv = dict(pairs)
        assert ts == "2024-05-01T08:15:30Z"
        assert kv["time"] == str(int(at.timestamp()))
        assert kv["loguid"].startswith("{0x%x," % int(at.timestamp()))


def test_ips_layout_and_product() -> None:
    for _ in range(30):
        _, host, pairs = _parse(render_one(IPS))
        kv = dict(pairs)
        assert host == "cp-mgmt"
        assert (kv["product"], kv["protection_type"]) == ("SmartDefense", "IPS")
        assert kv["action"] in ("Prevent", "Detect")
        for key in ("attack", "attack_info", "protection_name", "protection_id", "severity",
                    "confidence_level", "performance_impact", "src", "dst", "s_port",
                    "service", "proto", "smartdefense_profile", "session_id"):
            assert kv[key] != "", key


def test_ips_protection_fields_stay_paired() -> None:
    pool = set(IPS.default_params()["protection_pool"])
    for _ in range(60):
        kv = _kv(render_one(IPS))
        entry = "|".join([kv["protection_id"], kv["protection_name"], kv["attack"],
                          kv.get("industry_reference", ""), kv["severity"],
                          kv["confidence_level"], kv["performance_impact"]])
        assert entry in pool
        assert kv["attack_info"] == kv["protection_name"]


def test_ips_industry_reference_is_omitted_when_the_protection_has_no_cve() -> None:
    no_cve = "sig_example_1|Example Scanner|Scanner Enforcement Violation||1|3|1"
    with_cve = "sig_example_2|Example RCE|Web Server Enforcement Violation|CVE-2099-0001|4|5|2"
    assert "industry_reference" not in _kv(render_one(IPS, {"protection_pool": [no_cve]}))
    assert _kv(render_one(IPS, {"protection": with_cve}))["industry_reference"] == "CVE-2099-0001"


def test_ips_rule_conditions_can_be_pinned() -> None:
    params = {"action": "Detect", "src_pool": "198.51.100.5", "dst_pool": "192.0.2.44",
              "protection_pool": ["sig_example_2|Example RCE|Web Server Enforcement "
                                  "Violation|CVE-2099-0001|4|5|2"],
              "svc": "6/8443", "profile": "Strict"}
    for _ in range(10):
        kv = _kv(render_one(IPS, params))
        assert (kv["action"], kv["src"], kv["dst"]) == ("Detect", "198.51.100.5", "192.0.2.44")
        assert (kv["protection_name"], kv["attack"], kv["protection_id"]) == (
            "Example RCE", "Web Server Enforcement Violation", "sig_example_2")
        assert (kv["severity"], kv["confidence_level"], kv["performance_impact"]) == (
            "4", "5", "2")
        assert (kv["proto"], kv["service"], kv["smartdefense_profile"]) == (
            "6", "8443", "Strict")


def test_ips_severity_threshold_can_be_pinned_directly() -> None:
    kv = _kv(render_one(IPS, {"severity": "4", "confidence_level": "5", "action": "Prevent"}))
    assert (kv["severity"], kv["confidence_level"], kv["action"]) == ("4", "5", "Prevent")


def test_ips_emits_both_actions_by_default() -> None:
    seen = {_kv(render_one(IPS))["action"] for _ in range(200)}
    assert seen == {"Prevent", "Detect"}
