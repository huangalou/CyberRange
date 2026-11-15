"""Sophos Firewall 流量紀錄與 TippingPoint SMS IPS 事件:版面、驅動欄位的一致性、規則欄位可指定、時差。"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from cyberrange import find_spec, load_spec, render_one

SFW = load_spec(find_spec("sophos", "firewall", "19.x", "firewall.traffic"))
SMS = load_spec(find_spec("trendmicro", "tippingpoint-sms", "5.x", "ips.alert"))

AT = datetime(2026, 3, 9, 23, 5, 7, tzinfo=timezone.utc)
SMS_COLUMNS = 21


def _kv(line: str) -> dict[str, str]:
    return {k: v.strip('"') for k, v in re.findall(r'(\w+)=("[^"]*"|\S*)', line)}


def _cols(line: str) -> list[str]:
    """去掉 `<PRI>時間 主機 ` 標頭後,以 TAB 切出各欄。"""
    m = re.match(r"<\d+>\w{3} \d{2} \d{2}:\d{2}:\d{2} \S+ (.*)$", line, re.S)
    assert m, line
    return m.group(1).split("\t")


# ---------------------------------------------------------------- Sophos Firewall
def test_sfw_line_is_a_firewall_rule_log() -> None:
    line = render_one(SFW)
    assert re.match(r'<30>device="SFW" date=\d{4}-\d{2}-\d{2} time=\d{2}:\d{2}:\d{2} timezone="GMT" ', line)
    kv = _kv(line)
    assert (kv["log_type"], kv["log_component"]) == ("Firewall", "Firewall Rule")
    assert line.endswith(" log_occurrence=1") and "\n" not in line


def test_sfw_allowed_fields_follow_the_driver() -> None:
    for _ in range(40):
        line = render_one(SFW, {"action": "Allowed"})
        kv = _kv(line)
        assert (kv["log_id"], kv["log_subtype"], kv["status"]) == ("010101600001", "Allowed", "Allow")
        assert kv["nat_rule_id"] == "2" and kv["tran_src_ip"] == SFW.default_params()["nat_ip"]
        assert kv["connevent"] in ("Start", "Stop") and kv["connid"].isdigit()
        if kv["connevent"] == "Start":
            assert (kv["duration"], kv["sent_bytes"], kv["recv_bytes"]) == ("0", "0", "0")
        else:
            assert int(kv["duration"]) > 0 and int(kv["sent_bytes"]) > 0


def test_sfw_denied_fields_follow_the_driver() -> None:
    for _ in range(40):
        line = render_one(SFW, {"action": "Denied"})
        kv = _kv(line)
        assert (kv["log_id"], kv["log_subtype"], kv["status"]) == ("010102600002", "Denied", "Deny")
        assert (kv["nat_rule_id"], kv["tran_src_ip"], kv["tran_src_port"]) == ("0", "", "0")
        assert (kv["duration"], kv["sent_pkts"], kv["recv_pkts"], kv["sent_bytes"], kv["recv_bytes"]) == ("0",) * 5
        assert kv["connid"] == "" and "connevent=" not in line


def test_sfw_emits_both_verdicts_by_default() -> None:
    seen = {_kv(render_one(SFW))["log_subtype"] for _ in range(200)}
    assert seen == {"Allowed", "Denied"}


def test_sfw_port_fields_follow_protocol() -> None:
    tcp = render_one(SFW, {"protocol": "TCP", "src_port": 40001, "dst_port": 3389})
    assert ' protocol="TCP" src_port=40001 dst_port=3389 sent_pkts=' in tcp and "icmp_type=" not in tcp
    icmp = render_one(SFW, {"protocol": "ICMP", "action": "Allowed"})
    assert ' protocol="ICMP" icmp_type=8 icmp_code=0 sent_pkts=' in icmp
    # tran_src_port 仍在,但不得出現獨立的 src_port / dst_port 鍵
    assert " src_port=" not in icmp and " dst_port=" not in icmp
    assert _kv(icmp)["tran_src_port"] == "0"


def test_sfw_rule_conditions_can_be_pinned() -> None:
    params = {"action": "Denied", "src_pool": "192.0.2.5", "dst_pool": "198.51.100.44",
              "protocol": "TCP", "dst_port": 22, "fw_rule_id": 9, "user_pool": "svc-backup",
              "in_interface": "Port5", "out_interface": "Port6",
              "src_zone": "DMZ", "dst_zone": "VPN"}
    for _ in range(10):
        kv = _kv(render_one(SFW, params))
        assert (kv["src_ip"], kv["dst_ip"], kv["dst_port"], kv["fw_rule_id"]) == (
            "192.0.2.5", "198.51.100.44", "22", "9")
        assert (kv["user_name"], kv["user_gp"]) == ("svc-backup", "Open Group")
        assert (kv["in_interface"], kv["out_interface"]) == ("Port5", "Port6")
        assert (kv["srczone"], kv["dstzone"], kv["status"]) == ("DMZ", "VPN", "Deny")


def test_sfw_user_group_is_empty_without_user() -> None:
    kv = _kv(render_one(SFW, {"user_pool": ""}))
    assert (kv["user_name"], kv["user_gp"]) == ("", "")


def test_sfw_clock_follows_tz() -> None:
    assert ' date=2026-03-09 time=23:05:07 timezone="GMT" ' in render_one(SFW, at=AT)
    line = render_one(SFW, {"tz": "+0800", "tz_name": "CST"}, at=AT)
    assert ' date=2026-03-10 time=07:05:07 timezone="CST" ' in line


# ---------------------------------------------------------------- TippingPoint SMS
def test_sms_line_has_header_and_21_tab_columns() -> None:
    line = render_one(SMS, at=AT)
    assert line.startswith("<32>Mar 09 23:05:07 sms01 ")
    cols = _cols(line)
    assert len(cols) == SMS_COLUMNS
    assert cols[18] == str(int(AT.timestamp() * 1000))          # 事件時間:epoch 毫秒
    assert (cols[11], cols[12], cols[13], cols[16], cols[19]) == ("1", "1A", "1B", "ips01", "")
    assert cols[20].isdigit()


def test_sms_action_and_severity_codes_follow_their_drivers() -> None:
    for action, code in (("Permit", "7"), ("Block", "8"), ("P2P", "9"), ("Quarantine", "12")):
        assert _cols(render_one(SMS, {"action": action}))[0] == code
    for sev, code in (("Normal", "0"), ("Low", "1"), ("Minor", "2"), ("Major", "3"), ("Critical", "4")):
        assert _cols(render_one(SMS, {"severity": sev}))[1] == code


def test_sms_default_mix_only_uses_documented_codes() -> None:
    seen = {tuple(_cols(render_one(SMS))[:2]) for _ in range(200)}
    assert {a for a, _ in seen} == {"7", "8"}
    assert {s for _, s in seen} <= {"1", "2", "3", "4"}


def test_sms_filter_number_name_protocol_and_uuids_stay_paired() -> None:
    pool = SMS.default_params()["signature_pool"]
    for _ in range(40):
        cols = _cols(render_one(SMS))
        number, proto = cols[5], cols[6]
        prefix, name = cols[4].split(": ", 1)
        assert f"{number}:{proto}:{name}" in pool
        assert prefix == f"{int(number):04d}"
        assert cols[2] == f"00000002-0002-0002-0002-{int(number):012d}"
        assert cols[3] == f"00000001-0001-0001-0001-{int(number):012d}"


def test_sms_rule_conditions_can_be_pinned() -> None:
    params = {"action": "Block", "severity": "Critical",
              "signature_pool": ["90001:tcp:EXAMPLE: Test Filter Name"],
              "src_pool": "198.51.100.5", "dst_pool": "192.0.2.44",
              "src_port": 40001, "dst_port": 8443, "vlan_id": 120, "device_name": "tps-edge-1"}
    for _ in range(10):
        cols = _cols(render_one(SMS, params))
        assert cols[:2] == ["8", "4"]
        assert cols[4:11] == ["90001: EXAMPLE: Test Filter Name", "90001", "tcp",
                              "198.51.100.5", "40001", "192.0.2.44", "8443"]
        assert (cols[15], cols[16]) == ("120", "tps-edge-1")


def test_sms_protocol_can_be_pinned_on_its_own() -> None:
    assert _cols(render_one(SMS, {"protocol": "udp"}))[6] == "udp"


def test_sms_header_clock_follows_tz_but_event_time_does_not() -> None:
    line = render_one(SMS, {"tz": "+0800"}, at=AT)
    assert line.startswith("<32>Mar 10 07:05:07 sms01 ")
    assert _cols(line)[18] == str(int(AT.timestamp() * 1000))


def test_sms_header_none_and_other_delimiter() -> None:
    bare = render_one(SMS, {"header": "none"})
    assert re.match(r"<32>\t[78]\t\d\t", bare) and len(bare.split("\t")) == SMS_COLUMNS + 1
    piped = render_one(SMS, {"delimiter": "|", "comment": "note"})
    cols = piped.split(" ", 4)[4].split("|")
    assert len(cols) == SMS_COLUMNS and cols[19] == "note" and "\t" not in piped


def test_sophos_destination_port_follows_the_protocol() -> None:
    for _ in range(400):
        kv = _kv(render_one(SFW))
        if kv["protocol"] == "UDP":
            assert kv["dst_port"] in ("53", "123")
        elif kv["protocol"] == "TCP":
            assert kv["dst_port"] in ("443", "80", "22", "3389")
