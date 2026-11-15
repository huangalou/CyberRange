"""Junos RT_FLOW 連線紀錄與 SonicWall 防火牆 syslog:驅動欄位切換訊息種類,衍生欄位要跟著一致。"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from cyberrange import find_spec, load_spec, render_one

JUNOS = load_spec(find_spec("juniper", "junos", "21.x", "rt_flow.session"))
SONIC = load_spec(find_spec("sonicwall", "sonicos", "7.x", "firewall.syslog"))

AT = datetime(2026, 3, 1, 23, 30, 0, tzinfo=timezone.utc)

JUNOS_HEAD = re.compile(
    r"^<14>1 \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} srx-edge-01 RT_FLOW - "
    r"(RT_FLOW_SESSION_(?:CREATE|CLOSE|DENY)) \[junos@2636\.1\.1\.1\.2\.129 (.*)\]$")


def _junos(line: str) -> tuple[str, dict[str, str]]:
    m = JUNOS_HEAD.match(line)
    assert m, line
    pairs = re.findall(r'([a-z0-9-]+)="([^"]*)"', m.group(2))
    # 結構化資料區塊裡只能有 key="value",不能有殘留的樣板文字或重複的鍵
    assert " ".join(f'{k}="{v}"' for k, v in pairs) == m.group(2)
    assert len({k for k, _ in pairs}) == len(pairs)
    return m.group(1), dict(pairs)


def _sonic(line: str) -> tuple[str, dict[str, str]]:
    m = re.match(r"^<(\d+)>(id=firewall sn=\S+ time=\"[^\"]+\" fw=\S+ .*)$", line)
    assert m, line
    pairs = re.findall(r'(\w+)=("[^"]*"|\S+)', m.group(2))
    assert " ".join(f"{k}={v}" for k, v in pairs) == m.group(2)
    return m.group(1), {k: v.strip('"') for k, v in pairs}


# ---------------------------------------------------------------- Junos RT_FLOW

def test_junos_event_selects_tag_and_field_set() -> None:
    nat = {"nat-source-address", "nat-source-port", "nat-destination-address",
           "nat-destination-port", "src-nat-rule-name", "dst-nat-rule-name"}
    counters = {"packets-from-client", "bytes-from-client", "packets-from-server",
                "bytes-from-server", "elapsed-time"}
    for _ in range(20):
        tag, sd = _junos(render_one(JUNOS, {"event": "create"}))
        assert tag == "RT_FLOW_SESSION_CREATE"
        assert nat <= set(sd) and not counters & set(sd) and "reason" not in sd

        tag, sd = _junos(render_one(JUNOS, {"event": "close"}))
        assert tag == "RT_FLOW_SESSION_CLOSE"
        assert nat <= set(sd) and counters <= set(sd)
        assert list(sd)[0] == "reason"  # CLOSE 的 reason 排在最前面

        tag, sd = _junos(render_one(JUNOS, {"event": "deny"}))
        assert tag == "RT_FLOW_SESSION_DENY"
        assert not nat & set(sd) and not counters & set(sd)
        assert sd["reason"] == "Denied by policy" and "icmp-type" in sd


def test_junos_create_key_order_follows_the_vendor_sample() -> None:
    _, sd = _junos(render_one(JUNOS, {"event": "create"}))
    assert list(sd)[:19] == [
        "source-address", "source-port", "destination-address", "destination-port",
        "connection-tag", "service-name", "nat-source-address", "nat-source-port",
        "nat-destination-address", "nat-destination-port", "nat-connection-tag",
        "src-nat-rule-type", "src-nat-rule-name", "dst-nat-rule-type", "dst-nat-rule-name",
        "protocol-id", "policy-name", "source-zone-name", "destination-zone-name"]


def test_junos_policy_follows_event() -> None:
    params = JUNOS.default_params()
    for _ in range(30):
        _, sd = _junos(render_one(JUNOS, {"event": "deny"}))
        assert sd["policy-name"] in params["deny_policy_pool"]
        _, sd = _junos(render_one(JUNOS, {"event": "create"}))
        assert sd["policy-name"] in params["permit_policy_pool"]


def test_junos_service_and_protocol_follow_destination_port() -> None:
    expected = {"443": ("6", "junos-https"), "80": ("6", "junos-http"),
                "53": ("17", "junos-dns-udp"), "22": ("6", "junos-ssh"),
                "25": ("6", "junos-smtp"), "3389": ("6", "junos-ms-rdp")}
    for _ in range(80):
        _, sd = _junos(render_one(JUNOS))
        assert (sd["protocol-id"], sd["service-name"]) == expected[sd["destination-port"]]
    # 沒有預先定義應用程式的埠、以及另外釘住協定的情況
    _, sd = _junos(render_one(JUNOS, {"dst_port": "8443"}))
    assert (sd["protocol-id"], sd["service-name"]) == ("6", "None")
    _, sd = _junos(render_one(JUNOS, {"dst_port": "53", "protocol_id": "6"}))
    assert sd["service-name"] == "junos-dns-tcp"


def test_junos_close_reason_matches_protocol_and_counters_add_up() -> None:
    for _ in range(60):
        _, sd = _junos(render_one(JUNOS, {"event": "close"}))
        if sd["protocol-id"] == "6":
            assert sd["reason"] in ("TCP FIN", "TCP RST", "idle Timeout")
        else:
            assert sd["reason"] in ("idle Timeout", "response received")
        for side in ("client", "server"):
            packets, size = int(sd[f"packets-from-{side}"]), int(sd[f"bytes-from-{side}"])
            assert 60 * packets <= size <= 1400 * packets


def test_junos_nat_fields_repeat_the_tuple_unless_source_nat_is_set() -> None:
    _, sd = _junos(render_one(JUNOS, {"event": "create"}))
    assert (sd["nat-source-address"], sd["nat-source-port"]) == (
        sd["source-address"], sd["source-port"])
    assert (sd["src-nat-rule-type"], sd["src-nat-rule-name"]) == ("N/A", "N/A")

    _, sd = _junos(render_one(JUNOS, {"event": "close", "nat_src_ip": "203.0.113.10"}))
    assert sd["nat-source-address"] == "203.0.113.10" != sd["source-address"]
    assert (sd["src-nat-rule-type"], sd["src-nat-rule-name"]) == ("source rule", "src-nat-rule1")
    assert (sd["nat-destination-address"], sd["nat-destination-port"]) == (
        sd["destination-address"], sd["destination-port"])


def test_junos_rule_conditions_can_be_pinned() -> None:
    params = {"event": "deny", "src_pool": "198.51.100.5", "src_port": "40000",
              "dst_pool": "192.0.2.44", "dst_port": "22", "policy_name": "block-ssh",
              "src_zone": "dmz", "dst_zone": "mgmt", "user": "netops"}
    for _ in range(10):
        tag, sd = _junos(render_one(JUNOS, params))
        assert tag == "RT_FLOW_SESSION_DENY"
        assert (sd["source-address"], sd["source-port"], sd["destination-address"],
                sd["destination-port"]) == ("198.51.100.5", "40000", "192.0.2.44", "22")
        assert (sd["service-name"], sd["protocol-id"], sd["policy-name"]) == (
            "junos-ssh", "6", "block-ssh")
        assert (sd["source-zone-name"], sd["destination-zone-name"], sd["username"]) == (
            "dmz", "mgmt", "netops")


def test_junos_timestamp_follows_tz() -> None:
    assert render_one(JUNOS, at=AT).startswith("<14>1 2026-03-01T23:30:00 srx-edge-01 ")
    assert render_one(JUNOS, {"tz": "+0800"}, at=AT).startswith("<14>1 2026-03-02T07:30:00 ")


# ---------------------------------------------------------------- SonicWall

def test_sonic_event_selects_id_message_priority_and_action() -> None:
    expected = {"98": ("Connection Opened", "6", "262144", "NA", "134"),
                "537": ("Connection Closed", "6", "1024", "NA", "134"),
                "36": ("TCP connection dropped", "5", "64", "drop", "133"),
                "37": ("UDP packet dropped", "5", "128", "drop", "133")}
    allowed = {"opened": {"98"}, "closed": {"537"}, "dropped": {"36", "37"}}
    for event, ids in allowed.items():
        for _ in range(30):
            pri, kv = _sonic(render_one(SONIC, {"event": event}))
            assert kv["m"] in ids
            assert (kv["msg"], kv["pri"], kv["c"], kv["fw_action"], pri) == expected[kv["m"]]


def test_sonic_counters_only_on_connection_closed() -> None:
    counters = {"rcvd", "spkt", "rpkt", "dpi", "cdur"}
    _, kv = _sonic(render_one(SONIC, {"event": "closed"}))
    assert counters <= set(kv)
    assert 60 * int(kv["spkt"]) <= int(kv["sent"]) <= 600 * int(kv["spkt"])
    assert 60 * int(kv["rpkt"]) <= int(kv["rcvd"]) <= 1400 * int(kv["rpkt"])
    for event in ("opened", "dropped"):
        _, kv = _sonic(render_one(SONIC, {"event": event}))
        assert not counters & set(kv)


def test_sonic_tag_order_of_connection_closed() -> None:
    _, kv = _sonic(render_one(SONIC, {"event": "closed"}))
    assert list(kv) == ["id", "sn", "time", "fw", "pri", "c", "m", "msg", "n", "src", "dst",
                        "srcMac", "dstMac", "proto", "sent", "rcvd", "spkt", "rpkt", "dpi",
                        "cdur", "rule", "fw_action"]


def test_sonic_proto_and_drop_message_follow_destination_port() -> None:
    expected = {"443": "tcp/https", "80": "tcp/http", "53": "udp/dns", "22": "tcp/ssh",
                "25": "tcp/smtp", "3389": "tcp/3389"}
    for _ in range(80):
        _, kv = _sonic(render_one(SONIC, {"event": "dropped"}))
        port = kv["dst"].split(":")[1]
        assert kv["proto"] == expected[port]
        assert kv["m"] == ("37" if kv["proto"].startswith("udp/") else "36")
    # 另外釘住協定:任意埠的 UDP 丟棄
    _, kv = _sonic(render_one(SONIC, {"event": "dropped", "dst_port": "5060",
                                      "protocol": "udp"}))
    assert (kv["m"], kv["msg"], kv["proto"]) == ("37", "UDP packet dropped", "udp/5060")


def test_sonic_rule_conditions_can_be_pinned() -> None:
    params = {"event": "dropped", "src_pool": "198.51.100.5", "src_port": "40000",
              "src_iface": "X1", "dst_pool": "192.0.2.44", "dst_port": "22",
              "dst_iface": "X0", "rule": "12 (WAN->LAN)", "fw_ip": "203.0.113.200"}
    for _ in range(10):
        _, kv = _sonic(render_one(SONIC, params))
        assert (kv["src"], kv["dst"]) == ("198.51.100.5:40000:X1", "192.0.2.44:22:X0")
        assert (kv["m"], kv["proto"], kv["fw_action"]) == ("36", "tcp/ssh", "drop")
        assert (kv["rule"], kv["fw"]) == ("12 (WAN->LAN)", "203.0.113.200")
    # 動作欄位本身也能直接釘住(設備若在連線事件回報 forward)
    _, kv = _sonic(render_one(SONIC, {"event": "opened", "fw_action": "forward"}))
    assert (kv["m"], kv["fw_action"]) == ("98", "forward")


def test_sonic_time_follows_tz() -> None:
    assert ' time="2026-03-01 23:30:00" ' in render_one(SONIC, at=AT)
    assert ' time="2026-03-02 07:30:00" ' in render_one(SONIC, {"tz": "+0800"}, at=AT)


def test_default_addresses_are_documentation_ranges() -> None:
    doc = re.compile(r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$")
    for spec in (JUNOS, SONIC):
        for _ in range(30):
            line = render_one(spec)
            for ip in re.findall(r"\d+\.\d+\.\d+\.\d+", line.replace("2636.1.1.1.2.129", "")):
                assert doc.match(ip) or ip == "0.0.0.0", (ip, line)
