"""Radware DefensePro 攻擊事件、F5 APM 存取政策紀錄、Pulse Connect Secure 使用者登入紀錄。

規則條件會用到的欄位要能指定;由驅動欄位帶動的衍生欄位要跟著一致。
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from cyberrange import find_spec, load_spec, render_one

DP = load_spec(find_spec("radware", "defensepro", "8.x", "security.attack_event"))
APM = load_spec(find_spec("f5", "apm", "16.x", "apm.access_policy"))
PCS = load_spec(find_spec("pulsesecure", "connect-secure", "9.x", "vpn.user_access"))

AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

# 攻擊代碼 類別 "名稱" 協定 來源 埠 目的 埠 實體埠 情境 "政策" 狀態 封包數 頻寬
# VLAN MPLS-RD MPLS-tag 風險 動作 唯一識別碼
DP_RE = re.compile(
    r'<172>\w{3} \d{2} \d{2}:\d{2}:\d{2} (?P<device>\S+) DefensePro: '
    r'(?P<ts>\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}) WARNING '
    r'(?P<id>\d+) (?P<category>\S+) "(?P<name>[^"]+)" (?P<proto>\S+) '
    r'(?P<src>\S+) (?P<sport>\d+) (?P<dst>\S+) (?P<dport>\d+) (?P<phys>\d+) '
    r'(?P<context>\S+) "(?P<policy>[^"]+)" (?P<status>\S+) (?P<packets>\d+) '
    r'(?P<bandwidth>\d+) (?P<vlan>\S+) (?P<rd>\S+) (?P<tag>\S+) '
    r'(?P<risk>\S+) (?P<action>\S+) (?P<uid>[0-9A-F-]+)')

APM_RE = re.compile(
    r'<(?P<pri>\d+)>\w{3} \d{2} \d{2}:\d{2}:\d{2} (?P<host>\S+) (?P<level>\w+) '
    r'(?P<proc>\w+)\[(?P<pid>\d+)\]: (?P<code>\d{8}):(?P<num>\d): '
    r'/(?P<partition>\w+)/(?P<profile>[^:]+):(?P=partition):(?P<sid>[0-9a-f]{8}): (?P<text>.*)')

PCS_HEAD = r'<134>1 (?P<hts>\S+) (?P<appliance>\S+) PulseSecure: - - - '
PCS_STD_RE = re.compile(
    PCS_HEAD + r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (?P<node>\S+) - '
    r'\[(?P<src>[^\]]+)\] (?P<user>[^(]+)\((?P<realm>[^)]*)\)\[(?P<roles>[^\]]*)\] - (?P<msg>.*)')


def _m(rx: re.Pattern, line: str) -> dict[str, str]:
    m = rx.fullmatch(line)
    assert m, line
    return m.groupdict()


def _welf(line: str) -> dict[str, str]:
    body = line.split("PulseSecure: - - - ", 1)[1]
    return {k: v.strip('"') for k, v in re.findall(r'(\w+)=("[^"]*"|\S*)', body)}


# ---------------------------------------------------------------- DefensePro
def test_defensepro_line_follows_the_security_event_layout() -> None:
    for _ in range(40):
        f = _m(DP_RE, render_one(DP))
        assert (f["context"], f["vlan"], f["rd"], f["tag"]) == ("Regular", "N/A", "0", "N/A")
        assert re.fullmatch(r"FFFFFFFF-FFFF-FFFF-[0-9A-F]{4}-0000[0-9A-F]{8}", f["uid"])


def test_defensepro_attack_id_category_protocol_and_name_stay_paired() -> None:
    pool = set(DP.default_params()["attack_pool"])
    seen = set()
    for _ in range(120):
        f = _m(DP_RE, render_one(DP))
        entry = f'{f["id"]}:{f["category"]}:{f["proto"]}:{f["name"]}'
        assert entry in pool
        seen.add(entry)
    assert len(seen) > 1


def test_defensepro_rule_conditions_can_be_pinned() -> None:
    params = {"attack_pool": "90001:Intrusions:TCP:Example Signature: name with colon",
              "action": "drop", "risk": "high", "status": "start",
              "src_pool": "198.51.100.5", "src_port": "40000",
              "dst_pool": "192.0.2.44", "dst_port": "8443",
              "policy_pool": "edge-policy", "packet_count": "1234"}
    for _ in range(10):
        f = _m(DP_RE, render_one(DP, params))
        assert (f["id"], f["category"], f["proto"], f["name"]) == (
            "90001", "Intrusions", "TCP", "Example Signature: name with colon")
        assert (f["src"], f["sport"], f["dst"], f["dport"]) == (
            "198.51.100.5", "40000", "192.0.2.44", "8443")
        assert (f["action"], f["risk"], f["status"], f["policy"], f["packets"]) == (
            "drop", "high", "start", "edge-policy", "1234")


def test_defensepro_timestamps_follow_the_device_offset() -> None:
    utc = render_one(DP, at=AT)
    assert utc.startswith("<172>Jan 02 03:04:05 192.0.2.20 DefensePro: 02-01-2026 03:04:05 ")
    local = render_one(DP, {"tz": "+0800"}, at=AT)
    assert local.startswith("<172>Jan 02 11:04:05 192.0.2.20 DefensePro: 02-01-2026 11:04:05 ")
    # 唯一識別碼後半是事件時間的十六進位 epoch,不受時差影響
    assert _m(DP_RE, local)["uid"].endswith("%08X" % int(AT.timestamp()))


# ---------------------------------------------------------------- F5 APM
def test_apm_default_line_is_the_authentication_result() -> None:
    for _ in range(40):
        f = _m(APM_RE, render_one(APM))
        assert (f["pri"], f["level"], f["proc"], f["code"], f["num"]) == (
            "142", "info", "apmd", "01490017", "6")
        assert (f["partition"], f["profile"]) == ("Common", "vpn_access")
        assert re.fullmatch(
            r"AD agent: Auth \(logon attempt:0\): authenticate with '\w+' (successful|failed)",
            f["text"])


def test_apm_outcome_drives_the_result_text() -> None:
    expected = {
        ("auth_result", "success"): "AD agent: Auth (logon attempt:0): authenticate with 'alice' successful",
        ("auth_result", "failed"): "AD agent: Auth (logon attempt:0): authenticate with 'alice' failed",
        ("policy_result", "success"): "Access policy result: Network_Access",
        ("policy_result", "failed"): "Access policy result: Logon_Deny",
    }
    for (message, outcome), text in expected.items():
        f = _m(APM_RE, render_one(APM, {"message": message, "outcome": outcome,
                                        "user_pool": "alice"}))
        assert f["text"] == text


def test_apm_message_drives_process_level_and_log_id() -> None:
    expected = {"auth_result": ("142", "info", "apmd", "5444", "01490017", "6"),
                "policy_result": ("141", "notice", "apmd", "5444", "01490102", "5"),
                "new_session": ("141", "notice", "tmm", "20316", "01490500", "5"),
                "username": ("141", "notice", "apmd", "5444", "01490010", "5")}
    for message, head in expected.items():
        for outcome in ("success", "failed"):
            f = _m(APM_RE, render_one(APM, {"message": message, "outcome": outcome}))
            assert (f["pri"], f["level"], f["proc"], f["pid"], f["code"], f["num"]) == head


def test_apm_session_user_and_source_are_shared_across_the_lines_of_one_logon() -> None:
    # 同一次登入的各行靠釘住 session_id / 使用者 / 來源位址串起來
    pins = {"session_id": "8a1b2c3d", "user_pool": "alice", "src_pool": "198.51.100.5",
            "access_profile": "partner_portal", "outcome": "failed"}
    lines = {m: _m(APM_RE, render_one(APM, {**pins, "message": m}))
             for m in ("new_session", "username", "auth_result", "policy_result")}
    assert {f["sid"] for f in lines.values()} == {"8a1b2c3d"}
    assert {f["profile"] for f in lines.values()} == {"partner_portal"}
    assert lines["new_session"]["text"] == (
        "New session from client IP 198.51.100.5 (ST=/CC=/C=) at VIP 192.0.2.10 "
        "Listener /Common/vs_vpn_https (Reputation=Unknown)")
    assert lines["username"]["text"] == "Username 'alice'"
    assert lines["auth_result"]["text"].endswith("authenticate with 'alice' failed")
    assert lines["policy_result"]["text"] == "Access policy result: Logon_Deny"


def test_apm_session_id_is_random_per_record_unless_pinned() -> None:
    assert len({_m(APM_RE, render_one(APM))["sid"] for _ in range(20)}) > 1


def test_apm_timestamp_follows_the_device_offset() -> None:
    assert render_one(APM, at=AT).startswith("<142>Jan 02 03:04:05 bigip1 info apmd[5444]: ")
    assert render_one(APM, {"tz": "-0500"}, at=AT).startswith("<142>Jan 01 22:04:05 bigip1 ")


# ---------------------------------------------------------------- Pulse Connect Secure
def test_pcs_standard_login_success_and_failure() -> None:
    ok = _m(PCS_STD_RE, render_one(PCS, {"outcome": "success", "user_pool": "alice",
                                         "src_pool": "198.51.100.23"}))
    assert (ok["node"], ok["src"], ok["user"], ok["realm"], ok["roles"]) == (
        "ive", "198.51.100.23", "alice", "Users", "Staff")
    assert re.fullmatch(
        r"Login succeeded for alice/Users \(session:[0-9a-f]{8}\) from 198\.51\.100\.23 "
        r"with Mozilla/5\.0 .*\.", ok["msg"])

    bad = _m(PCS_STD_RE, render_one(PCS, {"outcome": "failed", "user_pool": "alice"}))
    assert (bad["user"], bad["realm"], bad["roles"]) == ("alice", "Users", "")
    assert bad["msg"] == ("Login failed using auth server System Local "
                          "(Local Authentication). Reason: Failed")


def test_pcs_welf_carries_message_id_and_the_same_values_as_the_message() -> None:
    expected = {("login", "success"): "AUT31504", ("login", "failed"): "AUT23457",
                ("primary_auth", "success"): "AUT24326", ("primary_auth", "failed"): "AUT24327"}
    for (event, outcome), msg_id in expected.items():
        for _ in range(10):
            line = render_one(PCS, {"log_filter": "welf", "event": event, "outcome": outcome})
            kv = _welf(line)
            assert list(kv) == ["id", "time", "pri", "fw", "vpn", "user", "realm", "roles",
                                "proto", "src", "dst", "dstname", "type", "op", "arg",
                                "result", "sent", "rcvd", "agent", "duration", "msg"]
            assert (kv["id"], kv["pri"], kv["vpn"], kv["proto"], kv["type"]) == (
                "firewall", "6", "ive", "auth", "vpn")
            assert kv["msg"].startswith(msg_id + ": ")
            signed_in = (event, outcome) == ("login", "success")
            assert (kv["roles"] == "Staff") is signed_in
            assert (kv["agent"] != "") is signed_in
            if event == "primary_auth" or signed_in:
                # 訊息本文裡的使用者與來源位址和欄位一致
                assert f' for {kv["user"]}/' in kv["msg"]
                assert f' from {kv["src"]}' in kv["msg"]


def test_pcs_primary_auth_messages() -> None:
    ok = _m(PCS_STD_RE, render_one(PCS, {"event": "primary_auth", "outcome": "success",
                                         "user_pool": "bob", "src_pool": "203.0.113.9"}))
    assert ok["msg"] == "Primary authentication successful for bob/System Local from 203.0.113.9"
    bad = _m(PCS_STD_RE, render_one(PCS, {"event": "primary_auth", "outcome": "failed",
                                          "user_pool": "bob", "src_pool": "203.0.113.9"}))
    assert bad["msg"] == "Primary authentication failed for bob/System Local from 203.0.113.9"
    assert ok["roles"] == bad["roles"] == ""


def test_pcs_user_realm_role_and_source_can_be_pinned() -> None:
    params = {"outcome": "success", "user_pool": "dave", "realm": "Contractors",
              "roles": "Contractor-Limited", "src_pool": "198.51.100.200", "node": "vpn-a"}
    for log_filter in ("standard", "welf"):
        line = render_one(PCS, {**params, "log_filter": log_filter})
        assert "Login succeeded for dave/Contractors (session:" in line
        assert " from 198.51.100.200 with " in line
        if log_filter == "standard":
            assert " - vpn-a - [198.51.100.200] dave(Contractors)[Contractor-Limited] - " in line
        else:
            kv = _welf(line)
            assert (kv["vpn"], kv["user"], kv["realm"], kv["roles"], kv["src"]) == (
                "vpn-a", "dave", "Contractors", "Contractor-Limited", "198.51.100.200")


def test_pcs_default_run_emits_login_pair_only() -> None:
    msgs = {_m(PCS_STD_RE, render_one(PCS))["msg"].split(" ", 2)[1] for _ in range(60)}
    assert msgs == {"succeeded", "failed"}


def test_pcs_header_and_inner_time_follow_the_appliance_offset() -> None:
    utc = render_one(PCS, at=AT)
    assert utc.startswith("<134>1 2026-01-02T03:04:05+00:00 192.0.2.30 PulseSecure: - - - "
                          "2026-01-02 03:04:05 - ive - ")
    local = render_one(PCS, {"tz": "+0530", "log_filter": "welf"}, at=AT)
    assert local.startswith("<134>1 2026-01-02T08:34:05+05:30 192.0.2.30 PulseSecure: - - - "
                            'id=firewall time="2026-01-02 08:34:05" pri=6 ')


def test_defensepro_port_and_policy_follow_the_attack_protocol() -> None:
    for _ in range(300):
        f = _m(DP_RE, render_one(DP))
        if f["proto"] == "UDP":
            assert (f["dport"], f["policy"]) == ("53", "dns-servers")
        else:
            assert f["dport"] in ("80", "443") and f["policy"] == "dmz-web"


def test_defensepro_counters_are_zero_at_attack_start() -> None:
    for _ in range(20):
        f = _m(DP_RE, render_one(DP, {"status": "start"}))
        assert (f["packets"], f["bandwidth"]) == ("0", "0")
    f = _m(DP_RE, render_one(DP, {"status": "ongoing"}))
    assert int(f["packets"]) > 0 and int(f["bandwidth"]) > 0
