"""PAN-OS 管理員驗證、Windows 4625 / 4964、Windows DNS 偵錯紀錄、BIND 查詢紀錄。"""
from __future__ import annotations

import json
import re

from cyberrange import find_spec, load_spec, render_one

PAN = load_spec(find_spec("paloalto", "panos", "10.0", "system.auth.cef"))
W4625 = load_spec(find_spec("microsoft", "windows", "2022", "security.event_id_4625"))
W4964 = load_spec(find_spec("microsoft", "windows", "2022", "security.event_id_4964"))
WDNS = load_spec(find_spec("microsoft", "dns-server", "2022", "dns.debug_log.packet"))
BIND = load_spec(find_spec("isc", "bind", "9.x", "dns.query"))


def _cef(line: str) -> tuple[list[str], str]:
    head = line.split("CEF:", 1)[1].split("|", 7)
    return head[:7], head[7]


def _event_data(line: str) -> dict:
    return json.loads(line[line.index("{"):])["winlog"]["event_data"]


def test_pan_system_header_follows_the_cef_guide_mapping() -> None:
    # Signature ID = subtype、Name = 記錄類型、事件名稱放在 cat
    for outcome, sev, eventid in (("failed", "3", "auth-fail"), ("success", "1", "auth-success")):
        head, ext = _cef(render_one(PAN, {"outcome": outcome}))
        assert head == ["0", "Palo Alto Networks", "PAN-OS", "10.0.0", "auth", "SYSTEM", sev]
        assert f" cat={eventid} " in ext


def test_pan_message_names_the_same_user_and_source_as_the_fields() -> None:
    _, ext = _cef(render_one(PAN, {"outcome": "failed", "user_pool": "netops",
                                   "src_pool": "198.51.100.9"}))
    assert " fname=netops " in ext
    assert ("msg=failed authentication for user 'netops'. Reason: Invalid "
            "username/password. From: 198.51.100.9. ") in ext


def test_pan_subtype_and_module_are_selectable() -> None:
    head, ext = _cef(render_one(PAN, {"subtype": "general", "module": "auth"}))
    assert head[4] == "general" and " flexString2=auth " in ext


def test_4625_failure_codes_stay_consistent() -> None:
    expected = {"bad_password": ("0xc000006d", "0xc000006a", "%%2313"),
                "unknown_user": ("0xc000006d", "0xc0000064", "%%2313"),
                "locked_out": ("0xc0000234", "0x0", "%%2307")}
    for failure, triple in expected.items():
        ed = _event_data(render_one(W4625, {"failure": failure}))
        assert (ed["Status"], ed["SubStatus"], ed["FailureReason"]) == triple


def test_4625_field_order_matches_the_event_schema() -> None:
    assert list(_event_data(render_one(W4625))) == [
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
        "TargetUserSid", "TargetUserName", "TargetDomainName", "Status", "FailureReason",
        "SubStatus", "LogonType", "LogonProcessName", "AuthenticationPackageName",
        "WorkstationName", "TransmittedServices", "LmPackageName", "KeyLength",
        "ProcessId", "ProcessName", "IpAddress", "IpPort"]


def test_4625_spray_shape_can_be_pinned() -> None:
    ed = _event_data(render_one(W4625, {"src_pool": "198.51.100.5", "target_user": "svc_sql",
                                        "logon_type": "10"}))
    assert (ed["IpAddress"], ed["TargetUserName"], ed["LogonType"]) == (
        "198.51.100.5", "svc_sql", "10")


def test_4964_field_order_and_sid_list_format() -> None:
    ed = _event_data(render_one(W4964))
    assert list(ed) == [
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
        "LogonGuid", "TargetUserSid", "TargetUserName", "TargetDomainName",
        "TargetLogonId", "TargetLogonGuid", "SidList"]
    assert ed["SidList"] == "%{S-1-5-21-1111111111-2222222222-3333333333-512}"
    assert re.fullmatch(r"\{[0-9A-F-]{36}\}", ed["LogonGuid"])


def test_4964_same_account_always_has_the_same_sid() -> None:
    sids: dict[str, set[str]] = {}
    for _ in range(120):
        ed = _event_data(render_one(W4964))
        sids.setdefault(ed["TargetUserName"], set()).add(ed["TargetUserSid"])
    assert len(sids) == 3 and all(len(v) == 1 for v in sids.values())
    assert sids["Administrator"].pop().endswith("-500")
    assert len({s for v in sids.values() for s in v}) == 2  # 其餘兩個帳號各不相同


def test_4625_logon_process_and_package_follow_logon_type() -> None:
    for logon_type, process, package in (("3", "NtLmSsp ", "NTLM"), ("10", "User32 ", "Negotiate"),
                                         ("2", "User32 ", "Negotiate"), ("8", "Advapi  ", "Negotiate")):
        ed = _event_data(render_one(W4625, {"logon_type": logon_type}))
        assert (ed["LogonProcessName"], ed["AuthenticationPackageName"]) == (process, package)


def test_json_catalogs_always_emit_valid_json() -> None:
    for spec in (W4625, W4964):
        for _ in range(200):
            _event_data(render_one(spec))


def test_4964_special_group_is_selectable() -> None:
    ed = _event_data(render_one(W4964, {"special_group_rid": "519"}))
    assert ed["SidList"].endswith("-519}")


PACKET = re.compile(
    r"\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d\d:\d\d [AP]M [0-9A-F]{4} PACKET  [0-9A-F]{16} "
    r"(UDP|TCP) (Snd|Rcv) (\S+)\s+([0-9a-f]{4}) (R| ) Q \[([0-9a-f]{4}) ([A ])([T ])([D ])([R ])"
    r"  (\S+)\] (\S+)\s+(\S+)")


def test_windows_dns_query_and_response_lines() -> None:
    q = PACKET.fullmatch(render_one(WDNS, {"direction": "query", "qname_pool": "www.example.com",
                                           "client_pool": "198.51.100.9", "qtype": "A"}))
    assert q and q.group(2, 3, 5, 6, 11, 12, 13) == (
        "Rcv", "198.51.100.9", " ", "0001", "NOERROR", "A", "(3)www(7)example(3)com(0)")
    assert q.group(7, 8, 9, 10) == (" ", " ", "D", " ")

    r = PACKET.fullmatch(render_one(WDNS, {"direction": "response",
                                           "response_rcode": "NXDOMAIN"}))
    assert r and r.group(2, 5, 6, 11) == ("Snd", "R", "8381", "NXDOMAIN")
    assert r.group(7, 8, 9, 10) == (" ", " ", "D", "R")


def test_windows_dns_query_never_carries_an_error_code() -> None:
    line = render_one(WDNS, {"direction": "query", "response_rcode": "NXDOMAIN"})
    assert "[0001   D   NOERROR]" in line


def test_windows_dns_clock_follows_tz() -> None:
    from datetime import datetime, timezone

    at = datetime(2026, 3, 9, 23, 5, 7, tzinfo=timezone.utc)
    assert render_one(WDNS, at=at).startswith("3/9/2026 11:05:07 PM ")
    assert render_one(WDNS, {"tz": "+0800"}, at=at).startswith("3/10/2026 7:05:07 AM ")


def test_bind_query_line_matches_the_manual_layout() -> None:
    line = render_one(BIND, {"client_pool": "198.51.100.9", "qname_pool": "www.example.com",
                             "qtype": "AAAA", "flags": "+E(0)K"})
    assert re.fullmatch(
        r"<30>\w{3} \d\d \d\d:\d\d:\d\d ns1 named\[1234\]: client @0x[0-9a-f]+ "
        r"198\.51\.100\.9#\d+ \(www\.example\.com\): query: www\.example\.com IN AAAA "
        r"\+E\(0\)K \(192\.0\.2\.53\)", line)


def test_bind_older_layout_without_object_id() -> None:
    line = render_one(BIND, {"client_object": ""})
    assert re.search(r"named\[\d+\]: client \d+\.\d+\.\d+\.\d+#\d+ \(", line)
