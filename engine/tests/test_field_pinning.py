"""規則驗證需要「剛好踩中條件」的事件:任何欄位都能用參數釘成固定值,打錯的參數名要報錯。"""
from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from cyberrange import find_spec, load_spec, render_one

FORTI = load_spec(find_spec("fortinet", "fortios", "7.4", "traffic.forward"))
AT = datetime(2026, 1, 2, 20, 30, 0, tzinfo=timezone.utc)


def test_any_field_can_be_pinned_by_name() -> None:
    params = {"dstport": "445", "action": "deny", "srcport": 443}
    lines = [render_one(FORTI, params) for _ in range(30)]
    assert all(" dstport=445 " in l for l in lines)
    assert all(' action="deny" ' in l for l in lines)
    assert all(" srcport=443 " in l for l in lines)


def test_unpinned_fields_keep_their_generators() -> None:
    lines = [render_one(FORTI, {"dstport": "445"}) for _ in range(60)]
    assert len({re.search(r"srcport=(\d+)", l).group(1) for l in lines}) > 1


def test_declared_params_still_work_alongside_pins() -> None:
    line = render_one(FORTI, {"dst_pool": ["203.0.113.66"], "dstport": "8443"})
    assert " dstip=203.0.113.66 dstport=8443 " in line


def test_unknown_param_is_rejected_with_the_valid_names() -> None:
    with pytest.raises(ValueError) as exc:
        render_one(FORTI, {"dst_port": "445"})
    msg = str(exc.value)
    assert "dst_port" in msg and "dstport" in msg and "dst_pool" in msg


def test_fortios_user_is_absent_by_default_and_emitted_when_set() -> None:
    assert " user=" not in render_one(FORTI)
    assert ' user="alice" ' in render_one(FORTI, {"user": "alice"})


def test_fortios_clock_matches_the_declared_tz() -> None:
    utc = render_one(FORTI, at=AT)
    assert 'date=2026-01-02 time=20:30:00 ' in utc and ' tz="+0000" ' in utc
    taipei = render_one(FORTI, {"tz": "+0800"}, at=AT)
    assert 'date=2026-01-03 time=04:30:00 ' in taipei and ' tz="+0800" ' in taipei
    assert taipei.startswith("<189>Jan 03 04:30:00 ")
    # eventtime 是絕對時間,不隨 tz 改變
    assert re.search(r"eventtime=(\d+)", utc).group(1) == re.search(
        r"eventtime=(\d+)", taipei).group(1)


def test_bad_utc_offset_is_rejected() -> None:
    with pytest.raises(ValueError, match="utc_offset"):
        render_one(FORTI, {"tz": "Asia/Taipei"})


def test_cli_rejects_unknown_param_before_sending(capsys) -> None:
    from cyberrange.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["gen", "--vendor", "fortinet", "--product", "fortios", "--version", "7.4",
              "--log-type", "traffic.forward", "--count", "1", "--param", "dst_port=445",
              "--sink", "stdout://"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "dst_port" in captured.err and "Traceback" not in captured.err


@pytest.mark.parametrize("bad", ["Asia/Taipei", "+2500", "+0860", "+08:00", ""])
def test_cli_rejects_bad_tz_without_traceback(bad: str, capsys) -> None:
    from cyberrange.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["gen", "--vendor", "fortinet", "--product", "fortios", "--version", "7.4",
              "--log-type", "traffic.forward", "--count", "1", "--param", f"tz={bad}",
              "--sink", "stdout://"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "utc_offset" in captured.err
    assert "Traceback" not in captured.err


def test_clock_follows_tz_when_at_is_not_utc() -> None:
    from datetime import timedelta

    at = datetime(2026, 1, 3, 4, 30, 0, tzinfo=timezone(timedelta(hours=8)))  # 同一瞬間
    assert 'date=2026-01-02 time=20:30:00 ' in render_one(FORTI, at=at)
    assert 'date=2026-01-02 time=15:00:00 ' in render_one(FORTI, {"tz": "-0530"}, at=at)


def test_declared_param_wins_over_a_same_named_field() -> None:
    # devname 同時是 param 與欄位:值經由 param 流進所有引用它的地方(syslog 主機名與 devname=)
    line = render_one(FORTI, {"devname": "FGT-EDGE-01"})
    assert " FGT-EDGE-01 date=" in line and ' devname="FGT-EDGE-01" ' in line
