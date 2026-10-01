"""時間模型軸:schedule 產生器、duration/burst 解析、emit 迴圈。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cyberrange.timing import burst, emit, parse_burst, parse_duration, uniform

T0 = datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("text", "expected"),
    [("120", 120.0), ("120s", 120.0), ("2m", 120.0), ("0.5s", 0.5), ("1h", 3600.0)],
)
def test_parse_duration_accepts(text: str, expected: float) -> None:
    assert parse_duration(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "-1s", "2d", "1.2.3s", "s"])
def test_parse_duration_rejects(text: str) -> None:
    with pytest.raises(ValueError, match="invalid duration"):
        parse_duration(text)


def test_parse_burst_ok() -> None:
    assert parse_burst("8/120s") == (8, 120.0)
    assert parse_burst("3/2m") == (3, 120.0)


@pytest.mark.parametrize("text", ["8", "8/", "/120s", "x/120s", "-1/120s", "0/120s", "8/0s"])
def test_parse_burst_rejects(text: str) -> None:
    with pytest.raises(ValueError):
        parse_burst(text)


def test_uniform_offsets() -> None:
    assert list(uniform(4, 2.0)) == [0.0, 0.5, 1.0, 1.5]


def test_uniform_rate_zero_is_all_zero() -> None:
    assert list(uniform(3, 0.0)) == [0.0, 0.0, 0.0]


def test_burst_single_group_spreads_within_window() -> None:
    offsets = list(burst(4, 120.0))
    assert offsets == [0.0, 30.0, 60.0, 90.0]
    assert all(o < 120.0 for o in offsets)


def test_burst_repeat_with_gap() -> None:
    offsets = list(burst(2, 10.0, repeat=3, gap=5.0))
    # 組 k 起點 = k * (window + gap)
    assert offsets == [0.0, 5.0, 15.0, 20.0, 30.0, 35.0]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"size": 0, "window": 10.0},
        {"size": 1, "window": 0.0},
        {"size": 1, "window": 10.0, "repeat": 0},
        {"size": 1, "window": 10.0, "gap": -1.0},
    ],
)
def test_burst_rejects_invalid_eagerly(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        burst(**kwargs)  # 不需要 list() 就要丟錯


class FakeTime:
    """可注入的 monotonic clock + sleep + wall;render 可呼叫 advance 模擬耗時。"""

    def __init__(self) -> None:
        self.t = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds

    def wall(self) -> datetime:
        return T0 + timedelta(seconds=self.t)

    def advance(self, seconds: float) -> None:
        self.t += seconds


class ListSink:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def write(self, line: str) -> None:
        self.lines.append(line)


def test_emit_sleeps_toward_deadline_without_drift() -> None:
    ft = FakeTime()
    sink = ListSink()

    def render(at: datetime) -> str:
        ft.advance(0.3)  # 每筆 render 耗時 0.3s
        return at.isoformat()

    sent = emit(uniform(3, 1.0), render, sink, clock=ft.clock, wall=ft.wall, sleep=ft.sleep)

    assert sent == 3
    # deadline 為 0,1,2;扣掉 render 耗時,只 sleep 0.7(舊寫法會 sleep 1.0)
    assert ft.sleeps == pytest.approx([0.7, 0.7])


def test_emit_stamps_actual_send_time() -> None:
    ft = FakeTime()
    sink = ListSink()
    emit(burst(2, 10.0), lambda at: at.isoformat(), sink,
         clock=ft.clock, wall=ft.wall, sleep=ft.sleep)
    assert sink.lines == [T0.isoformat(), (T0 + timedelta(seconds=5)).isoformat()]


def test_emit_overrun_never_sleeps_negative() -> None:
    ft = FakeTime()
    sink = ListSink()

    def slow(at: datetime) -> str:
        ft.advance(1.0)  # 比 burst 間距慢得多
        return "x"

    sent = emit(burst(1000, 0.001), slow, sink, clock=ft.clock, wall=ft.wall, sleep=ft.sleep)
    assert sent == 1000
    assert ft.sleeps == []
    assert len(sink.lines) == 1000


def test_emit_reports_progress() -> None:
    ft = FakeTime()
    seen: list[int] = []
    emit(uniform(3, 0.0), lambda at: "x", ListSink(),
         clock=ft.clock, wall=ft.wall, sleep=ft.sleep, on_sent=seen.append)
    assert seen == [1, 2, 3]


def test_emit_propagates_sink_error() -> None:
    ft = FakeTime()
    seen: list[int] = []

    class Boom:
        def __init__(self) -> None:
            self.n = 0

        def write(self, line: str) -> None:
            self.n += 1
            if self.n == 2:
                raise OSError("sink down")

    with pytest.raises(OSError, match="sink down"):
        emit(uniform(5, 0.0), lambda at: "x", Boom(),
             clock=ft.clock, wall=ft.wall, sleep=ft.sleep, on_sent=seen.append)
    assert seen == [1]
