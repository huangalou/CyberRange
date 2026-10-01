"""時間模型軸:schedule 產生器、duration/burst 解析、emit 迴圈。"""
from __future__ import annotations

import pytest

from cyberrange.timing import burst, parse_burst, parse_duration, uniform


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
