"""時間模型軸:事件排程(Schedule)與依節奏送出(emit)。

Schedule 產生「相對 anchor 的秒數 offset」序列;emit() 依 offset 算出
monotonic deadline 再 sleep,render 耗時不會累積成漂移。
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Callable, Iterator, Protocol

Schedule = Iterator[float]

_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)([smh]?)$")
_UNIT_SECONDS = {"": 1.0, "s": 1.0, "m": 60.0, "h": 3600.0}


def parse_duration(text: str) -> float:
    """`120` / `120s` / `2m` / `0.5s` / `1h` → 秒數。"""
    m = _DURATION_RE.match(text.strip())
    if not m:
        raise ValueError(
            f"invalid duration {text!r} (expected e.g. 120, 120s, 2m, 0.5s)"
        )
    return float(m.group(1)) * _UNIT_SECONDS[m.group(2)]


def parse_burst(text: str) -> tuple[int, float]:
    """`SIZE/WINDOW`(如 `8/120s`)→ (size, window 秒數)。"""
    size_s, sep, window_s = text.partition("/")
    if not sep or not size_s.isdigit():
        raise ValueError(
            f"invalid burst {text!r} (expected SIZE/WINDOW, e.g. 8/120s)"
        )
    size = int(size_s)
    window = parse_duration(window_s)
    if size < 1:
        raise ValueError(f"burst size must be >= 1, got {size}")
    if window <= 0:
        raise ValueError(f"burst window must be > 0, got {window_s!r}")
    return size, window


def uniform(count: int, rate: float) -> Schedule:
    """`count` 筆,每秒 `rate` 筆;rate == 0 表示不等待。"""
    step = (1.0 / rate) if rate > 0 else 0.0
    return (i * step for i in range(count))


def burst(size: int, window: float, repeat: int = 1, gap: float = 0.0) -> Schedule:
    """每組 `size` 筆平均落在 `window` 秒內,共 `repeat` 組,組間隔 `gap` 秒。"""
    if size < 1:
        raise ValueError(f"burst size must be >= 1, got {size}")
    if window <= 0:
        raise ValueError(f"burst window must be > 0, got {window}")
    if repeat < 1:
        raise ValueError(f"burst repeat must be >= 1, got {repeat}")
    if gap < 0:
        raise ValueError(f"burst gap must be >= 0, got {gap}")
    period = window + gap
    step = window / size
    return (k * period + j * step for k in range(repeat) for j in range(size))


class SinkLike(Protocol):
    def write(self, line: str) -> None: ...


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def emit(
    schedule: Schedule,
    render: Callable[[datetime], str],
    sink: SinkLike,
    *,
    clock: Callable[[], float] = time.monotonic,
    wall: Callable[[], datetime] = utcnow,
    sleep: Callable[[float], None] = time.sleep,
    on_sent: Callable[[int], None] | None = None,
) -> int:
    """依 schedule 節奏 render 並寫入 sink,回傳送出筆數。

    時間戳取「實際送出當下」的 wall(),與 SIEM 到達時間一致。
    render / sink 的例外不吞,直接往上拋。
    """
    anchor = clock()
    sent = 0
    for offset in schedule:
        remaining = anchor + offset - clock()
        if remaining > 0:
            sleep(remaining)
        sink.write(render(wall()))
        sent += 1
        if on_sent is not None:
            on_sent(sent)
    return sent
