# 時間模型軸 第 1 期（Burst 節奏與時鐘注入）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 讓 `cyberrange gen` 與 `POST /generate` 能以「N 筆 / T 秒」burst 節奏送出事件，時間戳可注入，並以 Wazuh 5712 live-fire 驗證與量測 TTD。

**Architecture:** 新增 `engine/src/cyberrange/timing.py`，Schedule（事件 offset 序列）與 `emit()`（以 monotonic deadline sleep 的共用送出迴圈）分離；`render_one` 多一個 `at` 參數。CLI 與 API runner 的重複 `sleep(1/rate)` 迴圈都改呼叫 `emit()`。

**Tech Stack:** Python 3.11+、pydantic v2、FastAPI、pytest、Jinja2。

**Spec:** `docs/superpowers/specs/2026-09-30-timing-axis-phase1-design.md`

## Global Constraints

- 文件 / commit / 註解：繁體中文；code 識別字、CLI 輸出、YAML key：English。
- Commit 格式 `<type>: <描述>`（feat / fix / refactor / docs / test / chore）。
- 公開 repo：文件、測試、commit 內不得出現 lab 主機名、內網 IP；範例 IP 只用 RFC 5737（`192.0.2.x` / `198.51.100.x` / `203.0.113.x`）；SOC 端一律稱「SOC-side」。
- `at is None` 時 `render_one` 行為必須與現行完全相同；`--rate` 模式的輸出內容不變。
- 57 份 catalog 除 `linux/openssh/9.x/auth-failure.yaml` 外不得修改。
- 回歸基準：engine `229 passed, 58 skipped`、api `47 passed`（本計畫只會增加測試數）；ArcSight 模擬器基準 OK 30 / WARN 1 / PARTIAL 4 / CATCH-ALL 1 / FAIL 3 / N/A 18 不變。
- 指令執行位置：engine 測試 `cd engine && source .venv/bin/activate && python -m pytest ...`；api 測試共用同一個 venv：`cd api && python -m pytest ...`。

## Review Focus

1. `--param src_pool=203.0.113.5`（純字串，非 JSON list）→ 使用者預期每筆都是這個 IP；現行 `choice` 會對字串逐字元 `random.choice`，吐出 `"2"`、`"."`。由 Task 3 的 `test_choice_param_plain_string_is_single_choice` 釘住。
2. `render_one(..., at=<naive datetime>)` → 預期立即 `ValueError`，而不是默默用本機時區算 epoch 產生錯誤時間。由 Task 3 的 `test_render_one_rejects_naive_at` 釘住。
3. burst 快於 render 能力（例如 `1000/0.001s`）→ 預期不 sleep 負值、不報錯、筆數全數送出。由 Task 2 的 `test_emit_overrun_never_sleeps_negative` 釘住。
4. Duration 各種寫法：`120`、`120s`、`2m`、`0.5s` 都應接受；`-1s`、`abc`、空字串、`2d` 應拒絕並給出清楚訊息。由 Task 1 的參數化測試釘住。
5. 只給 `--repeat` / `--gap` 沒給 `--burst` → 預期 exit 2，而不是被默默忽略。由 Task 4 的 `test_gen_repeat_without_burst_exits_2` 釘住。

---

### Task 1: Schedule 產生器與 duration / burst 解析

**Files:**
- Create: `engine/src/cyberrange/timing.py`
- Test: `engine/tests/test_timing.py`

**Interfaces:**
- Produces:
  - `Schedule = Iterator[float]`
  - `parse_duration(text: str) -> float`：秒數；非法時 `ValueError`
  - `parse_burst(text: str) -> tuple[int, float]`：`(size, window_seconds)`；非法時 `ValueError`
  - `uniform(count: int, rate: float) -> Schedule`
  - `burst(size: int, window: float, repeat: int = 1, gap: float = 0.0) -> Schedule`：參數非法時**呼叫當下**就 `ValueError`（非 lazy）

- [ ] **Step 1: 寫失敗測試**

`engine/tests/test_timing.py`：

```python
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
```

- [ ] **Step 2: 確認測試失敗**

Run: `cd engine && source .venv/bin/activate && python -m pytest tests/test_timing.py -q`
Expected: FAIL，`ModuleNotFoundError: No module named 'cyberrange.timing'`

- [ ] **Step 3: 最小實作**

`engine/src/cyberrange/timing.py`：

```python
"""時間模型軸:事件排程(Schedule)與依節奏送出(emit)。

Schedule 產生「相對 anchor 的秒數 offset」序列;emit() 依 offset 算出
monotonic deadline 再 sleep,render 耗時不會累積成漂移。
"""
from __future__ import annotations

import re
from typing import Iterator

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
```

- [ ] **Step 4: 確認測試通過**

Run: `cd engine && python -m pytest tests/test_timing.py -q`
Expected: 全部 PASS

- [ ] **Step 5: Commit**

```bash
git add engine/src/cyberrange/timing.py engine/tests/test_timing.py
git commit -m "feat(engine): 新增 timing 模組的 uniform/burst schedule 與 duration 解析"
```

---

### Task 2: `emit()` 共用送出迴圈

**Files:**
- Modify: `engine/src/cyberrange/timing.py`
- Test: `engine/tests/test_timing.py`

**Interfaces:**
- Consumes: `Schedule`、`uniform`、`burst`（Task 1）
- Produces:
  ```python
  def emit(
      schedule: Schedule,
      render: Callable[[datetime], str],
      sink: SinkLike,                      # 任何有 write(str) 的物件
      *,
      clock: Callable[[], float] = time.monotonic,
      wall: Callable[[], datetime] = utcnow,
      sleep: Callable[[float], None] = time.sleep,
      on_sent: Callable[[int], None] | None = None,
  ) -> int                                  # 送出筆數
  ```
  以及 `utcnow() -> datetime`（aware UTC）。

- [ ] **Step 1: 寫失敗測試**

附加到 `engine/tests/test_timing.py`（import 行改為下面這版）：

```python
from datetime import datetime, timedelta, timezone

from cyberrange.timing import burst, emit, parse_burst, parse_duration, uniform

T0 = datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)


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
```

- [ ] **Step 2: 確認測試失敗**

Run: `cd engine && python -m pytest tests/test_timing.py -q`
Expected: FAIL，`ImportError: cannot import name 'emit'`

- [ ] **Step 3: 最小實作**

在 `engine/src/cyberrange/timing.py` 補上 import 與函式：

```python
import re
import time
from datetime import datetime, timezone
from typing import Callable, Iterator, Protocol
```

```python
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
```

- [ ] **Step 4: 確認測試通過**

Run: `cd engine && python -m pytest tests/test_timing.py -q`
Expected: 全部 PASS

- [ ] **Step 5: Commit**

```bash
git add engine/src/cyberrange/timing.py engine/tests/test_timing.py
git commit -m "feat(engine): timing.emit 以 monotonic deadline 依節奏送出"
```

---

### Task 3: `render_one(at=...)` 時鐘注入與 choice 純字串防護

**Files:**
- Modify: `engine/src/cyberrange/generator.py`（`_render_datetime`、`_render_field`、`render_one`）
- Test: `engine/tests/test_render_at.py`

**Interfaces:**
- Produces: `render_one(spec, params=None, cef_header_overrides=None, cef_extension_overrides=None, at: datetime | None = None) -> str`；`at` 必須是 timezone-aware，否則 `ValueError("at must be timezone-aware")`。
- `choice` 欄位的 choices 解析結果若是 `str`，視為單一選項。

- [ ] **Step 1: 寫失敗測試**

`engine/tests/test_render_at.py`：

```python
"""render_one(at=...) 時鐘注入;choice 純字串 param 防護。"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cyberrange import CatalogSpec, render_one

AT = datetime(2026, 10, 1, 8, 5, 3, 123456, tzinfo=timezone.utc)


def _spec(fmt: str) -> CatalogSpec:
    return CatalogSpec(
        vendor="t", product="t", version="1", log_type="t", format="raw",
        fields=[{"name": "ts", "type": "datetime", "format": fmt}],
        template="{{ ts }}",
    )


@pytest.mark.parametrize(
    ("fmt", "expected"),
    [
        ("epoch", "1790841903"),
        ("%b %d %H:%M:%S", "Oct 01 08:05:03"),
        ("%Y-%m-%dT%H:%M:%S.%fZ", "2026-10-01T08:05:03.123456Z"),
    ],
)
def test_render_one_uses_injected_time(fmt: str, expected: str) -> None:
    assert render_one(_spec(fmt), at=AT) == expected


def test_render_one_without_at_uses_now() -> None:
    before = int(datetime.now(timezone.utc).timestamp())
    out = int(render_one(_spec("epoch")))
    after = int(datetime.now(timezone.utc).timestamp())
    assert before <= out <= after


def test_render_one_rejects_naive_at() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        render_one(_spec("epoch"), at=datetime(2026, 10, 1))


def test_choice_param_plain_string_is_single_choice() -> None:
    spec = CatalogSpec(
        vendor="t", product="t", version="1", log_type="t", format="raw",
        params={"pool": {"default": ["198.51.100.1", "198.51.100.2"]}},
        fields=[{"name": "ip", "type": "choice", "choices": "${params.pool}"}],
        template="{{ ip }}",
    )
    outs = {render_one(spec, {"pool": "203.0.113.5"}) for _ in range(20)}
    assert outs == {"203.0.113.5"}
```

- [ ] **Step 2: 確認測試失敗**

Run: `cd engine && python -m pytest tests/test_render_at.py -q`
Expected: FAIL，`TypeError: render_one() got an unexpected keyword argument 'at'`；choice 測試因逐字元選取而失敗。

- [ ] **Step 3: 最小實作**

`engine/src/cyberrange/generator.py`：

```python
def _render_datetime(fmt: str, at: datetime | None = None) -> str:
    now = at if at is not None else datetime.now(timezone.utc)
    if fmt == "epoch":
        return str(int(now.timestamp()))
    if fmt == "epoch_ns":
        return str(int(now.timestamp() * 1_000_000_000))
    return now.strftime(fmt)
```

`_render_field` 簽名改為：

```python
def _render_field(
    fs: FieldSpec,
    params: dict[str, Any],
    prior: dict[str, str],
    at: datetime | None = None,
) -> str:
```

`choice` 分支改為：

```python
    if t == "choice":
        choices = _resolve_param_ref(extras["choices"], params)
        if isinstance(choices, str):  # --param pool=1.2.3.4 → 單一選項,不是逐字元
            choices = [choices]
        return str(random.choice(list(choices)))
```

`datetime` 分支改為：

```python
    if t == "datetime":
        return _render_datetime(extras["format"], at)
```

`render_one` 簽名與開頭改為：

```python
def render_one(
    spec: CatalogSpec,
    params: dict[str, Any] | None = None,
    cef_header_overrides: dict[str, Any] | None = None,
    cef_extension_overrides: dict[str, dict[str, Any]] | None = None,
    at: datetime | None = None,
) -> str:
    if at is not None and at.tzinfo is None:
        raise ValueError("at must be timezone-aware")
    merged = {**spec.default_params(), **(params or {})}
    rendered: dict[str, str] = {}
    for fs in spec.fields:
        rendered[fs.name] = _render_field(fs, merged, rendered, at)
```

（其餘不動；`render_many` 不改。）

- [ ] **Step 4: 確認測試通過（含全 catalog smoke）**

Run: `cd engine && python -m pytest tests/test_render_at.py tests/test_smoke.py -q`
Expected: 全部 PASS

- [ ] **Step 5: Commit**

```bash
git add engine/src/cyberrange/generator.py engine/tests/test_render_at.py
git commit -m "feat(engine): render_one 支援注入時間戳,choice 純字串 param 視為單一選項"
```

---

### Task 4: CLI `--burst` / `--repeat` / `--gap` 與 JSON param

**Files:**
- Modify: `engine/src/cyberrange/cli.py`（imports、`_parse_param`、`cmd_gen`、`sp_gen` 參數定義）
- Test: `engine/tests/test_cli_gen_timing.py`

**Interfaces:**
- Consumes: `parse_burst`、`parse_duration`、`uniform`、`burst`、`emit`（Task 1–2）；`render_one(..., at=)`（Task 3）
- Produces: CLI 行為
  - `--burst SIZE/WINDOW`、`--repeat K`（≥1）、`--gap DURATION`
  - `--count` 預設 `None`（未指定且無 burst 時為 10）
  - `--param key=<JSON list/dict>` 解析成 list/dict；其他值維持字串

- [ ] **Step 1: 寫失敗測試**

`engine/tests/test_cli_gen_timing.py`：

```python
"""cyberrange gen:burst 參數、互斥檢查、JSON param。"""
from __future__ import annotations

from pathlib import Path

import pytest

from cyberrange.cli import _parse_param, main

BASE = ["gen", "--vendor", "linux", "--product", "openssh",
        "--version", "9.x", "--log-type", "auth.failure"]


def _lines(p: Path) -> list[str]:
    return [l for l in p.read_text().splitlines() if l.strip()]


def test_gen_burst_writes_size_times_repeat(tmp_path: Path) -> None:
    out = tmp_path / "out.log"
    rc = main([*BASE, "--burst", "3/0.03s", "--repeat", "2", "--gap", "0.01s",
               "--sink", f"file://{out}"])
    assert rc == 0
    assert len(_lines(out)) == 6


def test_gen_default_count_unchanged(tmp_path: Path) -> None:
    out = tmp_path / "out.log"
    assert main([*BASE, "--sink", f"file://{out}"]) == 0
    assert len(_lines(out)) == 10


@pytest.mark.parametrize(
    ("extra", "needle"),
    [
        (["--burst", "3/1s", "--rate", "5"], "--burst"),
        (["--burst", "3/1s", "--count", "5"], "--burst"),
        (["--burst", "0/1s"], "burst"),
        (["--burst", "3/1s", "--repeat", "0"], "repeat"),
        # 用 `=` 形式:`--gap -1s` 會被 argparse 當成另一個選項
        (["--burst", "3/1s", "--gap=-1s"], "invalid duration"),
    ],
)
def test_gen_invalid_timing_args_exit_2(
    extra: list[str], needle: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main([*BASE, *extra])
    assert exc.value.code == 2
    assert needle in capsys.readouterr().err


def test_gen_repeat_without_burst_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main([*BASE, "--repeat", "3"])
    assert exc.value.code == 2
    assert "--burst" in capsys.readouterr().err


def test_parse_param_json_list_and_dict() -> None:
    out = _parse_param([
        'src_pool=["203.0.113.5"]',
        'kind_weights={"invalid_user": 1}',
        "hostname=web01",
        "port=514",
        "odd=[not json",
    ])
    assert out == {
        "src_pool": ["203.0.113.5"],
        "kind_weights": {"invalid_user": 1},
        "hostname": "web01",
        "port": "514",
        "odd": "[not json",
    }
```

- [ ] **Step 2: 確認測試失敗**

Run: `cd engine && python -m pytest tests/test_cli_gen_timing.py -q`
Expected: FAIL，`unrecognized arguments: --burst`，以及 `_parse_param` 回傳字串而非 list/dict

- [ ] **Step 3: 實作**

`cli.py` imports：刪掉 `import time`（只有 `cmd_gen` 在用），`from .generator import render_many` 改為 `from .generator import render_many, render_one`，新增：

```python
from typing import Any

from .timing import Schedule, burst, emit, parse_burst, parse_duration, uniform
```

模組常數（放在 imports 之後）：

```python
DEFAULT_GEN_COUNT = 10
```

`_parse_param` 改為：

```python
def _parse_param_value(raw: str) -> Any:
    """JSON list/dict 才轉型,其餘一律保留字串(維持既有行為)。"""
    if raw[:1] not in ("[", "{"):
        return raw
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    return parsed if isinstance(parsed, (list, dict)) else raw


def _parse_param(items: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            raise SystemExit(f"--param expects key=value, got {item!r}")
        k, v = item.split("=", 1)
        out[k] = _parse_param_value(v)
    return out
```

新增 argparse type 轉換器與檢查（放在 `cmd_gen` 前）：

```python
def _burst_arg(text: str) -> tuple[int, float]:
    try:
        return parse_burst(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _duration_arg(text: str) -> float:
    try:
        return parse_duration(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _repeat_arg(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid repeat {text!r}") from exc
    if value < 1:
        raise argparse.ArgumentTypeError(f"repeat must be >= 1, got {value}")
    return value


def _gen_timing_conflict(args: argparse.Namespace) -> str | None:
    if args.burst is None:
        if args.repeat is not None or args.gap is not None:
            return "--repeat/--gap require --burst"
        return None
    if args.rate > 0:
        return "--burst and --rate are mutually exclusive"
    if args.count is not None:
        return "--burst and --count are mutually exclusive (total = SIZE x --repeat)"
    return None


def _build_schedule(args: argparse.Namespace) -> Schedule:
    if args.burst is not None:
        size, window = args.burst
        return burst(size, window, repeat=args.repeat or 1, gap=args.gap or 0.0)
    count = args.count if args.count is not None else DEFAULT_GEN_COUNT
    return uniform(count, args.rate)
```

`cmd_gen` 改為：

```python
def cmd_gen(args: argparse.Namespace) -> int:
    conflict = _gen_timing_conflict(args)
    if conflict:
        args.gen_parser.error(conflict)
    spec_path = find_spec(
        args.vendor,
        args.product,
        args.version,
        args.log_type,
        root=Path(args.catalog_root),
    )
    spec = load_spec(spec_path)
    params = _parse_param(args.param)
    schedule = _build_schedule(args)

    with open_sink(args.sink) as sink:
        emit(schedule, lambda at: render_one(spec, params, at=at), sink)
    return 0
```

`sp_gen` 參數：`--count` 改為

```python
    sp_gen.add_argument(
        "--count",
        type=int,
        default=None,
        help=f"number of events (default {DEFAULT_GEN_COUNT}); not with --burst",
    )
```

在 `--rate` 之後新增：

```python
    sp_gen.add_argument(
        "--burst",
        type=_burst_arg,
        default=None,
        metavar="SIZE/WINDOW",
        help="send SIZE events spread over WINDOW (e.g. 8/120s, 3/2m)",
    )
    sp_gen.add_argument(
        "--repeat",
        type=_repeat_arg,
        default=None,
        help="number of bursts (default 1; requires --burst)",
    )
    sp_gen.add_argument(
        "--gap",
        type=_duration_arg,
        default=None,
        help="pause after each burst window (default 0s; requires --burst)",
    )
```

`--param` 的 help 改為 `"key=value param override; JSON list/dict values are parsed; repeatable"`；`sp_gen.set_defaults(func=cmd_gen)` 改為 `sp_gen.set_defaults(func=cmd_gen, gen_parser=sp_gen)`。

- [ ] **Step 4: 確認測試通過**

Run: `cd engine && python -m pytest tests/test_cli_gen_timing.py -q`
Expected: 全部 PASS

- [ ] **Step 5: 全 engine 回歸**

Run: `cd engine && python -m pytest tests/ -q`
Expected: `229 + 新增數 passed, 58 skipped`，0 failed

- [ ] **Step 6: Commit**

```bash
git add engine/src/cyberrange/cli.py engine/tests/test_cli_gen_timing.py
git commit -m "feat(cli): gen 新增 --burst/--repeat/--gap,送出改走 timing.emit,--param 支援 JSON list/dict"
```

---

### Task 5: openssh auth-failure catalog 樣態權重參數化

**Files:**
- Modify: `catalog/linux/openssh/9.x/auth-failure.yaml`（`kind` 欄位、`params`）
- Test: `engine/tests/test_openssh_pinning.py`

**Interfaces:**
- Consumes: `render_one`（Task 3，含 choice 純字串防護）
- Produces: 新 param `kind_weights`（預設值與現行權重完全相同），供 live-fire 釘樣態。

- [ ] **Step 1: 寫失敗測試**

`engine/tests/test_openssh_pinning.py`：

```python
"""openssh auth-failure:live-fire 需要可釘住來源 IP 與樣態。"""
from __future__ import annotations

from cyberrange import find_spec, load_spec, render_one

SPEC = load_spec(find_spec("linux", "openssh", "9.x", "auth.failure"))


def test_kind_and_src_can_be_pinned() -> None:
    params = {"kind_weights": {"invalid_user": 1}, "src_pool": "203.0.113.5"}
    lines = [render_one(SPEC, params) for _ in range(50)]
    assert all("Failed password for invalid user" in l for l in lines)
    assert all("from 203.0.113.5 port" in l for l in lines)


def test_default_kind_weights_unchanged() -> None:
    assert SPEC.default_params()["kind_weights"] == {
        "invalid_user": 0.45,
        "failed_password": 0.30,
        "preauth_close": 0.15,
        "invalid_user_announce": 0.10,
    }
```

- [ ] **Step 2: 確認測試失敗**

Run: `cd engine && python -m pytest tests/test_openssh_pinning.py -q`
Expected: FAIL，`KeyError: 'kind_weights'`

- [ ] **Step 3: 修改 catalog**

`params:` 區塊末尾（`user_pool` 之後）新增：

```yaml
  # kind 權重;live-fire 可用 --param 'kind_weights={"invalid_user": 1}'
  # 釘成單一樣態(Wazuh 5710 → 5712 frequency 驗證)。預設值即現行分布。
  kind_weights:
    default:
      invalid_user:           0.45
      failed_password:        0.30
      preauth_close:          0.15
      invalid_user_announce:  0.10
```

`kind` 欄位改為（上方原有註解保留）：

```yaml
  - name: kind
    type: weighted_choice
    choices: ${params.kind_weights}
```

- [ ] **Step 4: 確認測試通過（含 smoke）**

Run: `cd engine && python -m pytest tests/test_openssh_pinning.py tests/test_smoke.py -q`
Expected: 全部 PASS

- [ ] **Step 5: ArcSight 模擬器基準（有 bundle 才跑）**

Run: `cd engine && ARCSIGHT_PARSERS=~/Projects/CyberRange-lab/vendor-refs/arcsight/arcsight python -m pytest tests/arcsight -q && python tests/arcsight/arcsight_sim.py --trace | tail -3`
Expected: PASS；統計仍為 OK 30 / WARN 1 / PARTIAL 4 / CATCH-ALL 1 / FAIL 3 / N/A 18

- [ ] **Step 6: Commit**

```bash
git add catalog/linux/openssh/9.x/auth-failure.yaml engine/tests/test_openssh_pinning.py
git commit -m "feat(catalog): openssh auth-failure 樣態權重改為 kind_weights param(預設值不變)"
```

---

### Task 6: API `burst` 欄位與 runner 改走 `emit()`

**Files:**
- Modify: `api/src/cyberrange_api/models.py`（`BurstSpec`、`GenerateRequest`、`JobStatus`）
- Modify: `api/src/cyberrange_api/routes/jobs.py`（`create_job`）
- Modify: `api/src/cyberrange_api/runner.py`（`_run`）
- Test: `api/tests/test_jobs_burst.py`

**Interfaces:**
- Consumes: `burst`、`uniform`、`emit`（`cyberrange.timing`）；`render_one(..., at=)`
- Produces:
  - `BurstSpec(size: int ≥1, window_s: float >0, repeat: int ≥1 = 1, gap_s: float ≥0 = 0.0)`，property `total -> int`
  - `GenerateRequest.burst: Optional[BurstSpec]`，`burst` 與 `rate > 0` 互斥（422）；property `total_count -> int`
  - `JobStatus.burst: Optional[BurstSpec]`；`JobStatus.count` = 實際總筆數

- [ ] **Step 1: 寫失敗測試**

`api/tests/test_jobs_burst.py`：

```python
"""POST /generate 的 burst 節奏。"""
from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from cyberrange_api.main import app

client = TestClient(app)

SPEC = {"vendor": "linux", "product": "openssh", "version": "9.x", "log_type": "auth.failure"}


def _wait_job(job_id: str, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/jobs/{job_id}").json()
        if job["status"] in ("completed", "failed"):
            return job
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish")


def test_burst_job_sends_size_times_repeat(tmp_path: Path) -> None:
    out = tmp_path / "out.log"
    r = client.post("/generate", json={
        **SPEC,
        "count": 50,  # 有 burst 時忽略
        "burst": {"size": 2, "window_s": 0.02, "repeat": 2, "gap_s": 0.01},
        "sink": f"file://{out}",
    })
    assert r.status_code == 202
    job = r.json()
    assert job["count"] == 4
    assert job["burst"]["size"] == 2

    final = _wait_job(job["id"])
    assert final["status"] == "completed", final
    assert final["sent"] == 4
    assert len([l for l in out.read_text().splitlines() if l.strip()]) == 4


def test_burst_and_rate_are_mutually_exclusive(tmp_path: Path) -> None:
    r = client.post("/generate", json={
        **SPEC, "rate": 5, "burst": {"size": 2, "window_s": 1},
        "sink": f"file://{tmp_path / 'x.log'}",
    })
    assert r.status_code == 422
    assert "mutually exclusive" in r.text


def test_burst_invalid_size_rejected(tmp_path: Path) -> None:
    r = client.post("/generate", json={
        **SPEC, "burst": {"size": 0, "window_s": 1},
        "sink": f"file://{tmp_path / 'x.log'}",
    })
    assert r.status_code == 422


def test_rate_job_unchanged(tmp_path: Path) -> None:
    out = tmp_path / "out.log"
    r = client.post("/generate", json={**SPEC, "count": 3, "sink": f"file://{out}"})
    final = _wait_job(r.json()["id"])
    assert final["status"] == "completed"
    assert final["sent"] == 3
    assert final["burst"] is None
```

- [ ] **Step 2: 確認測試失敗**

Run: `cd api && python -m pytest tests/test_jobs_burst.py -q`
Expected: FAIL（`count` 為 50 而非 4；`burst` key 不存在；422 未觸發）

- [ ] **Step 3: 實作 models**

`api/src/cyberrange_api/models.py`：import 改為 `from pydantic import BaseModel, Field, model_validator`。在 `GenerateRequest` 之前新增：

```python
class BurstSpec(BaseModel):
    """N 筆 / window_s 秒,共 repeat 組,組間隔 gap_s 秒。"""

    size: int = Field(ge=1)
    window_s: float = Field(gt=0)
    repeat: int = Field(default=1, ge=1)
    gap_s: float = Field(default=0.0, ge=0)

    @property
    def total(self) -> int:
        return self.size * self.repeat
```

`GenerateRequest` 在 `cef_extension_overrides` 之後新增：

```python
    # 時間模型軸第 1 期:設定時忽略 count,總數 = size * repeat
    burst: Optional[BurstSpec] = None

    @model_validator(mode="after")
    def _burst_excludes_rate(self) -> "GenerateRequest":
        if self.burst is not None and self.rate > 0:
            raise ValueError("burst and rate are mutually exclusive")
        return self

    @property
    def total_count(self) -> int:
        return self.burst.total if self.burst is not None else self.count
```

`JobStatus` 在 `sink: str` 之後新增：

```python
    burst: Optional[BurstSpec] = None
```

- [ ] **Step 4: 實作 jobs route**

`api/src/cyberrange_api/routes/jobs.py::create_job`：

```python
    if req.total_count < 1:
        raise HTTPException(status_code=400, detail="count must be >= 1")
```

`JobStatus(...)` 內 `count=req.count` 改為 `count=req.total_count`，並在 `sink=req.sink,` 之後加 `burst=req.burst,`。

- [ ] **Step 5: 實作 runner**

`api/src/cyberrange_api/runner.py` 全檔改為：

```python
"""Background thread runner for generation jobs."""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from cyberrange import find_spec, load_spec, render_one
from cyberrange.sinks import open_sink
from cyberrange.timing import Schedule, burst, emit, uniform

from .models import GenerateRequest
from .store import store

PROGRESS_EVERY = 100


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _schedule(req: GenerateRequest) -> Schedule:
    if req.burst is not None:
        b = req.burst
        return burst(b.size, b.window_s, repeat=b.repeat, gap=b.gap_s)
    return uniform(req.count, req.rate)


def _run(job_id: str, req: GenerateRequest) -> None:
    sent = 0

    def _progress(n: int) -> None:
        nonlocal sent
        sent = n
        if n % PROGRESS_EVERY == 0:
            store.update(job_id, sent=n)

    try:
        store.update(job_id, status="running", started_at=_utcnow_iso())
        spec_path = find_spec(req.vendor, req.product, req.version, req.log_type)
        spec = load_spec(spec_path)

        # v4 — flatten override Pydantic models to engine kwargs.
        cef_header_kw = (
            req.cef_header_overrides.model_dump(exclude_none=True)
            if req.cef_header_overrides is not None
            else None
        )
        cef_ext_kw = {
            pa_field: ov.model_dump(exclude_none=True)
            for pa_field, ov in req.cef_extension_overrides.items()
        }

        def _render(at: datetime) -> str:
            return render_one(
                spec,
                req.params,
                cef_header_overrides=cef_header_kw,
                cef_extension_overrides=cef_ext_kw,
                at=at,
            )

        with open_sink(req.sink) as sink:
            emit(_schedule(req), _render, sink, on_sent=_progress)
        store.update(
            job_id, sent=sent, status="completed", completed_at=_utcnow_iso()
        )
    except Exception as exc:  # noqa: BLE001
        store.update(
            job_id,
            sent=sent,
            status="failed",
            completed_at=_utcnow_iso(),
            error=f"{type(exc).__name__}: {exc}",
        )


def start_job(job_id: str, req: GenerateRequest) -> None:
    t = threading.Thread(target=_run, args=(job_id, req), daemon=True)
    t.start()
```

- [ ] **Step 6: 確認測試通過 + api 全回歸**

Run: `cd api && python -m pytest tests/ -q`
Expected: `47 + 4 passed`，0 failed

- [ ] **Step 7: Commit**

```bash
git add api/src/cyberrange_api/models.py api/src/cyberrange_api/routes/jobs.py api/src/cyberrange_api/runner.py api/tests/test_jobs_burst.py
git commit -m "feat(api): /generate 新增 burst 節奏,runner 改走 timing.emit"
```

---

### Task 7: 文件修正

**Files:**
- Modify: `CLAUDE.md:38-42`（CLI 範例）
- Modify: `README.md:55-57`（CLI 範例）

- [ ] **Step 1: 修 CLAUDE.md 範例**

把 `CLAUDE.md` 的 CLI 範例整段換成：

````markdown
```bash
cyberrange gen \
  --vendor fortinet --product fortios --version 7.4 --log-type traffic.forward \
  --count 1000 --rate 50 \
  --sink udp://192.0.2.10:514

# burst:8 筆 / 120 秒,驗證 frequency/timeframe 類規則(如 Wazuh 5712)
cyberrange gen \
  --vendor linux --product openssh --version 9.x --log-type auth.failure \
  --burst 8/120s --param 'kind_weights={"invalid_user": 1}' --param src_pool=203.0.113.5 \
  --sink udp://192.0.2.10:514
```
````

- [ ] **Step 2: 修 README.md 範例**

`README.md` 第 55–57 行的 `--type traffic` 改為 `--log-type traffic.forward`、`--rate 50/s` 改為 `--rate 50`，並在該範例後加上與 Step 1 相同的 burst 範例（第二段 code block）。

- [ ] **Step 3: 驗證範例能跑**

Run:
```bash
cd engine && cyberrange gen --vendor fortinet --product fortios --version 7.4 --log-type traffic.forward --count 2 --rate 50 | wc -l
cyberrange gen --vendor linux --product openssh --version 9.x --log-type auth.failure --burst 3/0.03s --param 'kind_weights={"invalid_user": 1}' --param src_pool=203.0.113.5
```
Expected: 第一條輸出 `2`；第二條 3 行皆含 `Failed password for invalid user` 與 `from 203.0.113.5 port`

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs: CLI 範例修正 --log-type/--rate,補 --burst 範例"
```

---

### Task 8: Live-fire 驗收與 TTD 回填（需使用者批准才執行 Step 2 之後）

**Files:**
- Modify: `catalog/linux/openssh/9.x/auth-failure.yaml`（`regression.baseline_ttd_ms` 與註解）

**前提**：Task 1–7 完成、全測試綠。目標主機以環境變數表示，不寫進 repo：
`WAZUH_SINK`（如 `udp://<manager>:514`）、`WAZUH_SSH`、`WAZUH_CONTAINER`，與 `scripts/wazuh_logtest_fixtures.py` 慣例相同。

- [ ] **Step 1: 向使用者提出 SOP 並等待批准**

SOP 內容（照此貼給使用者）：
1. 三組依序送出，組與組之間間隔 ≥ 150 秒，各用不同 src IP：
   - 正例：`--burst 8/120s`，src `203.0.113.11`
   - 反例 A：`--burst 7/120s`，src `203.0.113.12`
   - 反例 B：`--burst 8/300s`，src `203.0.113.13`
2. 每組都帶 `--param 'kind_weights={"invalid_user": 1}'`；送完立刻記下本機 `time.time()`，作為「最後一筆送出時間」。
3. 只送 log、不改 rule、不 restart manager；回滾方式：無（不會改變狀態）。
4. 以 SOC-side manager 容器內的 `/var/ossec/logs/alerts/alerts.json` 查 `rule.id == 5712` 且 `data.srcip` 等於各組 IP 的筆數與時間戳（remote shell 若找不到 `docker`，先把 docker 所在目錄補進 PATH）。

- [ ] **Step 2: 送出三組（批准後）**

```bash
cd engine && source .venv/bin/activate
for spec in "8/120s 203.0.113.11" "7/120s 203.0.113.12" "8/300s 203.0.113.13"; do
  set -- $spec
  cyberrange gen --vendor linux --product openssh --version 9.x --log-type auth.failure \
    --burst "$1" --param 'kind_weights={"invalid_user": 1}' --param "src_pool=$2" \
    --sink "$WAZUH_SINK"
  echo "$2 last_sent=$(python -c 'import time; print(time.time())')"
  sleep 150
done
```

- [ ] **Step 3: 查 alert**

```bash
for ip in 203.0.113.11 203.0.113.12 203.0.113.13; do
  echo "== $ip"
  ssh "$WAZUH_SSH" "docker exec $WAZUH_CONTAINER grep '\"id\":\"5712\"' /var/ossec/logs/alerts/alerts.json | grep '\"srcip\":\"$ip\"' | tail -3"
done
```

Expected: `.11` 恰 1 筆 5712；`.12`、`.13` 0 筆。任一組不符 → 停下，交給 superpowers:systematic-debugging，不要調參數硬湊結果。

- [ ] **Step 4: 計算 TTD 並回填**

TTD(ms) = (`.11` 那筆 5712 的 `timestamp` 轉 epoch − `.11` 的 `last_sent`) × 1000，四捨五入到整數。前提是兩台主機都有 NTP 校時；若差值為負或 > 60000，先檢查時鐘差，不要回填。

`catalog/linux/openssh/9.x/auth-failure.yaml` 的 `regression:` 區塊：`baseline_ttd_ms: 3000` 改成實測值，並在上方註解加一行：

```yaml
  # baseline_ttd_ms:2026-10 live-fire 實測(burst 8/120s → 5712,
  # 反例 7/120s 與 8/300s 皆 0 筆);量法:alert timestamp − 第 8 筆送出時間。
```

- [ ] **Step 5: 回歸並 commit**

Run: `cd engine && python -m pytest tests/ -q`
Expected: 全綠

```bash
git add catalog/linux/openssh/9.x/auth-failure.yaml
git commit -m "feat(catalog): openssh auth-failure 回填 burst live-fire 實測 TTD"
```
