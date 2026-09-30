# 時間模型軸 第 1 期：Burst 節奏與時鐘注入 — 設計

- 日期：2026-09-30
- 月更單位：2026-10（候選 (d) 時間模型軸）
- 狀態：設計已口頭確認，待 spec review

## 背景

`engine` 的時間只有一個來源：`generator.py::_render_datetime()` 直接呼叫
`datetime.now()`；送出節奏只有 `--rate`（`sleep(1/rate)`），且在
`cli.py::cmd_gen` 與 `api/runner.py::_run` 各複製一份。因此 CyberRange 無法：

1. 產生「N 筆 / T 秒」的 burst，讓 Wazuh frequency/timeframe、ELK threshold
   類規則在 live SIEM 上觸發；
2. 回填歷史時段；
3. 產生 baseline＋異常的時間形狀。

對照 splunk/eventgen（`interval`/`count`、`backfill`、`hourOfDayRate` 等）後，
決定分三期補齊。本文件只涵蓋 **第 1 期**。

## 分期總覽

所有情境共用同一個概念：**Schedule**（事件時間 offset 序列）與
**Pacing**（何時送出）分離。

| 期 | 情境 | Schedule | Pacing | 排程 |
|---|---|---|---|---|
| 1 | 時間窗口規則觸發 | `burst` | realtime | 2026-10（本文件） |
| 2 | 歷史回填 | `uniform` over `[start, end]` | asap | 2026-10 若有餘裕，否則 11 月 |
| 3 | Baseline＋異常 | `profile`（hour/day 權重）＋ burst 疊加 | 兩者皆可 | 2026-11 |

關鍵限制：Wazuh analysisd 以 **到達時間** 計算 frequency/timeframe，不看 log
內時間戳，所以第 1 期必須真的照節奏送出，不能只偽造時間戳。

## 範圍

**包含**

- `engine/src/cyberrange/timing.py`：`uniform` / `burst` schedule 與共用 `emit()` 迴圈
- `render_one(..., at=...)` 時鐘注入
- CLI `--burst` / `--repeat` / `--gap`
- API `GenerateRequest.burst`、`JobStatus.burst`
- `cli.py` 與 `api/runner.py` 的送出迴圈收斂到 `emit()`
- Live-fire 驗收：Wazuh 5712，外加兩組反例，量 TTD

**不包含**

- Web UI 表單（CLI/API 驗證後另開）
- asap pacing、`--start`/`--end` backfill（第 2 期）
- 時段權重 profile（第 3 期）
- catalog schema 新增 `regression.timing`（等 burst 驗證過再決定）

## 設計

### 1. `timing.py`

```python
Schedule = Iterator[float]   # 相對 anchor 的秒數 offset，單調不減

def uniform(count: int, rate: float) -> Schedule: ...
def burst(size: int, window: float, repeat: int = 1, gap: float = 0.0) -> Schedule: ...

def emit(
    schedule: Schedule,
    render: Callable[[datetime], str],
    sink: _Sink,
    *,
    clock: Callable[[], float] = time.monotonic,
    wall: Callable[[], datetime] = _utcnow,
    sleep: Callable[[float], None] = time.sleep,
    on_sent: Callable[[int], None] | None = None,
) -> int: ...   # 回傳送出筆數
```

- `uniform(count, rate)`：第 i 筆 offset = `i / rate`；`rate == 0` 時全部為 0
  （不 sleep，等同現行「盡速送出」）。
- `burst(size, window, repeat, gap)`：第 k 組（0 起算）第 j 筆的 offset =
  `k * (window + gap) + j * window / size`。每組 `size` 筆落在 `[0, window)`
  內，總筆數 `size * repeat`。
- `emit()`：
  - `anchor = clock()`；對每個 offset 計算 `deadline = anchor + offset`，
    `remaining = deadline - clock()`，`> 0` 才 `sleep(remaining)`。
    以 deadline 為準，不累加 render 耗時造成的漂移（現行 `sleep(1/rate)` 會漂移）。
  - 時間戳 `at = wall()`：取 **實際送出當下** 的時間，不是計畫時間。
    realtime 模式下時間戳與 SIEM 到達時間一致；`--rate` 的輸出與現行相同。
  - `line = render(at)` → `sink.write(line)` → `on_sent(sent)`。
  - 不吞例外：render 或 sink 失敗直接往上拋。

### 2. `generator.py` 時鐘注入

- `_render_datetime(fmt, at)`、`_render_field(..., at)`、
  `render_one(spec, params=None, ..., at: datetime | None = None)`。
- `at is None` → `datetime.now(timezone.utc)`，完全向後相容。
- `render_many` 不改（preview 使用）。
- 57 份 catalog 不需修改。

### 3. CLI

```bash
cyberrange gen --vendor linux --product openssh --version 9.x \
  --log-type auth.failure --burst 8/120s --repeat 1 --gap 0s \
  --sink udp://192.0.2.10:514
```

- `--burst SIZE/WINDOW`：WINDOW 接受 `120`、`120s`、`2m`。
- `--repeat K`（預設 1）、`--gap DURATION`（預設 `0s`），只有搭配 `--burst` 時才有效。
- `--count` 預設改為 `None`；未指定 burst 時視為 10（維持現行預設）。
- 互斥：`--burst` 與 `--rate > 0`、`--burst` 與明確給定的 `--count`。
  單獨給 `--repeat`/`--gap` 而沒給 `--burst` 也視為錯誤。
- `cmd_gen` 依參數組出 `uniform` 或 `burst`，呼叫 `emit()`。

### 4. API

```python
class BurstSpec(BaseModel):
    size: int = Field(ge=1)
    window_s: float = Field(gt=0)
    repeat: int = Field(default=1, ge=1)
    gap_s: float = Field(default=0.0, ge=0)

class GenerateRequest(SpecID):
    ...
    burst: Optional[BurstSpec] = None   # 與 rate > 0 互斥（model_validator）
```

- 設了 `burst` 時忽略 `count`，由 `size * repeat` 決定；`JobStatus.count`
  回報實際總數，並新增 `burst` 欄位。
- `runner._run` 改呼叫 `emit()`，`on_sent` 沿用「每 100 筆更新一次 store」。

### 5. 錯誤處理

| 狀況 | CLI | API |
|---|---|---|
| burst 格式錯（`8/0s`、`0/120s`、`abc`） | argparse error，exit 2 | 422 |
| `--gap` 為負、`--repeat < 1` | exit 2 | 422 |
| 互斥衝突 | exit 2，訊息點名兩個參數 | 422 |
| sink 寫入失敗 | 例外往上拋 | job `failed`，保留 `sent` |

## 測試

TDD，全部使用注入的 fake clock / sleep，不做真實等待。

- `engine/tests/test_timing.py`
  - `uniform`：offset 值、`rate=0` 全為 0
  - `burst`：單組、`repeat>1` 加 `gap`、總筆數、每組落在 window 內
  - `emit`：sleep 參數等於 `deadline - now`（無累加漂移）；render 超時時不 sleep；
    `at` 取 `wall()`；`on_sent` 計數；sink 例外會往上拋
- `engine/tests/test_render_at.py`：固定 `at`，對 `epoch`、`%b %d %H:%M:%S`、
  `%Y-%m-%dT%H:%M:%S.%fZ` 三個 format 的輸出為確定值；`at=None` 行為不變
- CLI：`--burst` 解析（`120`/`120s`/`2m`）、各互斥情況 exit 2
- API：不合法 burst 與 `burst`＋`rate` 都回 422；合法時 `JobStatus.count == size*repeat`
- 回歸：engine 與 api 既有測試全綠；ArcSight 模擬器基準
  （OK 30 / WARN 1 / PARTIAL 4 / CATCH-ALL 1 / FAIL 3 / N/A 18）不變

## Live-fire 驗收

目標：Wazuh 內建 **5712**（`if_matched_sid 5710`，frequency 8 / 120s，
`same_source_ip`）。Catalog：`linux/openssh/9.x/auth-failure`。

| 組 | 參數 | 預期 5712 |
|---|---|---|
| 正例 | `--burst 8/120s` | 1 次 |
| 反例 A | `--burst 7/120s` | 0 次 |
| 反例 B | `--burst 8/300s` | 0 次 |

- 各組之間間隔超過 120 秒，而且每組以 param 指定不同的單一來源 IP，
  避免組與組之間的計數互相污染。
- **前置條件**：catalog 目前隨機輪換 4 種樣態、6 個 src IP。驗收需要把 src 釘成單一 IP、
  樣態限定在 `invalid user` 類（5710 會命中的樣態）。實作時先確認 `--param` 能否做到；
  不能的話在 catalog 補 `${params.}` 參數（預設值不變，輸出分布不變）。
- TTD = alert 時間 − 第 8 筆送出時間，取正例結果寫進該 catalog 的
  `regression.baseline_ttd_ms`。
- 以 SOC-side Wazuh manager 的 `alerts.json` 為準查 alert。
- 送 log 前先給 SOP，批准後執行（只送 log、不改 rule）。

## 完成條件

1. 上述測試全綠，既有回歸不變。
2. Live-fire 三組結果符合預期表。
3. openssh catalog 的 `regression.baseline_ttd_ms` 回填實測值。
4. CLAUDE.md 的 CLI 範例修正（`--type` → `--log-type`，移除不存在的 `--start`，
   補上 `--burst` 範例）。
