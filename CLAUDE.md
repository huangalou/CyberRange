# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案定位

CyberRange 是一套 **DetectOps Harness**：指定廠牌 / 產品 / 版本，即可產生具備真實樣態的事件日誌，餵給 SIEM（Wazuh / ELK 等）驗證偵測規則是否真的會 fire，而不是只憑「格式看起來對」就假設規則有效。

核心迴圈：`catalog/`（vendor 日誌格式規格）→ `engine/`（產生日誌）→ sink（送進 SIEM）→ 反查偵測規則是否命中，並量測 Time-to-Detect。三個 KPI：

| KPI | 回答的問題 |
|---|---|
| Time-to-Catalog | 一份新的威脅情資，多快能變成可產生、可測試的 log spec？ |
| Time-to-Detect | 流量送進去之後，規則多快 fire？ |
| Time-to-Verified-Detection | 從「規則寫好」到「用真實樣本證明它會 fire」要多久？ |

CyberRange 本身**不做偵測**，只負責產生「打進 SIEM 的東西」；伴生的 SIEM stack（Wazuh + ELK）是驗證對象，不在本 repo 範圍內。

## 三層架構

### 1. `catalog/` — Log 格式規格庫（YAML）

每個廠牌 / 產品 / 版本 / log type 一份 YAML，描述格式骨架、欄位 schema、對應 OCSF class。目前 schema **v4**，主要 block：

- `fields` — 欄位定義，`generator` 支援 `pool` / `faker` / `fixed` / `sequence` / `weighted_choice`
- `ocsf` — OCSF class / category 對映（可選）
- `cef_header` / `cef_mapping` — CEF header 組成與 extension 欄位對映（僅 CEF-wrapped catalog 需要）
- `detections` — `wazuh` / `sigma` / `elk_detection` 三軸，紀錄對應的偵測規則 id
- `cti` — 情資來源、IOC bundle（`cti.iocs`）
- `vulnops` — CVE / advisory 反查用的 `cve_refs`
- `regression` — 預期 alert 數、baseline TTD，作為 regression 基準

### 2. `engine/` — Generator 引擎（Python library + CLI）

吃一份 catalog YAML + 執行參數，輸出日誌串流；也可作為 library 給上層呼叫。CLI 範例：

```bash
cyberrange gen \
  --vendor fortinet --product fortios --version 7.4 --type traffic \
  --count 1000 --rate 50/s --start "2026-05-05T00:00:00" \
  --sink udp://192.0.2.10:514
```

### 3. `api/` + `web/` — Web UI

- `api/` — FastAPI，封裝 engine 為 REST endpoint，提供 catalog 瀏覽、預覽、批次送出、CVE 反查
- `web/` — Next.js 前端：瀏覽 catalog → 設定生成參數 → 預覽樣本 → 選擇 sink → 送出 → 看歷史紀錄

## Log Sink 慣例

文件中的 IP 一律使用 RFC 5737 文件示例位址（`192.0.2.x`），例如：

| Sink | 範例端點 |
|---|---|
| Wazuh syslog | `192.0.2.10:514/udp` |
| ELK syslog | `192.0.2.10:9514/tcp` 或 `/udp` |

實際部署時，把自己的 sink host 加進 `.env` 的 `CYBERRANGE_ALLOWED_SINK_HOSTS` 白名單（engine 本身不限制目標，這道白名單在 API 層強制）。

## 目前結構

```
CyberRange/
├── CLAUDE.md
├── LICENSE
├── README.md
├── catalog/                 ← 57 份 YAML，23 個 vendor/product
├── engine/                  ← Python library + CLI
│   ├── pyproject.toml       ← cyberrange console script
│   ├── src/cyberrange/
│   │   ├── schema.py / loader.py / generator.py / sinks.py / cli.py / vulnops.py
│   │   └── cti/             ← 情資子系統（feeds + ioc_extractor + catalog_writer + metrics）
│   └── tests/                ← pytest
├── api/                     ← FastAPI backend
│   ├── pyproject.toml       ← cyberrange-api console script
│   ├── src/cyberrange_api/
│   │   ├── main.py / auth.py / models.py / store.py / runner.py / sink_policy.py
│   │   └── routes/           ← catalog / preview / generate / jobs / sinks / vulnops / cti_metrics
│   └── tests/
├── web/                     ← Next.js 15 + React 19 + Tailwind v4
│   ├── app/                  ← layout / page / jobs / catalog/[...] / vulnops / metrics
│   ├── components/
│   └── lib/                  ← api.ts / vendors.ts
├── runbooks/                ← 端到端偵測驗證 runbook（fixture → dispatch → 反查）
├── scripts/                 ← 手動驗證用的 shell 腳本
├── tests/fixtures/           ← wazuh-logtest fixture + expected.json（TDD 用）
└── deploy/                  ← 部署與 SIEM 端 patch 文件
```

## 開發環境啟動

```bash
# 引擎 + API（共用同一個 venv）
cd engine && python -m venv .venv && source .venv/bin/activate
pip install -e . -e ../api
cyberrange-api      # http://127.0.0.1:8001

# Web（另一個 shell）
cd web && npm install && npm run dev   # http://localhost:3000
```

## 測試指令

```bash
cd engine && source .venv/bin/activate && python -m pytest tests/ -q   # engine
cd api && python -m pytest tests/ -q                                    # api（沿用同一個 venv）
cd web && npm run build                                                 # web
```

## 工具整合準則

每次納入新 open-source 工具時：

1. **Search-first**：先找官方倉庫與既有整合，避免重做。
2. **隔離部署**：優先 Docker 容器化，每個工具自己一份 `docker-compose.yml`。
3. **產出對齊 sink**：能輸出 syslog / Beats / agent / file 其中一種，否則加一層 forwarder。
4. **雙送策略**：同類 log 需要同時驗證多個 SIEM 時，採 single-source + dual-output，避免重複跑攻擊。
5. **可重現**：場景腳本必須冪等；不依賴外網下載當下時刻的 payload。
6. **不真打外部目標**：靶機與攻擊行為侷限在本地 lab 網段，只產生 telemetry，不執行真實 exploit。

## 語言與 Locale

- 文件 / commit / 對話：**繁體中文**
- Code 識別字 / CLI 輸出 / catalog YAML key：**English**

## License

Apache-2.0
