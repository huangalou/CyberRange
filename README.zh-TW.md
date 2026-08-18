# CyberRange — DetectOps 驗證框架

[English](README.md) | **繁體中文**

**貼近原廠格式的日誌產生 → SIEM 收容 → 偵測驗證,收斂成一個可重複執行的工程迴圈。**

CyberRange 是一套偵測工程(detection engineering)驗證框架,核心理念很單純:SOC 團隊應該要能「證明」自己的偵測規則真的有效 — 持續地、用貼近真實的 telemetry、以可量測的 KPI 來驗證 — 而不是因為規則當初 parse 過一次,就假設它一定會觸發。

指定廠牌/產品/版本,它就能產生忠於真實格式的日誌串流(FortiGate key-value、PAN-OS CSV/CEF、Windows Sysmon XML、CloudTrail JSON、ModSecurity audit JSON…),送進你的 SIEM sink(Wazuh、Elastic、檔案、syslog),並反查預期的偵測規則是否真的觸發。

```
┌──────────┐    ┌──────────┐    ┌───────────────┐    ┌──────────────────┐
│ catalog/ │ →  │ engine/  │ →  │ sinks         │ →  │ verify           │
│ 57 YAML  │    │ generate │    │ Wazuh / ELK   │    │ rule fired?      │
│ specs    │    │ + chain  │    │ syslog / file │    │ Time-to-Detect?  │
└──────────┘    └──────────┘    └───────────────┘    └──────────────────┘
```

## 為什麼叫「DetectOps」

VulnOps 管理的是弱點的生命週期;DetectOps 管理的則是**偵測的生命週期** — 從威脅情資、catalog 規格、部署上線的規則,一路到「經過驗證」的偵測,而且每次變更都跑迴歸測試。CyberRange 把這件事落實成三個可操作的 KPI:

| KPI | 回答的問題 |
|---|---|
| **Time-to-Catalog** | 一份新的資安通告,多快能變成可產生、可測試的日誌規格? |
| **Time-to-Detect** | 流量送進去之後,規則多快觸發? |
| **Time-to-Verified-Detection** | 從「規則寫好」到「用貼近真實的樣本證明它會觸發」要多久? |

## 專案內容

- **`catalog/`** — 57 份 YAML 日誌格式規格,涵蓋 23 條廠牌/產品線(Fortinet、Palo Alto、Cisco ASA/Firepower、F5 ASM、Citrix NetScaler、Imperva、Microsoft Windows/Sysmon、Linux auditd/OpenSSH、Kubernetes audit、AWS CloudTrail、OWASP ModSecurity CRS、Trend Micro、Symantec、Sophos、McAfee、Kaspersky、F-Secure、Nginx、Apache…)。Schema v4:欄位產生器(pool/faker/weighted)、OCSF 對映、CEF header/extension 對映、`cti.iocs` 與 `vulnops.cve_refs` 區塊。
- **`engine/`** — Python 函式庫 + `cyberrange` CLI。模板驅動的日誌產生,具備貼近真實的欄位分布、速率控制、時間窗回放、多 sink 派送。199 個測試。
- **`api/` + `web/`** — FastAPI 後端 + Next.js 介面:瀏覽 catalog、預覽樣本、派送任務、查看歷史紀錄、CVE → catalog → 偵測規則反查(`/vulnops`)、CTI 指標儀表板(`/metrics`)。47 個 API 測試。
- **`runbooks/`** — 端到端驗證 runbook,對應真實攻擊行動,例如 FortiGate SSL-VPN 利用的 **S3→S4 pivot 偵測切片**(認證成功 → AD 帳號建立關聯)、以及帶自訂 Wazuh 規則鏈的供應鏈攻擊行動試點 — 每份都附 TDD fixture(`tests/fixtures/wazuh-logtest/*/expected.json`)、live-fire 雙送(Wazuh + Elastic)與偵測數驗證。
- **`cti/` 子系統** — RSS 資安通告 feed → IoC 萃取 → catalog 草稿產生,把「從情資到偵測」的迴圈收起來。

## 設計原則

1. **Catalog 優先** — 日誌格式是資料(YAML 規格),不是程式碼。新增一個廠牌是多寫一份規格,不是多 fork 一份程式。
2. **只產生、不攻擊** — chain/campaign 模式回放的是多階段攻擊的 *telemetry*;絕不執行真實 exploit,也不碰外部目標。
3. **偵測也要 TDD** — 每條規則都附 fixture 與 `expected.json`;迴歸測試是一等公民。
4. **雙 SIEM 意識** — 單一來源、雙路輸出(Wazuh + Elastic),用同一份流量同時驗證兩套。

## 快速上手

```bash
# Engine + API(共用同一個 venv)
cd engine && python -m venv .venv && source .venv/bin/activate && pip install -e . -e ../api
cyberrange-api                    # http://127.0.0.1:8001

# Web UI
cd web && npm install && npm run dev   # http://localhost:3000

# 或直接用 CLI
cyberrange gen \
  --vendor fortinet --product fortios --version 7.4 --type traffic \
  --count 1000 --rate 50/s --sink udp://192.0.2.10:514
```

> 文件中的 IP 一律使用 RFC 5737 文件示例位址(`192.0.2.x`)。實際部署請透過 `.env` 的 `CYBERRANGE_ALLOWED_SINK_HOSTS` 設定自己的 sink 白名單 — 參考 `.env.example`。

## 目前狀態

積極開發中。Roadmap 包含:catalog 擴充(Azure AD 登入日誌)、SSE 任務串流、Triage Discipline 迴歸排程器、chain 模式攻擊行動 playbook — 專案慣例見 `CLAUDE.md`。

## 授權

Apache-2.0
