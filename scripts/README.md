# scripts/ — verification helpers

實機驗證 CyberRange → 伴生 SOC stack（Wazuh + ELK）雙送通路用的可貼可跑腳本。
本目錄不含應用程式邏輯,只放離線檢查 / SSH 過去手動跑的工具。

## 雙送驗證

### A. 連通性 + dispatch probe(在 lab@192.0.2.10 跑)

```bash
ssh lab@192.0.2.10
cd ~/CyberRange

# 預設打到本機 8001 API,不經過 reverse proxy — 排除 nginx 變數
./scripts/verify-sinks.sh

# 若要連帶驗證 reverse proxy 路徑與 Basic Auth:
API_BASE=https://bas.example.com \
BASIC_USER=admin BASIC_PASS='<from-1password>' \
./scripts/verify-sinks.sh
```

預期輸出:8 條 `[OK]`(4 條連通性 + 4 條 probe sent)+ 2 個 dispatch job_id。

### B-1. Wazuh 端反查(在 .10 跑)

```bash
ssh lab@192.0.2.10  # 或 ssh 192.0.2.10
sudo INDEXER_PASS='<wazuh-admin-pass>' \
  /path/to/CyberRange/scripts/check-ingest-wazuh.sh
```

三層確認:
1. `archives.log` — raw ingest 有沒有進來
2. `alerts.log` — decoder 解得開、rule 觸發
3. `wazuh-alerts-*` — 進到 Indexer

任何一層 0 hits → 上游有問題:
- 1 為 0 → CyberRange 端封包根本沒到(ACL / VIP / 路由)
- 2 為 0 → 進來了但 decoder 不認得 — 預期,等 catalog ↔ decoder 對映完成
- 3 為 0 → 有 alert 但沒進 indexer — Wazuh manager 內部問題

### B-2. ELK 端反查(.18 或任何能 reach 9200 的地方)

```bash
./scripts/check-ingest-elk.sh

# 限定特定廠牌:
SEARCH_TERM="FortiGate" ./scripts/check-ingest-elk.sh
SEARCH_TERM="PAN-OS" WINDOW=1h ./scripts/check-ingest-elk.sh
```

預期 `total_hits >= 1`,並印出最近 3 筆的 `_source` 預覽。

## 常見坑

| 症狀 | 排查 |
|---|---|
| `verify-sinks.sh` UDP 全部 OK 但 reverse query 0 hits | UDP 是 fire-and-forget,nc 報 OK 不代表對端有 listener。改 TCP/1514 重試 |
| dispatch 回 401 | 環境變數 `BASIC_USER` / `BASIC_PASS` 沒傳,或 hash 跟 .env 對不上 |
| `[WARN] cannot read /var/ossec/logs/archives/archives.log` | Wazuh 預設不開 archives,需要 `<logall>yes</logall>` 加進 ossec.conf 才會記 |
| ELK 有 hits 但 `message` 空白 | Filebeat strip_priority processor 拔掉 PRI 之後 message 欄被搬到 `event.original`,腳本已 fallback 顯示 |
