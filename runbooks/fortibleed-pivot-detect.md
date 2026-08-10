# FortiBleed Pivot Runbook — SSL VPN Valid-Account Login → AD Account Creation

> FortiBleed 攻擊鏈 S3→S4 偵測 runbook。ELK EQL 為 pivot 主偵測器；Wazuh 僅覆蓋 S3（SSL VPN tunnel-up）。

## Purpose

把 FortiBleed 攻擊鏈兩個可觀測 stage 的 fixture log 送進伴生 SOC stack（Wazuh + ELK），驗證偵測規則生效：

- **S3**：`logid=0101039947`（SSL VPN tunnel-up，jchen 從未知 remip 登入）→ Wazuh rule 132080 + ELK auto-route `fortigate-*`
- **S4**：Windows Security 4720（jchen 在 WIN-DC01 建立 svc_backdoor$ 帳號）→ ELK auto-route `windows-sec-*` + EQL sequence signal

**S2（離線爆破）無 log，此階段 SOC 應為盲，偵測極限在此；勿假設無 log = 未被破。**

---

## 偵測現實（誠實說明，runbook 不 overclaim）

本 runbook 基於 Task 6 live-fire 真實結果：

| 系統 | 事件 | 結果 | 說明 |
|------|------|------|------|
| Wazuh | S3 rule 132080 | ✅ fire，TTD < 10s | SSL VPN tunnel-up，`dstuser=jchen` |
| Wazuh | S4 rule 131021 | ❌ syslog 路徑不 fire | Windows JSON-over-syslog，`winlog.event_data.*` 不被解碼；需 Winlogbeat/agent transport |
| Wazuh | rule 132085 | ❌ dormant by design | `if_matched_sid` 掛 FortiGate chain，結構上不評估 Windows JSON 事件，無法跨源 fire |
| ELK | EQL sequence signal | ✅ 觸發，TTD ~210s | `sequence by user.name maxspan=15m`，fortigate-* + windows-sec-* 均含 `user.name=jchen`；signal 為 pivot 主偵測 |

**關於 132085**：此規則是「關聯意圖」文件化規則（`if_matched_sid` co-occurrence 設計，rule-tree 掛 FortiGate chain child），不是 CDB lookup 規則。因 Wazuh 架構上無法對 Windows JSON-over-syslog 事件做跨源欄位比對，**跨源 pivot 關聯由 ELK EQL 負責**。

---

## 環境

| 服務 | Host | 端點 |
|------|------|------|
| Wazuh Manager (syslog ingest 514/udp) | lab Mac mini `192.0.2.10` | UDP 514（socat sidecar relay → analysisd） |
| Wazuh Indexer API | `192.0.2.10` | `https://192.0.2.10:9200` |
| Wazuh Dashboard | `192.0.2.10` | `https://192.0.2.10:443` |
| ELK filebeat (syslog ingest) | `192.0.2.10` | TCP/UDP `9514` |
| Elasticsearch | `192.0.2.10` | `http://192.0.2.10:9201` |
| Kibana | `192.0.2.10` | `http://192.0.2.10:5602` |

> **注意**：ELK 已從 MacBook (.18) 搬至 .10 Mac mini Docker。`.18` 端點已退役，勿使用。

SSH 連線：`ssh lab@192.0.2.10`（passwordless）

Manager container 名稱：`<wazuh-manager-container>`

---

## Prerequisites

- SSH passwordless：`lab@192.0.2.10`
- CyberRange engine venv 啟用：`~/Projects/CyberRange/engine/.venv`
- Wazuh + ELK 全容器 healthy（`ssh lab@192.0.2.10 "export PATH=/usr/local/bin:$PATH && docker ps"` 確認）
- 伴生 SOC repo 本機 working copy 含 `local_fortigate_sslvpn.xml`（rules 132080 + 132085）
- Kibana 已匯入 `fortibleed-pivot-sequence.ndjson` detection rule

---

## Step 1 — 確認 fixture 存在（不需要重新生成）

```bash
ls ~/Projects/CyberRange/tests/fixtures/wazuh-logtest/sslvpn-pivot-fortibleed/
# 應有：s3-sslvpn-auth-success.log  s4-4720-account-create.log
```

> **重要**：`--log-type fortios.event.vpn.sslvpn_auth.fortibleed` 的 `user` 欄位使用 `choices` pool；CLI `--param` 模式會從 pool 隨機抽單字元，無法固定 `user=jchen`。**請直接使用既有 fixture 檔**，不要重新 gen。
>
> 如需更換 fixture，手工 craft 並確保 `user="jchen"` 固定。

S3 fixture 格式確認（應含）：
```
logid=0101039947 type=event subtype=vpn ... action=tunnel-up ... user="jchen" ...
```

S4 fixture 格式確認（應含）：
```json
{"winlog":{"event_id":4720,"event_data":{"SubjectUserName":"jchen","TargetUserName":"svc_backdoor$"}}, ...}
```

---

## Step 2 — Deploy Wazuh rule XML（含 132080 + 132085）

```bash
# scp 個別 rule 檔到 .10（不用 rsync 整 repo，避免 divergence）
scp <soc-repo>/config/wazuh_manager/rules/local_fortigate_sslvpn.xml \
    lab@192.0.2.10:<soc-repo>/config/wazuh_manager/rules/

# Dry-run（必跑，config 錯誤會產 production CRITICAL）
ssh lab@192.0.2.10 \
  "export PATH=/usr/local/bin:$PATH && docker exec <wazuh-manager-container> /var/ossec/bin/wazuh-analysisd -t"

# Restart daemons（從 container 內執行，不是 docker compose restart）
ssh lab@192.0.2.10 \
  "export PATH=/usr/local/bin:$PATH && docker exec <wazuh-manager-container> /var/ossec/bin/wazuh-control restart"

# 確認 daemons running
ssh lab@192.0.2.10 \
  "export PATH=/usr/local/bin:$PATH && docker exec <wazuh-manager-container> /var/ossec/bin/wazuh-control status"
```

### Logtest 驗證（S3 fixture）

```bash
ssh lab@192.0.2.10 \
  "export PATH=/usr/local/bin:$PATH && docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest" \
  < ~/Projects/CyberRange/tests/fixtures/wazuh-logtest/sslvpn-pivot-fortibleed/s3-sslvpn-auth-success.log
# 預期：Phase 3 id: '132080', level: '8'
```

> logtest 直餵 raw line 對 132080 會綠。**S4 fixture 對 Wazuh logtest 不適用**（需 Winlogbeat agent transport 才能正確解碼 `winlog.event_data.*`）。

---

## Step 3 — Deploy ELK pipeline + detection rule

### 3a — Ingest pipeline（fortibleed-user-normalize）

```bash
# 確認 pipeline 存在
curl -s http://192.0.2.10:9201/_ingest/pipeline/fortibleed-user-normalize | python3 -m json.tool

# 如需重新匯入：
ELK_PW=$(ssh lab@192.0.2.10 'cat <soc-repo>/.env | grep ELASTIC_PASSWORD | cut -d= -f2-')
curl -X PUT -u "elastic:$ELK_PW" \
  "http://192.0.2.10:9201/_ingest/pipeline/fortibleed-user-normalize" \
  -H 'Content-Type: application/json' \
  -d @<soc-repo>/elk-stack/ingest-pipelines/fortibleed-user-normalize.json
```

### 3b — Auto-route pipeline

```bash
# 確認 auto-route 含 fortibleed branch
curl -s http://192.0.2.10:9201/_ingest/pipeline/auto-route | python3 -m json.tool | grep fortibleed
# 應有 fortibleed-user-normalize 分支
```

### 3c — soc-ecs pipeline（windows-sec-* index routing）

```bash
# 確認 pipeline 含 windows.security routing
curl -s http://192.0.2.10:9201/_ingest/pipeline/soc-ecs | python3 -m json.tool | grep windows
```

### 3d — EQL detection rule（Kibana）

```bash
# 匯入 ndjson（Kibana Stack Management > Saved Objects > Import）
# 或使用 API：
KBN_PW=$(ssh lab@192.0.2.10 'cat <soc-repo>/.env | grep ELASTIC_PASSWORD | cut -d= -f2-')
curl -X POST -u "elastic:$KBN_PW" \
  "http://192.0.2.10:5602/api/saved_objects/_import" \
  -H 'kbn-xsrf: true' \
  --form file=@<soc-repo>/elk-stack/kibana/detection-rules/fortibleed-pivot-sequence.ndjson
# Rule: "FortiBleed pivot — SSL VPN valid-account login → AD account creation"
# Rule ID: <kibana-rule-uuid>
# EQL: sequence by user.name maxspan=15m [fortigate-* action=tunnel-up] [windows-sec-* event.code=4720]
# Interval: 300s
```

---

## Step 4 — Dispatch：雙送（Wazuh 514/udp + ELK 9514/tcp）

```bash
FIX=~/Projects/CyberRange/tests/fixtures/wazuh-logtest/sslvpn-pivot-fortibleed

# S3 → Wazuh (UDP 514)
nc -u -w1 192.0.2.10 514 < $FIX/s3-sslvpn-auth-success.log

# S3 → ELK (TCP 9514)
nc -w1 192.0.2.10 9514 < $FIX/s3-sslvpn-auth-success.log

# 等 2s 確保 S3 先到（EQL sequence 要求 S3 在前）
sleep 2

# S4 → Wazuh (UDP 514) — 到達 Wazuh archives 但 rule 不 fire（已知限制）
nc -u -w1 192.0.2.10 514 < $FIX/s4-4720-account-create.log

# S4 → ELK (TCP 9514)
nc -w1 192.0.2.10 9514 < $FIX/s4-4720-account-create.log

echo "送出完成。Wazuh 132080 應 < 10s；ELK EQL signal 在下個 300s interval 產生（最多 ~210s）。"
```

---

## Step 5 — Verify

### 5a — Wazuh 132080 命中（S3）

```bash
WZ_PW=$(ssh lab@192.0.2.10 'grep INDEXER_PASSWORD <soc-repo>/.env | cut -d= -f2-')
TODAY=$(date +%Y.%m.%d)

# 查 132080 alerts
curl -u "admin:$WZ_PW" -k -s \
  "https://192.0.2.10:9200/wazuh-alerts-*/_search?size=5" \
  -H 'Content-Type: application/json' -d '{
    "sort": [{"@timestamp": "desc"}],
    "query": {"bool": {"must": [
      {"range": {"@timestamp": {"gte": "now-15m"}}},
      {"term": {"rule.id": "132080"}}
    ]}}
  }' | python3 -m json.tool | grep -E '"rule.id"|dstuser|@timestamp'
# 預期：rule.id=132080，dstuser=jchen
```

### 5b — Wazuh 131021 / 132085（預期 0）

```bash
# 這兩條在真實 syslog 路徑下 hits = 0（已知架構限制）
curl -u "admin:$WZ_PW" -k -s \
  "https://192.0.2.10:9200/wazuh-alerts-*/_search?size=0" \
  -H 'Content-Type: application/json' -d '{
    "query": {"bool": {"must": [
      {"range": {"@timestamp": {"gte": "now-15m"}}},
      {"terms": {"rule.id": ["131021", "132085"]}}
    ]}},
    "aggs": {"by_rule": {"terms": {"field": "rule.id"}}}
  }' | python3 -m json.tool
# 預期：aggregations buckets 空（0 hits）
# 131021：Wazuh syslog 路徑不解碼 winlog.event_data.*，需 Winlogbeat agent
# 132085：if_matched_sid co-occurrence rule，掛 FortiGate chain，結構上無法評估 Windows json
```

### 5c — ELK S3 ingest 確認

```bash
ELK_PW=$(ssh lab@192.0.2.10 'grep ELASTIC_PASSWORD <soc-repo>/.env | cut -d= -f2-')
TODAY=$(date +%Y.%m.%d)

curl -u "elastic:$ELK_PW" -s \
  "http://192.0.2.10:9201/fortigate-$TODAY/_search?size=3" \
  -H 'Content-Type: application/json' -d '{
    "sort": [{"@timestamp": "desc"}],
    "query": {"bool": {"must": [
      {"range": {"@timestamp": {"gte": "now-15m"}}},
      {"term": {"user.name": "jchen"}},
      {"term": {"event.action": "tunnel-up"}}
    ]}}
  }' | python3 -m json.tool | grep -E '"user.name"|event.action|@timestamp'
# 預期：user.name=jchen，event.action=tunnel-up
```

### 5d — ELK S4 ingest 確認

```bash
curl -u "elastic:$ELK_PW" -s \
  "http://192.0.2.10:9201/windows-sec-$TODAY/_search?size=3" \
  -H 'Content-Type: application/json' -d '{
    "sort": [{"@timestamp": "desc"}],
    "query": {"bool": {"must": [
      {"range": {"@timestamp": {"gte": "now-15m"}}},
      {"term": {"user.name": "jchen"}},
      {"term": {"event.code": "4720"}}
    ]}}
  }' | python3 -m json.tool | grep -E '"user.name"|event.code|user.target.name|@timestamp'
# 預期：user.name=jchen，event.code=4720，user.target.name=svc_backdoor$
```

### 5e — EQL signal（等下個 300s interval 後查）

```bash
# 查 Kibana detection engine signals
curl -u "elastic:$ELK_PW" -s \
  "http://192.0.2.10:9201/.alerts-security.alerts-default/_search?size=5" \
  -H 'Content-Type: application/json' -d '{
    "sort": [{"@timestamp": "desc"}],
    "query": {"bool": {"must": [
      {"range": {"@timestamp": {"gte": "now-30m"}}},
      {"term": {"kibana.alert.rule.rule_id": "<kibana-rule-uuid>"}}
    ]}}
  }' | python3 -m json.tool | grep -E 'user.name|signal|@timestamp' | head -20
# 預期：signal 1 筆（user.name=jchen）；若測試殘留多筆 4720 doc 可能出現 >1 signal
```

---

## Time-to-Detect（Live-fire baseline 2026-06-19）

| 系統 | 事件 | Time-to-Detect | 備註 |
|------|------|----------------|------|
| Wazuh | 132080 SSL VPN tunnel-up | **< 10s** | UDP 514 → socat → analysisd；@timestamp 反映 log 事件時間 |
| ELK | EQL sequence signal (pivot) | **~210s** | 受 300s rule interval 排程；ingest latency 本身 < 2s |

ELK 的 210s 不是 ingest 延遲，而是 EQL rule 排程等待（最壞情況接近 300s；平均 210s）。

---

## S2 盲點說明（重要）

**FortiBleed S2 階段（離線爆破）無 log 可觀測。**

攻擊者從 SSL VPN 記憶體 dump（FortiBleed CVE-2024-21762 漏洞）取得 credential material，在攻擊者端離線爆破 PBKDF2 hash，不與任何 SOC-visible 系統互動。

此階段 SOC 應視為偵測盲區。**勿假設「沒有 S2 alert」= 攻擊者未取得密碼**。S3（合法帳號成功登入 VPN）才是第一個可觀測信號。

SOC 推薦對策：geo anomaly / off-hours SSL VPN 登入基線告警（OOTB rule 81622 level 3 可用於建基線）；搭配 rule 132080 level 8 提高告警優先級。

---

## Known Limitations

1. **Wazuh 無法做跨源 pivot 關聯**：`dstuser`（FortiGate decoded）≠ `winlog.event_data.SubjectUserName`（Windows JSON），`same_field` 或 `if_matched_sid` 均無法跨越兩個欄位命名空間。**Cross-source pivot 唯一可靠路徑：ELK EQL**，透過 `fortibleed-user-normalize` pipeline 將兩源 normalize 到 `user.name` 後做 sequence join。

2. **Wazuh 對 Windows 4720 的偵測需 Winlogbeat**：S4 JSON blob 透過 UDP 514 → socat → Wazuh 路徑，Wazuh 的 JSON decoder 不能在 syslog envelope 內解析 `winlog.event_data.*`。如需 131021 在 Wazuh 端 fire，Windows DC 必須部署 Winlogbeat agent 或 Logstash 前處理。

3. **EQL 多 signal**：若測試殘留的 windows-sec-* index 含多筆 `user.name=jchen` + `event.code=4720` 的歷史 doc，900s EQL 窗內可能產 > 1 signal。生產環境應清理測試殘留或縮短 EQL 窗。

4. **132085 dormant by design**：本規則記錄設計意圖（co-occurrence intent），不是可 fire 的偵測規則。文件化保留，不需移除。

---

## Rollback

### Wazuh

```bash
# 移除 rule XML
ssh lab@192.0.2.10 \
  'rm <soc-repo>/config/wazuh_manager/rules/local_fortigate_sslvpn.xml'

# Restart daemons
ssh lab@192.0.2.10 \
  "export PATH=/usr/local/bin:$PATH && docker exec <wazuh-manager-container> /var/ossec/bin/wazuh-control restart"

# 若 git revert 需要（伴生 SOC repo）：
# cd <soc-repo> && git log --oneline | head -5
# git revert <commit-that-added-132080-132085>
```

### ELK

```bash
ELK_PW=$(ssh lab@192.0.2.10 'grep ELASTIC_PASSWORD <soc-repo>/.env | cut -d= -f2-')

# 移除 fortibleed-user-normalize pipeline
curl -X DELETE -u "elastic:$ELK_PW" \
  "http://192.0.2.10:9201/_ingest/pipeline/fortibleed-user-normalize"

# 還原 auto-route（移除 fortibleed branch）— 重新匯入無 fortibleed 分支版本
curl -X PUT -u "elastic:$ELK_PW" \
  "http://192.0.2.10:9201/_ingest/pipeline/auto-route" \
  -H 'Content-Type: application/json' \
  -d @<soc-repo>/elk-stack/ingest-pipelines/auto-route.json

# 還原 soc-ecs（若有改動）
curl -X PUT -u "elastic:$ELK_PW" \
  "http://192.0.2.10:9201/_ingest/pipeline/soc-ecs" \
  -H 'Content-Type: application/json' \
  -d @<soc-repo>/elk-stack/ingest-pipelines/soc-ecs.json

# Reload pipelines（讓 filebeat 拿到新 pipeline config）
curl -X POST -u "elastic:$ELK_PW" \
  "http://192.0.2.10:9201/_ingest/pipeline/_simulate" \
  -H 'Content-Type: application/json' -d '{}'

# 移除 Kibana EQL detection rule（Stack Management > Rules > 搜 "FortiBleed" > Delete）
# 或 API：
KBN_PW=$ELK_PW
curl -X DELETE -u "elastic:$KBN_PW" \
  "http://192.0.2.10:5602/api/detection_engine/rules?rule_id=<kibana-rule-uuid>" \
  -H 'kbn-xsrf: true'
```

---

## Cross-references

| 資產 | 路徑 |
|------|------|
| S3 Catalog | `catalog/fortinet/fortios/7.4/fortios.event.vpn.sslvpn_auth.fortibleed.yaml` |
| S3 fixture | `tests/fixtures/wazuh-logtest/sslvpn-pivot-fortibleed/s3-sslvpn-auth-success.log` |
| S4 fixture | `tests/fixtures/wazuh-logtest/sslvpn-pivot-fortibleed/s4-4720-account-create.log` |
| Live-fire baseline | `tests/fixtures/wazuh-logtest/sslvpn-pivot-fortibleed/live-fire-baseline.json` |
| Wazuh rule file | `<soc-repo>: config/wazuh_manager/rules/local_fortigate_sslvpn.xml` |
| ELK pipeline | `<soc-repo>: elk-stack/ingest-pipelines/fortibleed-user-normalize.json` |
| EQL detection rule | `<soc-repo>: elk-stack/kibana/detection-rules/fortibleed-pivot-sequence.ndjson` |

## 已知 gotcha 對照

- 部署用 `wazuh-control restart`（從 container 內），**不是** `docker compose restart`（s6 不會 auto-restart daemons）
- `wazuh-analysisd -t` dry-run **必跑**（config 錯誤會 production CRITICAL）
- ELK 在 .10 是 plain HTTP（port 9201），不是 HTTPS — curl 用 `http://` 且 port 9201
- Kibana 在 .10 port 5602（容器內 5601 → host 5602）
- `.10` host 的 docker 指令需 `export PATH=/usr/local/bin:$PATH`
- S3 fixture `user` 欄位必須固定為 `jchen`（CLI choices pool 會隨機抽，不保證 jchen）
- EQL rule interval 300s；送完 log 後最多等 ~300s 才看到 signal
