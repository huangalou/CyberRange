# TeamPCP Pilot Runbook — FortiGate UTM Web Filter Detection

> Pilot of TeamPCP DetectOps rollout. Batch sprint adapts this runbook for 5 sibling catalogs (sysmon / auditd file / auditd execve / k8s-audit / cloudtrail).

## Purpose

把 catalog `catalog/fortinet/fortios/7.4/utm-webfilter-litellm-c2-teampcp.yaml` 渲染的 FortiGate UTM webfilter event 偵測為 TeamPCP IOC alert(custom rule 132010 level 12)。

## Prerequisites

- SSH passwordless:`lab@192.0.2.10`(Wazuh)、`lab@192.0.2.18`(ELK)
- Wazuh / ELK Docker stack 均在執行中(單機同時只跑一組 compose 的環境,確認未被切換停用)
- CyberRange engine venv:`~/Projects/CyberRange/engine/.venv` 啟用
- 伴生 SOC repo rule 已 in repo(companion SOC repo 對應 commit)
- Wazuh / ELK 端 service 全 healthy(`docker ps` 確認 manager / indexer / filebeat 全 running)

## Step 1 — Generate fixture sample logs

```bash
cd ~/Projects/CyberRange
source engine/.venv/bin/activate

cyberrange gen \
  --vendor fortinet --product fortios --version 7.4 \
  --log-type fortios.utm.webfilter.litellm_c2.teampcp \
  --count 50 \
  --sink file:///tmp/cyberrange-fixture-batch.log

FIX=tests/fixtures/wazuh-logtest/fortigate-utm-teampcp
grep -m1 'reqheader_xfilename="tpcp.tar.gz"' /tmp/cyberrange-fixture-batch.log > $FIX/sample-litellm-exfil-post.log
grep -m1 'hostname="checkmarx.zone"'          /tmp/cyberrange-fixture-batch.log > $FIX/sample-checkmarx-raw-poll.log
grep -m1 'logid="0315012544"'                  /tmp/cyberrange-fixture-batch.log > $FIX/sample-telnyx-wav-dl.log
grep -m1 'url=.*api/v1/heartbeat'              /tmp/cyberrange-fixture-batch.log > $FIX/sample-litellm-beacon-get.log
```

## Step 2 — Deploy rule XML to Wazuh manager (.10)

```bash
# 從伴生 SOC repo 本機 working copy scp
scp <soc-repo>/config/wazuh_manager/rules/local_fortigate_teampcp.xml \
    lab@192.0.2.10:<soc-repo>/config/wazuh_manager/rules/

# Dry-run(必跑)
ssh lab@192.0.2.10 "/usr/local/bin/docker exec <wazuh-manager-container> /var/ossec/bin/wazuh-analysisd -t"

# Restart manager 內 daemons(不是 docker compose restart)
ssh lab@192.0.2.10 "/usr/local/bin/docker exec <wazuh-manager-container> /var/ossec/bin/wazuh-control restart"

# Verify all daemons running
ssh lab@192.0.2.10 "/usr/local/bin/docker exec <wazuh-manager-container> /var/ossec/bin/wazuh-control status"

# Verify rule via wazuh-logtest(對 4 條 fixture 全跑)
for f in ~/Projects/CyberRange/tests/fixtures/wazuh-logtest/fortigate-utm-teampcp/sample-*.log; do
  echo "=== $(basename $f) ==="
  ssh lab@192.0.2.10 'docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' < $f
done
```

## Step 3 — Live-fire 50 events 雙送

```bash
cd ~/Projects/CyberRange
source engine/.venv/bin/activate

cyberrange gen \
  --vendor fortinet --product fortios --version 7.4 \
  --log-type fortios.utm.webfilter.litellm_c2.teampcp \
  --count 50 \
  --sink file:///tmp/pilot-fortigate-teampcp.log

# 雙送(.10 + .18)
for HOST in 192.0.2.10 192.0.2.18; do
  while IFS= read -r line; do
    echo -n "$line" | nc -u -w1 $HOST 514
  done < /tmp/pilot-fortigate-teampcp.log
done

sleep 15  # wait for ingest
```

## Step 4 — Verify + baseline 回寫

```bash
# Wazuh aggregation
ES_PW=$(grep ^INDEXER_PASSWORD <soc-repo>/.env | cut -d= -f2-)
curl -u "admin:$ES_PW" -k -s \
  "https://192.0.2.10:9200/wazuh-alerts-*/_search?size=0" \
  -H 'Content-Type: application/json' -d '{
    "query": { "bool": { "must": [
      { "range": { "@timestamp": { "gte": "now-30m" } } },
      { "terms": { "rule.id": ["81644", "112034", "132010"] } }
    ] } },
    "aggs": { "by_rule": { "terms": { "field": "rule.id", "size": 10 } } }
  }' | python3 -m json.tool

# Expected:
#   rule 132010: 38–46
#   rule 81644 + 112034 (or 1 of them): rest of 50

# ELK ingest verify (ELK uses HTTP not HTTPS; message field search since pipeline doesn't extract typed fields)
ELK_PW=$(ssh lab@192.0.2.18 'grep ^ELASTIC_PASSWORD <elk-stack-dir>/.env | cut -d= -f2-')
TODAY=$(date +%Y.%m.%d)
curl -u "elastic:$ELK_PW" -s \
  "http://192.0.2.18:9200/fortigate-$TODAY/_count" \
  -H 'Content-Type: application/json' -d '{
    "query": { "bool": { "must": [
      { "range": { "@timestamp": { "gte": "now-30m" } } },
      { "match": { "message": "FGT100E-LAB" } }
    ] } }
  }' | python3 -m json.tool

# Expected: count ≥ 38 (UDP loss tolerance, this lab seen 41/50 in Task 4, 50/50 in Task 5)

# 更新 catalog regression block 為實測值;見 spec section 6.3
```

## Live-fire 實測 baseline(pilot 2026-05-17)

- rule 132010 fired: 41/50 (82%, in range 38–46) ✅
- rule 112034 (SOC pre-existing custom) fired: 9/50 (non-IOC events, beacon scenarios)
- rule 81644 (stock UTM webfilter blocked): 0/50 (this lab — SOC 112034 chained ahead)
- Wazuh total: 50/50 ingested ✅
- ELK fortigate-* total: 50/50 (Task 4 saw 41/50 due to transient UDP loss) ✅
- ELK URL distribution: tpcp.tar.gz=19 / /raw=13 / /ringtone.wav=9 / /api/v1/heartbeat=9
  (weighted_choice 0.35/0.30/0.20/0.15 of 50)
- P95 TTD: 83945 ms — note this includes `nc -u -w1` dispatcher pacing (50 packets serialized over ~50s)
  First-packet delta ≈ 36s 比較接近 Wazuh 管線真值。Batch sprint 應用 parallel dispatcher 重 baseline。

## Known limitations (for batch sprint to address)

- **ELK ingest pipeline doesn't extract typed fields** for UTM webfilter — `url` / `logid` / `devname` 只在 `message` raw。filebeat fortinet module 有抽 `event.module=fortinet` / `event.dataset=fortinet.firewall` / `observer.product=FortiGate`,但 KV pairs 沒 expand 成 ECS。Batch sprint 應評估擴 `fortigate-entry` pipeline 加 KV → ECS mapping。
- **UDP packet loss** 在 .15 → .18 跨網段 Task 4 觀察到 ~18% (9/50),Task 5 重跑 0%。不穩定,Production deploy 應走 TCP syslog (1514/tcp) 或 filebeat 直連。
- **`<if_sid>` chain target 不同 UTM subtype 不同** — `type="utm" subtype="webfilter"` chain off 81644;ips / av / appcontrol / dlp 各 subtype 需個別 grep stock rule 確認 chain parent,不要假設 81620 / 81644 適用全 UTM。
- **TTD baseline 受 dispatcher 影響** — serialized `nc -u -w1` 把 50 packets 拉成 ~50s 線性序列,P95 反映 dispatcher 序列尾端而非單事件管線延遲。Batch sprint 可用 GNU parallel 或 Python asyncio dispatcher 拆掉 serialization 雜訊。

## Rollback

```bash
# 從 .10 移除 rule
ssh lab@192.0.2.10 'rm <soc-repo>/config/wazuh_manager/rules/local_fortigate_teampcp.xml'

# 從伴生 SOC repo 本機 git 也 revert
cd <soc-repo>
git revert <companion-SOC-repo-對應-commit>

# Wazuh restart
ssh lab@192.0.2.10 "/usr/local/bin/docker exec <wazuh-manager-container> /var/ossec/bin/wazuh-control restart"
```

## Cross-references

- Catalog : `catalog/fortinet/fortios/7.4/utm-webfilter-litellm-c2-teampcp.yaml`(CyberRange)
- Advisory: PYSEC-2026-2(Datadog Security Labs — TeamPCP supply-chain campaign)
- 伴生 SOC repo rule commit:(companion SOC repo 對應 commit)

## 已知 gotcha 對照

- 部署用 `wazuh-control restart`(從 container 內),**不是** `docker compose restart`(s6 不會 auto-restart daemons)
- `wazuh-analysisd -t` dry-run **必跑**(分析 config 失敗會 production CRITICAL)
- scp 個別檔,**不**用 rsync 整 repo(divergence 風險;.10 HEAD 可能落後本機)
- Wazuh `<field name="...">` 對 bare top-level decoded fields fails silently,用 `<match>` 對 raw body
- Wazuh os_regex 不認 PCRE shorthand,寫 regex 用 `type="pcre2"`
- 1514/tcp 是 Wazuh agent binary protocol,**不收 raw syslog**;raw syslog 走 **514/udp**(經 socat sidecar relay)
- ELK 在 .18 是 plain HTTP (port 9200),不是 HTTPS — curl 用 `http://` 不要用 `https://`
