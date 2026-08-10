# wazuh-logtest fixture — AWS CloudTrail credential-abuse (TeamPCP)

Catalog: `catalog/aws/cloudtrail/2.0/credential-abuse-teampcp.yaml`

## 取樣方式

4 條 fixture 是 deterministic hand-crafted — 依 catalog template line 310 結構各 render 一個完整 CloudTrail JSON record(eventVersion 1.11,含 tlsDetails + sessionContext),
時間戳 / UUID / accessKeyId / principalId 全固定,reproducible。

CloudTrail wire form 是純 JSON line(無 syslog 前綴),`transport: [beats, file]`,不過 socat UDP。直接 pipe stdin 給 wazuh-logtest。

> **All commands assume cwd = this directory.** From repo root:
> `cd tests/fixtures/wazuh-logtest/cloudtrail-credential-abuse-teampcp/`

## 跑單一 fixture

```bash
ssh lab@192.0.2.10 'docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' \
  < sample-cloudtrail-creds-validation-teampcp-infra.log
```

Expected output(看 Phase 3):

```
**Phase 3: Completed filtering (rules).
        Rule id: '132060'
        Level: '12'
        Description: 'TeamPCP — CloudTrail API call from known C2 source IP'
```

## 跑全部 4 條

```bash
for f in sample-*.log; do
  echo "=== $f ==="
  ssh lab@192.0.2.10 'docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' < $f
  echo
done
```

## 通過條件(對 expected.json)

| Fixture | Must fire | Must NOT fire | Axis |
|---|---|---|---|
| cloudtrail-creds-validation-teampcp-infra | **132060**(level 12) | 132061 | source_ip 軸(83.142.209.203;UA=aws-cli) |
| cloudtrail-iam-enum-pythonurllib          | **132061**(level 12) | 132060 | UA+eventName 軸(192.0.2.55 非 IOC;Python-urllib + ListAccessKeys) |
| cloudtrail-privesc-double-axis            | **132060 + 132061**(level 12) | —     | **雙軸**(83.142.209.11 + Python-urllib + AssumeRole) |
| cloudtrail-secret-access-teampcp-infra    | **132060**(level 12) | 132061 | source_ip 軸(46.151.182.203;UA=Boto3) |

132060 fire 3/4,132061 fire 2/4,雙 fire 1/4。

`phase2_observe` 是「若 decoder 抽到算 bonus」的觀察清單,**非 pass-fail**;phase3 rule fire 才是過關標準
(rule 走 raw `<match type=pcre2>` 對 JSON message body 比對,不依賴 phase 2 field 抽取)。

## Wazuh 端 rule 部署

Rule XML 落在 伴生 SOC repo(<soc-repo>)的 `config/wazuh_manager/rules/local_aws_cloudtrail_teampcp.xml`:
- rule 132059 level-0 anchor: `<match>"eventVersion":"</match>`(對任何 CloudTrail JSON line 命中)
- rule 132060 level 12: `<if_sid>132059</if_sid>` + pcre2 source_ip 軸:
  - `"sourceIPAddress":"(83\.142\.209\.203|83\.142\.209\.11|46\.151\.182\.203)"`
- rule 132061 level 12: `<if_sid>132059</if_sid>` + pcre2 UA+eventName 組合軸:
  - `"eventName":"(GetCallerIdentity|ListAccessKeys|AssumeRole|GetSecretValue|DescribeInstances|ListBuckets)".*"userAgent":"Python-urllib`

部署 SOP 與 fortigate-utm-teampcp fixture 相同(見該 README)。

## Live-fire blocker(catalog `live_fire_pending=true`)

無 AWS 環境;真實 cloudtrail event 來源需要:
1. AWS account + CloudTrail trail 寫 S3
2. SQS notification + ArcSight SmartConnector(CEF 變體)OR filebeat aws module(JSON 變體)
3. Wazuh integration 或 ELK aws ingest pipeline

本 fixture-only 驗收建立 wazuh-logtest 端 deterministic baseline;Sprint 2 或日後接 AWS lab 環境再補 live-fire 量測。
