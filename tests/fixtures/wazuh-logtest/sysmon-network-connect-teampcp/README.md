# wazuh-logtest fixture — sysmon network-connect (TeamPCP)

Catalog: `catalog/microsoft/windows/2022/sysmon-network-connect-teampcp.yaml`
取樣指令:
```bash
cyberrange gen --vendor microsoft --product windows --version 2022 \
  --log-type sysmon-network-connect-teampcp --count 50 \
  --sink file:///tmp/sysmon-batch.log
grep -m1 'models.litellm.cloud' /tmp/sysmon-batch.log | \
  sed -E 's/^<[0-9]+>[A-Z][a-z]+ [0-9]+ [0-9:]+ [^ ]+ //' \
  > sample-sysmon-exfil-litellm.log
# 同理 checkmarx.zone / 83.142.209.203
```

> **Why strip syslog header?**:fixture 是給本機 `wazuh-logtest` 用,raw pipe
> 不會經過 wazuh-logcollector 的 RFC3164 剝離。剝掉後 stock `json` decoder
> 直接匹配 `^\{` prematch,抽出 `winlog.event_data.*` 給 rule 用。
> Live-fire 真實 syslog ingest 時 logcollector 會自動剝 header。

> **All commands assume cwd = this directory.** From repo root:
> `cd tests/fixtures/wazuh-logtest/sysmon-network-connect-teampcp/`

## 跑單一 fixture 對 .10 Wazuh

```bash
ssh lab@192.0.2.10 'docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' \
  < sample-sysmon-exfil-litellm.log
```

Expected output(看 Phase 3):

```
**Phase 3: Completed filtering (rules).
        Rule id: '132020'
        Level: '12'
        Description: 'TeamPCP — Sysmon NetworkConnect to known C2 hostname'
```

## 跑全部 3 條

```bash
for f in sample-*.log; do
  echo "=== $f ==="
  ssh lab@192.0.2.10 'docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' < $f
  echo
done
```

## 通過條件(對 expected.json)

| Fixture | Phase 3 must fire | Notes |
|---|---|---|
| sysmon-exfil-litellm     | 132020(level 12) | DestinationHostname=`models.litellm.cloud` |
| sysmon-beacon-checkmarx  | 132020(level 12) | DestinationHostname=`checkmarx.zone` |
| sysmon-wav-stage-telnyx  | 132021(level 12) | DestinationIp=`83.142.209.203`(raw IP IOC) |

`phase2_observe` 是「若 decoder 抽到算 bonus」的觀察清單,**非 pass-fail**;phase3 rule fire 才是過關標準。

## Wazuh 端 rule 部署

Rule XML 落在 伴生 SOC repo(<soc-repo>)的 `wazuh/etc/rules/local_sysmon_teampcp.xml`:
- rule 132020 `if_sid 61606` + `<field DestinationHostname pcre2>^(models\.litellm\.cloud|checkmarx\.zone)$`
- rule 132021 `if_sid 61606` + `<field DestinationIp pcre2>^(83\.142\.209\.(203|11)|46\.151\.182\.203)$`

部署 SOP 與 fortigate-utm-teampcp fixture 相同(見該 README)。
