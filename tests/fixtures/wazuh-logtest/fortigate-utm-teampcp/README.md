# wazuh-logtest fixture — fortigate utm webfilter (TeamPCP)

Catalog: `catalog/fortinet/fortios/7.4/utm-webfilter-litellm-c2-teampcp.yaml`

> **All commands assume cwd = this directory.** From repo root:
> `cd tests/fixtures/wazuh-logtest/fortigate-utm-teampcp/`

## 跑單一 fixture 對 .10 Wazuh

```bash
ssh lab@192.0.2.10 'docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' \
  < sample-litellm-exfil-post.log
```

Expected output(看 Phase 3):

```
**Phase 3: Completed filtering (rules).
        Rule id: '132010'
        Level: '12'
        Description: 'TeamPCP: FortiGate webfilter blocked event matched advisory IOC ...'
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

| Fixture | Phase 3 must fire | Must NOT fire |
|---|---|---|
| litellm-exfil-post  | 132010(level 12,terminal — chain off 81644) | — |
| checkmarx-raw-poll  | 132010(level 12,terminal — chain off 81644) | — |
| telnyx-wav-dl       | 132010(level 12,terminal — chain off 81644) | — |
| litellm-beacon-get  | (whatever stock/custom fires) | 132010 |

`phase2_observe` 是「若 decoder 抽到算 bonus」的觀察清單,**非 pass-fail**;phase3 rule fire 才是過關標準。
