# wazuh-logtest fixture — auditd file-create (TeamPCP)

Catalog: `catalog/linux/auditd/3.x/file-create-teampcp.yaml`

## 取樣方式

3 條 fixture 是 deterministic hand-crafted — 用 catalog template 對應 3 個 IOC scenario
(`sysmon_py` / `sysmon_service` / `tmp_pglog`)各 render 一個完整 5-record audit event,
serial 固定為 200001/200002/200003,inode/pid/ses 都用固定 value,確保 reproducible。

也可用 cyberrange CLI 隨機抽樣:

```bash
./engine/.venv/bin/cyberrange gen --vendor linux --product auditd --version 3.x \
  --log-type auditd.file_create.teampcp --count 100 --sink file:///tmp/auditd-batch.log
# 然後用 awk 對 audit serial group,grep 含特定 IOC path 的 SYSCALL/PATH line 抽出對應 5 line
```

deterministic 抽法在 sibling 2 採用,因為 audit event 5-record 共享 serial 的 grep + group 邏輯
比 sibling 1(JSON-in-syslog 1 line per event)複雜,deterministic fixture 對 logtest 更乾淨。

## 為什麼剝 syslog header

fixture 是給本機 `wazuh-logtest` pipe stdin 用,raw pipe 不會經過 wazuh-logcollector 的
RFC3164 剝離。剝掉 `<PRI>RFC3164_TS HOST ` 後 stock `auditd` decoder 直接命中
`kernel:` prematch,抽出 audit field 給 rule 用。Live-fire 真實 syslog ingest 時
logcollector 會自動剝 header。

> **All commands assume cwd = this directory.** From repo root:
> `cd tests/fixtures/wazuh-logtest/file-create-teampcp/`

## 跑單一 fixture 對 .10 Wazuh

```bash
ssh lab@192.0.2.10 'docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' \
  < sample-auditd-sysmon-py.log
```

Expected output(看 Phase 3,fixture 5-line 會 dispatch 5 次,其中 PATH CREATE 那條應命中 132030):

```
**Phase 3: Completed filtering (rules).
        Rule id: '132030'
        Level: '11'
        Description: 'TeamPCP — auditd file-create IOC path'
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

| Fixture | Phase 3 must fire | IOC path |
|---|---|---|
| auditd-sysmon-py        | 132030(level 11) | `~/.config/sysmon/sysmon.py` |
| auditd-sysmon-service   | 132030(level 11) | `~/.config/systemd/user/sysmon.service` |
| auditd-tmp-pglog        | 132030(level 11) | `/tmp/pglog` |

`phase2_observe` 是「若 decoder 抽到算 bonus」的觀察清單,**非 pass-fail**;phase3 rule fire 才是過關標準
(rule 走 raw <match> + pcre2,不依賴 phase 2 field 抽取)。

## Wazuh 端 rule 部署

Rule XML 落在 伴生 SOC repo(<soc-repo>)的 `config/wazuh_manager/rules/local_auditd_teampcp.xml`:
- rule 132029 level-0 anchor: `<match>kernel: type=PATH</match>`
- rule 132030 level 11: `<if_sid>132029</if_sid>` + `<match type="pcre2">(\.config/sysmon/sysmon\.py|\.config/systemd/user/sysmon\.service|site-packages/litellm_init\.pth|/tmp/pglog|/tmp/\.pg_state)</match>`

部署 SOP 與 fortigate-utm-teampcp fixture 相同(見該 README)。
