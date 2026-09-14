# wazuh-logtest fixture — Sophos Central HMPA(行為軸)

Catalog: `catalog/sophos/endpoint/xg/hmpa-prevent.yaml`
Decoder(Phase 2 `name`): `sophos-central-endpoint`

沿用既有 SOC 端自訂 decoder `sophos-central-endpoint`(與 av-detect 共用),**不需要新 decoder**;只新增 rule 131120–131124 到 `rules/local_sophos_endpoint.xml`。

Rule chain:`131100 → 131103(group=RANSOMWARE)→ 131120/131121;131100 → 131122–131124(lvl 11 self-contained)`

> 樣本是 manager 看到的 body(已去掉 syslog PRI `<NNN>`),由 catalog `render_one`
> 逐情境抽樣而來;每條對應一個 rule 情境。decoder / rule 檔位於 SOC 端 Wazuh manager
> 的 `etc/decoders/`、`etc/rules/`(bind-mount 目錄;logtest 立即可見,analysisd 要
> `wazuh-control restart` 才生效,restart 前先跑 `wazuh-analysisd -t`)。

## 跑這一組(repo root)

```bash
WAZUH_SSH=lab@192.0.2.10 WAZUH_CONTAINER=<wazuh-manager-container> \
  python scripts/wazuh_logtest_fixtures.py sophos-hmpa-prevent
# 全部 fixture 組
python scripts/wazuh_logtest_fixtures.py --all
```

## 手動跑單一 fixture

```bash
ssh lab@192.0.2.10 'docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' \
  < sample-cryptoguard.log
```

## 通過條件(對 expected.json)

| Fixture | Phase 3 must fire |
|---|---|
| cryptoguard | 131120(level ≥ 12) |
| cryptoguard-smb | 131120(level ≥ 12) |
| cryptoguard-resolved | 131121(level ≥ 5) |
| exploit-prevented | 131122(level ≥ 11) |
| credguard | 131123(level ≥ 11) |
| privguard | 131124(level ≥ 11) |
| app-hijacking | 131124(level ≥ 11) |
| behaviour-prevented | 131124(level ≥ 11) |

`phase2_observe` 是「decoder 抽到算 bonus」的觀察清單,**非 pass-fail**;Phase 3 rule fire 才是過關標準。
2026-09-14 基準:8/8 PASS(wazuh-logtest v4.14.4)。
