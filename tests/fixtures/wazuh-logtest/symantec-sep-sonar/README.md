# wazuh-logtest fixture — Symantec SEP SONAR(SEPM syslog)

Catalog: `catalog/symantec/endpoint-protection/14.x/sonar-detect.yaml`
Decoder(Phase 2 `name`): `symantec-sep-sonar`

新 decoder `decoders/symantec_sep_sonar_decoder.xml`(prematch 鎖 SONAR 欄位順序 `…risk found,Computer name:`,不碰 Risk Log sibling);rule 家族 `rules/local_symantec_sep_sonar.xml`。

Rule chain:`133200(decoded_as)→ 133210(已處置)/ 133211(未處置)/ 133212(HostFile)`

> 樣本是 manager 看到的 body(已去掉 syslog PRI `<NNN>`),由 catalog `render_one`
> 逐情境抽樣而來;每條對應一個 rule 情境。decoder / rule 檔位於 SOC 端 Wazuh manager
> 的 `etc/decoders/`、`etc/rules/`(bind-mount 目錄;logtest 立即可見,analysisd 要
> `wazuh-control restart` 才生效,restart 前先跑 `wazuh-analysisd -t`)。

## 跑這一組(repo root)

```bash
WAZUH_SSH=lab@192.0.2.10 WAZUH_CONTAINER=<wazuh-manager-container> \
  python scripts/wazuh_logtest_fixtures.py symantec-sep-sonar
# 全部 fixture 組
python scripts/wazuh_logtest_fixtures.py --all
```

## 手動跑單一 fixture

```bash
ssh lab@192.0.2.10 'docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' \
  < sample-heuristic-quarantined.log
```

## 通過條件(對 expected.json)

| Fixture | Phase 3 must fire |
|---|---|
| heuristic-quarantined | 133210(level ≥ 8) |
| heuristic-terminated | 133210(level ≥ 8) |
| heuristic-left-alone | 133211(level ≥ 10) |
| heuristic-all-failed | 133211(level ≥ 10) |
| hostfile-change | 133212(level ≥ 9) |

`phase2_observe` 是「decoder 抽到算 bonus」的觀察清單,**非 pass-fail**;Phase 3 rule fire 才是過關標準。
2026-09-14 基準:5/5 PASS(wazuh-logtest v4.14.4)。
2026-09-14 live-fire 基準:UDP 514 送 40 筆 → 40/40 落在本家族 rule(alerts.json 統計),無掉包、無被其他 rule 搶走。
