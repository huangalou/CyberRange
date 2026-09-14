# wazuh-logtest fixture — Trend Micro Apex Central Behavior Monitoring(BM:1000 CEF)

Catalog: `catalog/trendmicro/apex-one/14.x/behavior-monitoring.yaml`
Decoder(Phase 2 `name`): `trend-apex-central-bm`

新 decoder `decoders/trend_apex_central_bm_decoder.xml`(prematch 鎖 `|BM:`,AV / Web Reputation CEF sibling 不受影響);rule 家族 `rules/local_trendmicro_apex_bm.xml`,條件對 raw body 的 `cs2=<Policy>` token。

Rule chain:`133300(decoded_as)→ 133310–133314(依 cs2 policy 互斥)`

> 樣本是 manager 看到的 body(已去掉 syslog PRI `<NNN>`),由 catalog `render_one`
> 逐情境抽樣而來;每條對應一個 rule 情境。decoder / rule 檔位於 SOC 端 Wazuh manager
> 的 `etc/decoders/`、`etc/rules/`(bind-mount 目錄;logtest 立即可見,analysisd 要
> `wazuh-control restart` 才生效,restart 前先跑 `wazuh-analysisd -t`)。

## 跑這一組(repo root)

```bash
WAZUH_SSH=lab@192.0.2.10 WAZUH_CONTAINER=<wazuh-manager-container> \
  python scripts/wazuh_logtest_fixtures.py trendmicro-apex-behavior-monitoring
# 全部 fixture 組
python scripts/wazuh_logtest_fixtures.py --all
```

## 手動跑單一 fixture

```bash
ssh lab@192.0.2.10 'docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' \
  < sample-file-encrypt.log
```

## 通過條件(對 expected.json)

| Fixture | Phase 3 must fire |
|---|---|
| file-encrypt | 133310(level ≥ 12) |
| registry-persist | 133311(level ≥ 9) |
| hostfile-mod | 133311(level ≥ 9) |
| new-program | 133312(level ≥ 6) |
| dll-injection | 133313(level ≥ 9) |
| threat-behavior | 133314(level ≥ 8) |

`phase2_observe` 是「decoder 抽到算 bonus」的觀察清單,**非 pass-fail**;Phase 3 rule fire 才是過關標準。
2026-09-14 基準:6/6 PASS(wazuh-logtest v4.14.4)。
2026-09-14 live-fire 基準:UDP 514 送 40 筆 → 40/40 落在本家族 rule(alerts.json 統計),無掉包、無被其他 rule 搶走。

> Group 命名注意:Wazuh `<if_matched_group>` 是子字串比對。133311 的 group 用 `bm_persist_tamper`,
> 因為 `persistence`(連 `bm_persistence`)都會被 SOC 端既有的 supply-chain persistence 關聯規則吃走。
