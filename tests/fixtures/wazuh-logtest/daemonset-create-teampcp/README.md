# wazuh-logtest fixture — k8s-audit DaemonSet create (TeamPCP)

Catalog: `catalog/kubernetes/k8s-audit/1.x/daemonset-create-teampcp.yaml`
對齊 rule: `<soc-repo>/config/wazuh_manager/rules/k8s-lateral-anomaly.xml`

## Sibling 4 的特殊性 — 不寫新 rule、不 deploy、不 live-fire

跟 Sibling 1-3 不同:

| 面向 | Sibling 1-3 | Sibling 4 |
|---|---|---|
| Rule 來源 | 寫新伴生 SOC repo rule(132020-132040)| **既有 `k8s-lateral-anomaly.xml`**(112501-112510 forward-ready,2026-05-15 落地)|
| Decoder 路徑 | socat-relay UDP → custom decoder + raw `<match type=pcre2>` | Wazuh 內建 `json` decoder 自動 flatten + `<field name="objectRef.resource">` |
| Live-fire | 50 events × `.10:514/udp`,Wazuh + ELK 雙送 | **無**。0 K8s 環境 + .18 ELK 無 k8s ingest pipeline |
| 驗收方式 | logtest + live-fire 雙 path baseline | **僅 logtest forward-ready 驗收** |

關鍵 finding:catalog template 模擬 **DaemonSet create**(attacker 直接 POST DS),既有 rule 112501-112510 全偵測 **Pod create**(K8s controller 自動 spawn)。Catalog 採 **dual-emit**(每 render 2 line)保留 advisory fidelity + 對齊既有 rule。

## 取樣方式

4 條 fixture deterministic hand-crafted — 用 catalog template 對應 4 個 IOC scenario:

| Sample | Container | Namespace | 預期 phase 3 fire | 原因 |
|---|---|---|---|---|
| `sample-1-kamikaze-default-ns` | kamikaze | default | **112502 lvl 15** | 取代 112501(Wazuh single-rule-per-event) |
| `sample-2-kamikaze-kube-system-ns` | kamikaze | kube-system | **112502 lvl 15** | 同上 |
| `sample-3-provisioner-default-ns` | provisioner | default | **112501 lvl 14** | 112503 commented,112501 為唯一 match |
| `sample-4-provisioner-app-ns` | provisioner | app-prod-1 | **112501 lvl 14** | 同上 |

**Wazuh single-rule-per-event 行為**:既有 k8s 112501/112502 是**非 chain**(無 `<if_sid>`),per event 只 fire 最高 level 那條;這跟 Sibling 1 chain-rule pattern(132019 anchor → 132020/132021 child)讓 sibling 雙 fire 的行為**不同**。已 logtest live 驗證(2026-05-20)。

每個 fixture file 是 **2-line dual-emit**:
- Line 1: DaemonSet create event(attacker-direct,`objectRef.resource: daemonsets`,`user: compromised-sa`,`userAgent: Python-urllib/*`)
- Line 2: Pod create event(controller-spawn,`objectRef.resource: pods`,`user: daemon-set-controller`,`userAgent: kube-controller-manager/...`)

> **All commands assume cwd = this directory.** From repo root:
> `cd tests/fixtures/wazuh-logtest/daemonset-create-teampcp/`

## 跑單一 fixture

```bash
ssh lab@192.0.2.10 'docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' \
  < sample-1-kamikaze-default-ns.log
```

Expected output(2 line pipe = 2 dispatch,只有 line 2 命中既有 rule):

```
**Phase 1: Completed pre-decoding.        # daemonset line — no rule fire
**Phase 2: Completed decoding.
        name: 'json'
        objectRef.resource: 'daemonsets'
        ...
**Phase 3: Completed filtering (rules).   # ← line 1 無 Rule id 顯示

**Phase 1: Completed pre-decoding.        # pod line
**Phase 2: Completed decoding.
        name: 'json'
        objectRef.resource: 'pods'
        ...
**Phase 3: Completed filtering (rules).
        id: '112502'                       # kamikaze case (or '112501' for provisioner)
        level: '15'                        # kamikaze=15 / provisioner=14
        description: 'EXTREME+: K8s pod create with container `kamikaze` — TeamPCP destructive payload ...'
**Alert to be generated.
```

## 跑全部 4 條

```bash
for f in sample-*.log; do
  echo "=== $f ==="
  ssh lab@192.0.2.10 'docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' < $f
  echo
done
```

## 通過條件(對 expected.json `phase3_must_fire`)

| Fixture | Phase 3 must fire | IOC axis |
|---|---|---|
| sample-1-kamikaze-default-ns | 112501(lvl 14)+ 112502(lvl 15)| pod-name + kamikaze container |
| sample-2-kamikaze-kube-system-ns | 112501 + 112502 | pod-name + kamikaze container(kube-system ns)|
| sample-3-provisioner-default-ns | 112501(lvl 14)only | pod-name(112503 provisioner commented)|
| sample-4-provisioner-app-ns | 112501 only | pod-name(custom tenant ns)|

`phase2_observe` 是「decoder flatten 後該抽到的欄位」觀察清單,**非 pass-fail**;phase3 rule fire 才是過關標準。

## Wazuh 端 rule 部署狀態

Rule XML 已落在伴生 SOC repo(<soc-repo>) `config/wazuh_manager/rules/k8s-lateral-anomaly.xml`(2026-05-15):

- **rule 112501 level 14**:`<field name="objectRef.resource">^pods$</field>` + `<field name="objectRef.name">^node-setup-</field>` ← pod name IOC
- **rule 112502 level 15**:同 axis + `<regex type="pcre2">"name":"kamikaze"</regex>` ← kamikaze container IOC
- **rule 112503 level 14**:同 axis + provisioner container regex,**目前 commented**(legit storage provisioner 衝突,需 cluster baseline)
- **rule 112504 level 13**:secrets API + Python-urllib UA(本 catalog 不模擬,scope 是 daemonset/pod create)
- **rule 112510 level 15**:30min ≥ 2 signal correlation(logtest single-event 不觸發)

Forward-ready 狀態:rule 已 active 但無 live event 流入(0 K8s 環境),本 fixture 是 deployment readiness 證明 — 證明 rule logic 對 catalog dual-emit 第 2 line 命中。

## 不適用 Sibling 1-3 pattern 的部分

- **無 chain-rule pattern**:既有 112501-112510 用 `<decoded_as>json</decoded_as>` + `<field>` 直接 match,不用 parent level-0 anchor 設計
- **無 socat-relay UDP path**:0 K8s 環境無 audit log shipping,catalog `transport: [beats, file]` 對齊真實 K8s 生態(fluentd/fluentbit → ES)而非 syslog
- **無 50-event live-fire**:`baseline_alert_count_logtest_*` 取代 `baseline_alert_count`,catalog 加 `live_fire_pending: true` 旗標
- **無 sibling 2 multi-line UDP loss caveat**:logtest pipe 是同步處理,每 line 各自 dispatch,無 50% deterministic loss 風險
