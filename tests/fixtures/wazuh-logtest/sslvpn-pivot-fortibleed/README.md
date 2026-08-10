# wazuh-logtest fixture — FortiBleed SSL VPN pivot（S3 → S4）

Catalog S3: `catalog/fortinet/fortios/7.4/fortios.event.vpn.sslvpn_auth.fortibleed.yaml`
Catalog S4: `catalog/microsoft/windows/2022/security-4720-account-create.yaml`

## 場景說明

FortiBleed 攻擊鏈的 S3→S4 pivot 切片：

| Stage | 事件 | Join key |
|-------|------|----------|
| S3 | FortiGate SSL VPN tunnel-up（user="jchen"，remip=203.0.113.50 境外 IP） | `dstuser=jchen` |
| S4 | Windows 4720 建立帳號（SubjectUserName=jchen 建立 svc_backdoor$） | `winlog.event_data.SubjectUserName=jchen` |

**join user：`jchen`** — S3 VPN 登入帳號（Wazuh decoded → `dstuser`）與 S4 建帳操作者（`SubjectUserName`）一致，
確立「竊來的憑證→認證成功→橫向移動→後門帳號」四段鏈。

## TargetUserName 含 `$` 的用意

`svc_backdoor$` 使用 `$` 後綴是 Windows AD 機器帳號命名慣例。
4720（User 帳號建立）出現 `$` 結尾 TargetUserName 是已知 IOC：

- 攻擊者用 `NET USER svc_backdoor$ /ADD` 透過 USER 路徑建機器帳號
  （應走 4741 Computer Account Created，繞過後留下 4720 痕跡）
- Rubeus / mimikatz Kerberoasting 前置操作（Computer-Account-as-User 特權暫存）
- ArcSight 既有規則 130000「AD_新增包含錢字號帳號」即針對此 IOC

既有 Wazuh 規則 **131021**（level 12）已覆蓋此 IOC，S4 fixture 設計成命中它作為 TDD 紅基線。

## Fixture 製作方式

兩筆 fixture 均為 **deterministic hand-crafted**，時間戳、tunnelid、SID 全部固定：

- S3 時間錨：`2026-06-19 02:00:00`，tunnelid=2026061900，remip=203.0.113.50（境外 C2 段）
- S4 時間錨：`2026-06-19T02:03:00`（S3 後 3 分鐘，在 900 秒關聯窗內）

S3 格式為 FortiOS key_value syslog（含 RFC3164 PRI + timestamp header），與 FortiGate decoder sample 對齊。
S4 格式為純 JSON line（syslog header 已剝除），`json` decoder 直接命中 `^\{` prematch。

### 為何 S4 不含 syslog header

Wazuh `wazuh-logtest` 不走 `logcollector` 的 RFC3164 剝除路徑。
Windows 4720 事件在 live-fire 下由 winlogbeat/Wazuh agent 以純 JSON 形式送出（`transport: [beats, file]`）；
logtest 直接送 JSON line 才能讓 `json` decoder 命中 `^\{` prematch，抽出 `winlog.event_data.*` 欄位。

## S2 盲點（離線爆破）

本切片只涵蓋 S3（SSL VPN tunnel-up）與 S4（AD 後門帳號建立）。
S2 Infostealer 離線爆破階段**不產生 Wazuh 可見事件**：

- 攻擊者在本地對竊得的 LSASS dump / credential store 執行 hashcat / John the Ripper
- 完全在攻擊者端，零 SOC telemetry
- S3 之前的 "why did jchen succeed from 203.0.113.50" 問題須靠 IP geo anomaly + off-hours
  detection（Task 3/4 負責），而非 S2 本身的 Wazuh rule

## 跑單一 fixture

```bash
# All commands assume cwd = repo root (CyberRange/)

ssh lab@192.0.2.10 'export PATH=/usr/local/bin:$PATH && docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' \
  < tests/fixtures/wazuh-logtest/sslvpn-pivot-fortibleed/s3-sslvpn-auth-success.log

ssh lab@192.0.2.10 'export PATH=/usr/local/bin:$PATH && docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' \
  < tests/fixtures/wazuh-logtest/sslvpn-pivot-fortibleed/s4-4720-account-create.log
```

## 跑全部（比對 expected.json）

```bash
for f in s3-sslvpn-auth-success.log s4-4720-account-create.log; do
  echo "=== $f ==="
  ssh lab@192.0.2.10 'export PATH=/usr/local/bin:$PATH && docker exec -i <wazuh-manager-container> /var/ossec/bin/wazuh-logtest' \
    < tests/fixtures/wazuh-logtest/sslvpn-pivot-fortibleed/$f
  echo
done
```

## 紅基線結果（TDD 起點，2026-06-19 驗證）

| Fixture | Phase 3 實際命中 | 預期（Task 3 完成後） | 狀態 |
|---------|-----------------|----------------------|------|
| s3-sslvpn-auth-success.log | **81622** level 3「Fortigate: VPN user connected.」 | **132080** level 8 | 🔴 RED（132080 未建） |
| s4-4720-account-create.log | **131021** level 12「New Windows account with '$'...」 | **131021** level 12 ✅ | 🟡 S4 既有規則已覆蓋 |
| 關聯 132085 | **不存在** | **132085** level 12 | 🔴 RED（規則未建） |

S3 Phase 2 解碼確認：`dstuser: 'jchen'`，`remip: '203.0.113.50'`，`logid: '0101039947'`，
decoder: `fortigate-firewall-v5`（v6 child decoder 抽 `user=` → `dstuser`）。

S4 Phase 2 解碼確認：`winlog.event_data.SubjectUserName: 'jchen'`，
`winlog.event_data.TargetUserName: 'svc_backdoor$'`，`winlog.event_id: '4720'`。

## 通過條件（Task 3 部署 rule 132080/132085 後）

| Fixture | Phase 3 must fire | Notes |
|---------|-------------------|-------|
| s3-sslvpn-auth-success.log | **132080**（level ≥ 8）| FortiBleed SSL VPN anomaly rule |
| s4-4720-account-create.log | **131021**（level 12）| 既有 `$` account rule |
| 關聯（CDB lookup）          | **132085**（level 12）| jchen in CDB → 4720 chain fire |

## Wazuh 端 rule 部署（預定）

Rule XML 將落在 伴生 SOC repo(<soc-repo>)的 `config/wazuh_manager/rules/local_fortibleed.xml`：
- rule 132080 level 8：`if_sid 81622` + `dstuser` 存入 CDB（FortiBleed VPN anomaly anchor）
- rule 132085 level 12：`if_sid 131020/131021` + CDB lookup `winlog.event_data.SubjectUserName`
  → jchen 在 VPN CDB 中 → "FortiBleed pivot detected" chain alert

部署 SOP 見 Task 3 runbook（待建）。
