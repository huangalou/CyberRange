# elk-pipeline-patch

ES ingest pipeline patches for `.18` ELK stack. Counterpart to `deploy/elk-logstash-patch/` (which is for the deferred Logstash Beats input).

## auto-route-v2.json — Live-fire Wave 1 reroute extension

### What it changes (vs v1 already deployed on `.18`)

v1 only routed 5 sources (FortiGate, the companion SOC stack's own CEF app, fail2ban, nginx-CEF, ModSec audit) — anything else stayed in `incoming-*` and was invisible to the 6 detection rule index patterns (`fortigate-*`, `nginx-cef-*`, `soc-app-*`, `fail2ban-*`, `cef-other-*`, `syslog-other-*`).

v2 adds **3 new content-based router rules + 2 catch-all buckets** so CyberRange catalog events land in indices the detection rules actually query:

| Router rule | Trigger pattern | Destination index | Why |
|---|---|---|---|
| Sophos Central Endpoint | `CEF:0\|sophos\|sophos central\|` literal | `cef-other-*` | Sophos AV CEF events; matches `local_sophos_endpoint.xml` rule 131100 chain |
| Fortinet FortiWeb | `device_id=FV-` AND `type=attack` | `cef-other-*` | FortiWeb attack-log (key=value, not CEF — but bucketed here because no dedicated `fortinet-fortiweb-*` index exists yet) |
| Other CEF (catch-all) | regex `/CEF:0\|/` | `cef-other-*` | Any other CEF wire that didn't match a specific vendor router |
| Windows Security JSON | message contains `Microsoft-Windows-Security-Auditing` | `syslog-other-*` | catalog `microsoft/windows/2022/security-event_id_*` events |
| Non-CEF catch-all | any other message | `syslog-other-*` | everything else (Apache combined, OpenSSH RFC3164, Sysmon JSON, etc.) |

Order matters: specific vendor routers (Sophos / FortiWeb / generic CEF) are checked first; catch-alls only fire when `ctx._router == null`.

### Source-of-truth diff

```diff
 v1 → v2
 + Sophos Central router (CEF:0|sophos|sophos central|)
 + FortiWeb router (device_id=FV- + type=attack)
 + Generic CEF catch-all (regex CEF:0|)
 + Windows Security JSON router (Microsoft-Windows-Security-Auditing)
 + Default syslog-other catch-all
 + cef-other-* date_index_name reroute
 + syslog-other-* date_index_name reroute
 ~ description string updated
```

`fortigate-*` / `soc-app-*` / `fail2ban-*` / `nginx-cef-*` / `modsec-audit` routers and their entry pipelines are unchanged.

## Apply SOP

Run from any host that can reach `192.0.2.18:9200` (e.g. an admin workstation or `.18` itself).

```bash
# 1. Snapshot current pipeline body for rollback
ES_PASS=$(ssh lab@192.0.2.18 'grep ^ELASTIC_PASSWORD <elk-stack-dir>/.env | cut -d= -f2')
curl -sS -u "elastic:$ES_PASS" \
  http://192.0.2.18:9200/_ingest/pipeline/auto-route \
  > deploy/elk-pipeline-patch/auto-route-v1.snapshot.$(date +%Y%m%d).json

# 2. Validate v2 JSON syntax locally
python3 -c 'import json; json.load(open("deploy/elk-pipeline-patch/auto-route-v2.json"))'

# 3. PUT v2 pipeline (idempotent — replaces body)
curl -sS -u "elastic:$ES_PASS" -X PUT \
  -H 'Content-Type: application/json' \
  http://192.0.2.18:9200/_ingest/pipeline/auto-route \
  -d @deploy/elk-pipeline-patch/auto-route-v2.json

# 4. Smoke test — simulate one Sophos CEF and one FortiWeb event through pipeline
curl -sS -u "elastic:$ES_PASS" \
  -H 'Content-Type: application/json' \
  http://192.0.2.18:9200/_ingest/pipeline/auto-route/_simulate \
  -d '{
    "docs":[
      {"_source":{"message":"CEF:0|sophos|sophos central|1.0|Event::Endpoint::Threat::HIPSDismissed|Mal/Generic-S|8|rt=2026-05-16T11:30:37Z","@timestamp":"2026-05-16T11:30:37Z"}},
      {"_source":{"message":"date=2026-05-16 time=11:30:42 log_id=20000011 device_id=FV-1KD3A15800072 vd=\"root\" type=attack pri=warning","@timestamp":"2026-05-16T11:30:42Z"}}
    ]
  }' | python3 -m json.tool

# Expected: doc 0 → "_index": "cef-other-2026.05.16"
#           doc 1 → "_index": "cef-other-2026.05.16"
```

## Rollback

```bash
curl -sS -u "elastic:$ES_PASS" -X PUT \
  -H 'Content-Type: application/json' \
  http://192.0.2.18:9200/_ingest/pipeline/auto-route \
  -d @deploy/elk-pipeline-patch/auto-route-v1.snapshot.<date>.json
```

## Validation after apply

Re-run CyberRange live-fire Tier 1 (5 catalog × 10 events × 2 sinks) and reverse-query the 6 detection rule indices. Expected after v2:

| Catalog | v1 actual | v2 expected |
|---|---|---|
| security-4624 | `incoming-*` 10 / detection idx 0 | `syslog-other-*` 10 (routed by `Microsoft-Windows-Security-Auditing`) |
| security-4672 | `incoming-*` 10 / detection idx 0 | `syslog-other-*` 10 |
| security-4720 | `incoming-*` 10 / detection idx 0 | `syslog-other-*` 10 |
| sophos av | `incoming-*` 10 / detection idx 0 | `cef-other-*` 10 |
| fortiweb attack | `incoming-*` 10 / detection idx 0 | `cef-other-*` 10 |

Detection rule trigger depends on whether the ArcSight-derived rules' KQL patterns actually match the routed docs — that's a separate validation pass (Kibana SIEM detection engine → rule run history).

## Open items / known limits

- `cef-other-*` and `syslog-other-*` indices do NOT have an index template yet — they'll auto-create with default mapping (no ECS field types), which may make some detection rules miss numeric range queries. Consider adding a follow-up index template `soc-cef-other` + `soc-syslog-other` with explicit ECS mapping mirroring `soc-ecs`.
- FortiWeb routing to `cef-other-*` is approximate — FortiWeb attack-log is key=value, not CEF. A more accurate placement would be a new `fortiweb-*` index with its own entry pipeline (TODO).
- No `fortiweb-entry` ECS pipeline exists yet; FortiWeb docs in `cef-other-*` will not have ECS `source.ip` etc populated. Add follow-up pipeline `fortiweb-entry` patterned on `fortigate-entry`.
