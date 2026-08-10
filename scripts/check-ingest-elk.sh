#!/usr/bin/env bash
# check-ingest-elk.sh — Phase-B reverse-query against ELK (.18).
#
# Run from the ELK host (or anywhere reachable to ES on port 9200).
# Confirms recent CyberRange probes / dispatched logs landed in incoming-* index.
#
# Filters:
#   - default: anything mentioning "cyberrange" in the past 15 minutes
#   - VENDOR_FILTER (env) overrides the search term (e.g. "FortiGate" / "PAN-OS")
#
# Output: top hit count + last 3 _source previews. Greppable.

set -euo pipefail

ES_BASE="${ES_BASE:-http://192.0.2.18:9200}"
ES_USER="${ES_USER:-}"
ES_PASS="${ES_PASS:-}"
INDEX="${INDEX:-incoming-*}"
SEARCH_TERM="${SEARCH_TERM:-cyberrange}"
WINDOW="${WINDOW:-15m}"
SIZE="${SIZE:-3}"

auth_args=()
if [[ -n "$ES_USER" && -n "$ES_PASS" ]]; then
  auth_args=(-u "$ES_USER:$ES_PASS")
fi

query=$(cat <<JSON
{
  "size": $SIZE,
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "must": [
        {"query_string": {"query": "$SEARCH_TERM"}},
        {"range": {"@timestamp": {"gte": "now-$WINDOW"}}}
      ]
    }
  }
}
JSON
)

resp=$(curl -sS "${auth_args[@]}" \
  -H 'Content-Type: application/json' \
  "$ES_BASE/$INDEX/_search" \
  -d "$query")

total=$(printf '%s' "$resp" | sed -n 's/.*"total"[[:space:]]*:[[:space:]]*{[[:space:]]*"value"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p')

if [[ -z "$total" ]]; then
  echo "[FAIL] could not parse ES response. raw:"
  printf '%s\n' "$resp" | head -c 1000
  exit 1
fi

echo "[OK] index=$INDEX term=\"$SEARCH_TERM\" window=$WINDOW total_hits=$total"

if [[ "$total" -eq 0 ]]; then
  echo "[WARN] zero hits — Filebeat may not be running or term mismatch. Try VENDOR_FILTER=<vendor>."
  exit 2
fi

echo "--- last $SIZE preview ---"
printf '%s' "$resp" | python3 -c '
import json, sys
d = json.loads(sys.stdin.read())
for h in d.get("hits", {}).get("hits", []):
    src = h.get("_source", {})
    msg = src.get("message") or src.get("event", {}).get("original") or json.dumps(src)[:300]
    print(f"@ts={src.get(\"@timestamp\",\"?\")}\n  {msg[:300]}\n")
'
