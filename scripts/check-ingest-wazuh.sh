#!/usr/bin/env bash
# check-ingest-wazuh.sh — Phase-B reverse-query against Wazuh (.10).
#
# Run on the Wazuh host (192.0.2.10) or via SSH. Three independent checks:
#
#   1. archives.log     — raw ingest (does anything reach the manager at all?)
#   2. alerts.log       — decoded + matched a rule (was it understood?)
#   3. Indexer search   — searchable in OpenSearch (alerts indexed?)
#
# Set env to point at the right files. Defaults match the canonical
# wazuh-manager container layout (/var/ossec inside, mounted to host).

set -euo pipefail

ARCHIVES="${ARCHIVES:-/var/ossec/logs/archives/archives.log}"
ALERTS="${ALERTS:-/var/ossec/logs/alerts/alerts.log}"
INDEXER_BASE="${INDEXER_BASE:-https://192.0.2.10:9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASS="${INDEXER_PASS:-}"

SEARCH_TERM="${SEARCH_TERM:-cyberrange}"
TAIL_LINES="${TAIL_LINES:-50}"
WINDOW="${WINDOW:-15m}"

# ──────────────── 1. archives.log ────────────────
echo "[STEP] 1. archives.log -- raw ingest"
if [[ -r "$ARCHIVES" ]]; then
  hits=$(grep -ci "$SEARCH_TERM" "$ARCHIVES" || true)
  echo "[OK] $ARCHIVES contains $hits line(s) matching \"$SEARCH_TERM\""
  if [[ "$hits" -gt 0 ]]; then
    echo "--- last 3 ---"
    grep -i "$SEARCH_TERM" "$ARCHIVES" | tail -3
  fi
else
  echo "[WARN] cannot read $ARCHIVES (permission? path?). Try: sudo $0"
fi

echo

# ──────────────── 2. alerts.log ────────────────
echo "[STEP] 2. alerts.log -- decoded + rule matched"
if [[ -r "$ALERTS" ]]; then
  alert_hits=$(grep -ci "$SEARCH_TERM" "$ALERTS" || true)
  echo "[OK] $ALERTS contains $alert_hits alert line(s) matching \"$SEARCH_TERM\""
  if [[ "$alert_hits" -eq 0 ]]; then
    echo "[INFO] zero alerts. May mean: (a) no decoder hit (b) decoded but no rule (c) matched but level<3 dropped"
  else
    echo "--- last 3 ---"
    grep -i "$SEARCH_TERM" "$ALERTS" | tail -3
  fi
else
  echo "[WARN] cannot read $ALERTS"
fi

echo

# ──────────────── 3. Indexer search ────────────────
echo "[STEP] 3. wazuh-indexer search -- alerts indexed"
if [[ -z "$INDEXER_PASS" ]]; then
  echo "[SKIP] INDEXER_PASS not set; export it (or set INDEXER_PASS=$(< file)) to enable"
else
  query=$(cat <<JSON
{"size":3,"sort":[{"@timestamp":{"order":"desc"}}],"query":{"bool":{"must":[{"query_string":{"query":"$SEARCH_TERM"}},{"range":{"@timestamp":{"gte":"now-$WINDOW"}}}]}}}
JSON
)
  resp=$(curl -sk -u "$INDEXER_USER:$INDEXER_PASS" \
    -H 'Content-Type: application/json' \
    "$INDEXER_BASE/wazuh-alerts-*/_search" \
    -d "$query" || true)
  total=$(printf '%s' "$resp" | sed -n 's/.*"total"[[:space:]]*:[[:space:]]*{[[:space:]]*"value"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p')
  if [[ -z "$total" ]]; then
    echo "[FAIL] indexer search failed. raw:"
    printf '%s\n' "$resp" | head -c 500
  else
    echo "[OK] wazuh-alerts-* total_hits=$total (window=$WINDOW)"
  fi
fi
