#!/usr/bin/env bash
# verify-sinks.sh — Phase-A connectivity + dispatch probe for dual-send verification.
#
# Run from the CyberRange deploy host (lab@192.0.2.10).
# It performs three checks against each SOC ingress:
#
#   1. TCP reachability   (nc -zv  <host> 1514)
#   2. UDP reachability   (nc -uzv <host> 514)   -- best-effort, UDP can't truly confirm
#   3. Probe syslog send  (single RFC3164-ish line via nc, both UDP/514 and TCP/1514)
#
# Then it triggers a one-shot CyberRange API dispatch to each sink
# (count=1, FortiGate traffic catalog) and reports the job_id back.
#
# Output layout: greppable "[step] result detail" so you can pipe to tee / parse.

set -euo pipefail

# ──────────────── config (override via env) ────────────────
WAZUH_HOST="${WAZUH_HOST:-192.0.2.10}"
ELK_HOST="${ELK_HOST:-192.0.2.18}"

UDP_PORT="${UDP_PORT:-514}"
TCP_PORT="${TCP_PORT:-1514}"

# CyberRange API. Default goes through the local container on the deploy host
# so we don't bounce through the reverse proxy. Override to https://bas.example.com
# if you want to validate the public path too.
API_BASE="${API_BASE:-http://127.0.0.1:8001}"
BASIC_USER="${BASIC_USER:-}"
BASIC_PASS="${BASIC_PASS:-}"

# Probe catalog (must exist in catalog/). Picked because it lands as plain
# kv-pair syslog that both Wazuh and ELK can ingest without extra decoders.
VENDOR="${VENDOR:-fortinet}"
PRODUCT="${PRODUCT:-fortios}"
VERSION="${VERSION:-7.4}"
LOG_TYPE="${LOG_TYPE:-traffic}"

# ──────────────── helpers ────────────────
log()  { printf '[%s] %s\n' "$1" "$2"; }
ok()   { log "OK"   "$*"; }
warn() { log "WARN" "$*"; }
fail() { log "FAIL" "$*"; exit_code=1; }

exit_code=0

# RFC3164-style probe message. Sufficient to confirm transport; SOC may or may not
# decode it cleanly — that's a separate (Phase-B) check via the ingest reverse-query.
probe_line() {
  local target=$1
  local ts
  ts="$(date '+%b %d %H:%M:%S')"
  echo "<134>$ts cyberrange-probe verify-sinks: target=$target ts=$(date -u +%FT%TZ)"
}

# ──────────────── Phase A.1 — TCP/UDP reachability ────────────────
check_tcp() {
  local host=$1 port=$2 name=$3
  if nc -zv -w 3 "$host" "$port" >/dev/null 2>&1; then
    ok "$name TCP $host:$port reachable"
  else
    fail "$name TCP $host:$port unreachable"
  fi
}

check_udp() {
  local host=$1 port=$2 name=$3
  # -u -z is best-effort; success doesn't truly mean a listener is there.
  if nc -uzv -w 3 "$host" "$port" >/dev/null 2>&1; then
    ok "$name UDP $host:$port best-effort reachable (UDP can't confirm)"
  else
    warn "$name UDP $host:$port nc returned non-zero (may still be open)"
  fi
}

log "STEP" "A.1 reachability"
check_tcp "$WAZUH_HOST" "$TCP_PORT" "Wazuh"
check_udp "$WAZUH_HOST" "$UDP_PORT" "Wazuh"
check_tcp "$ELK_HOST"   "$TCP_PORT" "ELK"
check_udp "$ELK_HOST"   "$UDP_PORT" "ELK"

# ──────────────── Phase A.2 — probe syslog ────────────────
send_probe() {
  local host=$1 port=$2 proto=$3 name=$4
  local line
  line="$(probe_line "$name-$proto")"
  case "$proto" in
    udp) printf '%s\n' "$line" | nc -u -w 1 "$host" "$port" || true ;;
    tcp) printf '%s\n' "$line" | nc    -w 2 "$host" "$port" || true ;;
  esac
  ok "probe sent $name $proto://$host:$port"
}

log "STEP" "A.2 probe syslog"
send_probe "$WAZUH_HOST" "$UDP_PORT" udp Wazuh
send_probe "$WAZUH_HOST" "$TCP_PORT" tcp Wazuh
send_probe "$ELK_HOST"   "$UDP_PORT" udp ELK
send_probe "$ELK_HOST"   "$TCP_PORT" tcp ELK

# ──────────────── Phase A.3 — API dispatch one-shot ────────────────
auth_args=()
if [[ -n "$BASIC_USER" && -n "$BASIC_PASS" ]]; then
  auth_args=(-u "$BASIC_USER:$BASIC_PASS")
fi

dispatch() {
  local host=$1 name=$2
  local payload
  payload=$(cat <<JSON
{"vendor":"$VENDOR","product":"$PRODUCT","version":"$VERSION","log_type":"$LOG_TYPE","count":1,"rate":0,"sink":"udp://$host:$UDP_PORT","params":{}}
JSON
)
  local resp
  resp=$(curl -sS -X POST "$API_BASE/generate" \
    -H 'Content-Type: application/json' \
    "${auth_args[@]}" \
    -d "$payload" || true)
  if [[ -z "$resp" ]]; then
    fail "$name dispatch returned empty (auth? api down?)"
    return
  fi
  local job_id
  job_id=$(printf '%s' "$resp" | sed -n 's/.*"job_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [[ -n "$job_id" ]]; then
    ok "$name dispatch job_id=$job_id sink=udp://$host:$UDP_PORT"
  else
    fail "$name dispatch unexpected response: $resp"
  fi
}

log "STEP" "A.3 API dispatch"
dispatch "$WAZUH_HOST" Wazuh
dispatch "$ELK_HOST"   ELK

# ──────────────── summary ────────────────
echo
if [[ $exit_code -eq 0 ]]; then
  log "DONE" "all checks passed — proceed to Phase B (reverse query) on .10 and .18"
else
  log "DONE" "some checks failed — fix transport/auth before reverse query"
fi
exit $exit_code
