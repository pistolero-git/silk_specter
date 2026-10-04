#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCENARIO="${1:-easy}"
SOURCE_INDEX="${2:-}"
NOTABLE_INDEX="${3:-${NOTABLE_INDEX:-notable}}"
CONTAINER="${SPLUNK_CONTAINER:-splunk}"

CFG="$ROOT/config/scenarios/$SCENARIO.json"
DATA="$ROOT/dataset/$SCENARIO/notables"

RESTART_TIMEOUT="${SPLUNK_RESTART_TIMEOUT:-60}"
READY_TIMEOUT="${SPLUNK_READY_TIMEOUT:-300}"
PROBE_TIMEOUT="${SPLUNK_READY_PROBE_TIMEOUT:-5}"
INGEST_TIMEOUT="${SPLUNK_INGEST_TIMEOUT:-300}"

if [[ ! -f "$CFG" ]]; then
  echo "ERROR: unknown scenario: $SCENARIO" >&2
  exit 2
fi

if [[ -z "$SOURCE_INDEX" ]]; then
  SOURCE_INDEX="$(python3 - "$CFG" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding="utf-8"))["index"])
PY
)"
fi

if [[ ! -f "$DATA/hec/events.jsonl" || ! -f "$DATA/manifest.json" ]]; then
  echo "ERROR: notable dataset missing under $DATA. Generate the track first." >&2
  exit 3
fi

EXPECTED="$(python3 - "$DATA/manifest.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1],encoding="utf-8"))["events"])
PY
)"

SAFE_SOURCE="$(printf '%s' "$SOURCE_INDEX" | tr -c 'A-Za-z0-9_.-' '_')"
SAFE_NOTABLE="$(printf '%s' "$NOTABLE_INDEX" | tr -c 'A-Za-z0-9_.-' '_')"
APP_NAME="SA-silk-specter-notables-${SCENARIO}-${SAFE_SOURCE}-${SAFE_NOTABLE}"
APP_DST="/opt/splunk/etc/apps/$APP_NAME"

REMOTE="/opt/splunk/var/spool/silk-specter-notables-${SCENARIO}-${SAFE_SOURCE}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}"
HEC_GLOB="$REMOTE/*.jsonl"
HEC_REMOTE="$REMOTE/events-${RUN_ID}.jsonl"
HEC_UPLOAD="$HEC_REMOTE.upload"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/app/local"

PREPARED="$TMP/events.jsonl"
python3 - "$DATA/hec/events.jsonl" "$PREPARED" "$SOURCE_INDEX" <<'PY'
import json,sys
src,dst,index=sys.argv[1:4]
count=0
with open(src,encoding="utf-8") as fin, open(dst,"w",encoding="utf-8",newline="\n") as fout:
    for line in fin:
        if not line.strip():
            continue
        row=json.loads(line)
        row["event"]=str(row.get("event","")).replace("<index>",index)
        fout.write(json.dumps(row,separators=(",",":"))+"\n")
        count += 1
print(f"Prepared {count} notable events for source index {index}.")
PY

LINES="$(wc -l < "$PREPARED" | tr -d ' ')"
if [[ "$LINES" != "$EXPECTED" ]]; then
  echo "ERROR: prepared notable stream has $LINES lines but manifest expects $EXPECTED." >&2
  exit 4
fi

bounded() {
  timeout --signal=TERM --kill-after=1s "${PROBE_TIMEOUT}s" "$@"
}

index_is_configured() {
  local index="$1"
  local cfg
  cfg="$(
    bounded podman exec --user splunk "$CONTAINER" \
      /opt/splunk/bin/splunk btool indexes list "$index" --debug 2>/dev/null || true
  )"
  grep -Eq '(^|[[:space:]])homePath[[:space:]]*=' <<<"$cfg"
}

wait_for_container() {
  local started=$SECONDS
  local deadline=$((started + READY_TIMEOUT))
  local next_report=10
  local running=""
  local health=""

  while (( SECONDS < deadline )); do
    running="$(
      bounded podman inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true
    )"
    health="$(
      bounded podman inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
        "$CONTAINER" 2>/dev/null || true
    )"

    if [[ "$running" == "true" && "$health" == "healthy" ]]; then
      return 0
    fi

    if [[ "$running" == "true" && "$health" == "none" ]]; then
      if bounded podman exec --user splunk "$CONTAINER" \
          /opt/splunk/bin/splunk btool props list asteron:hec >/dev/null 2>&1; then
        return 0
      fi
    fi

    if (( SECONDS - started >= next_report )); then
      echo "      Still waiting for container readiness ($((SECONDS - started))s elapsed; health=${health:-unknown}) ..."
      next_report=$((next_report + 10))
    fi
    sleep 2
  done

  return 1
}

wait_for_batch_consumption() {
  local started=$SECONDS
  local deadline=$((started + INGEST_TIMEOUT))
  local next_report=15

  while (( SECONDS < deadline )); do
    if bounded podman exec --user splunk "$CONTAINER" test ! -e "$HEC_REMOTE"; then
      return 0
    fi

    if (( SECONDS - started >= next_report )); then
      echo "      Still waiting for Splunk to consume notable batch file ($((SECONDS - started))s elapsed) ..."
      next_report=$((next_report + 15))
    fi
    sleep 2
  done

  return 1
}

echo "[1/7] Checking source index and notable index"

if ! index_is_configured "$SOURCE_INDEX"; then
  echo "ERROR: source index '$SOURCE_INDEX' is not present in Splunk configuration." >&2
  echo "Load the main $SCENARIO dataset first." >&2
  exit 5
fi

CREATE_INDEX=0
if index_is_configured "$NOTABLE_INDEX"; then
  echo "      Notable index '$NOTABLE_INDEX' exists; using it."
else
  if [[ "${CREATE_NOTABLE_INDEX:-0}" == "1" ]]; then
    CREATE_INDEX=1
    echo "      Notable index '$NOTABLE_INDEX' does not exist; it will be created through indexes.conf."
  else
    echo "ERROR: notable index '$NOTABLE_INDEX' is not present in Splunk configuration." >&2
    echo "If this is intentional, rerun with CREATE_NOTABLE_INDEX=1." >&2
    exit 6
  fi
fi

cat >"$TMP/app/local/inputs.conf" <<EOF
[batch://$HEC_GLOB]
disabled = 0
index = $NOTABLE_INDEX
sourcetype = asteron:hec
host = SILK-SPECTER-ES
move_policy = sinkhole
crcSalt = <SOURCE>
EOF

if (( CREATE_INDEX == 1 )); then
  cat >"$TMP/app/local/indexes.conf" <<EOF
[$NOTABLE_INDEX]
homePath = \$SPLUNK_DB/$SAFE_NOTABLE/db
coldPath = \$SPLUNK_DB/$SAFE_NOTABLE/colddb
thawedPath = \$SPLUNK_DB/$SAFE_NOTABLE/thaweddb
EOF
fi

echo "[2/7] Installing container-local notable loader app"
podman exec --user 0 "$CONTAINER" rm -rf "$APP_DST"
podman exec --user 0 "$CONTAINER" mkdir -p "$APP_DST" "$REMOTE"
podman cp "$TMP/app/." "$CONTAINER:$APP_DST"
podman exec --user 0 "$CONTAINER" chown -R splunk:splunk "$APP_DST" "$REMOTE"

echo "[3/7] Restarting Splunk container (stop timeout=${RESTART_TIMEOUT}s)"
restart_rc=0
podman restart --time "$RESTART_TIMEOUT" "$CONTAINER" >/dev/null || restart_rc=$?
if (( restart_rc != 0 )); then
  echo "WARNING: podman restart returned rc=$restart_rc; waiting for recovery." >&2
fi

echo "[4/7] Waiting up to ${READY_TIMEOUT}s for container health"
if ! wait_for_container; then
  echo "ERROR: Splunk container did not become ready within ${READY_TIMEOUT}s." >&2
  podman inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' \
    "$CONTAINER" 2>/dev/null >&2 || true
  podman logs --tail 100 "$CONTAINER" 2>/dev/null >&2 || true
  exit 7
fi
echo "      Container is ready."

echo "[5/7] Verifying parser, target index, and batch input"
if ! bounded podman exec --user splunk "$CONTAINER" \
    /opt/splunk/bin/splunk btool props list asteron:hec --debug 2>/dev/null \
    | grep -Eq 'INDEXED_EXTRACTIONS[[:space:]]*=[[:space:]]*HEC'; then
  echo "ERROR: [asteron:hec] INDEXED_EXTRACTIONS=HEC is not active." >&2
  echo "Install/update TA-asteron-v3 and restart Splunk." >&2
  exit 8
fi

if ! index_is_configured "$NOTABLE_INDEX"; then
  echo "ERROR: notable index '$NOTABLE_INDEX' is still not active after restart." >&2
  exit 8
fi

INPUT_CFG="$(
  bounded podman exec --user splunk "$CONTAINER" \
    /opt/splunk/bin/splunk btool inputs list --debug 2>/dev/null || true
)"
if ! grep -Fq "[batch://$HEC_GLOB]" <<<"$INPUT_CFG"; then
  echo "ERROR: notable batch input is not active after restart." >&2
  exit 8
fi

echo "[6/7] Copying $EXPECTED notables into a unique live batch source: $(basename "$HEC_REMOTE")"
echo "      Unique source path + crcSalt=<SOURCE> prevents fishbucket from suppressing a corrected reload."
podman exec --user 0 "$CONTAINER" mkdir -p "$REMOTE"
podman exec --user 0 "$CONTAINER" rm -f "$HEC_UPLOAD" "$HEC_REMOTE"
podman cp "$PREPARED" "$CONTAINER:$HEC_UPLOAD"
podman exec --user 0 "$CONTAINER" chown splunk:splunk "$HEC_UPLOAD"
podman exec --user 0 "$CONTAINER" mv "$HEC_UPLOAD" "$HEC_REMOTE"

echo "[7/7] Waiting for Splunk to consume the notable batch source"
if ! wait_for_batch_consumption; then
  echo "ERROR: Splunk did not consume $HEC_REMOTE within ${INGEST_TIMEOUT}s." >&2
  echo "Effective input stanza:" >&2
  podman exec --user splunk "$CONTAINER" \
    /opt/splunk/bin/splunk btool inputs list --debug 2>/dev/null \
    | grep -A10 -B2 -F "$HEC_REMOTE" >&2 || true
  echo "Relevant splunkd.log entries:" >&2
  podman exec --user splunk "$CONTAINER" \
    grep -F "$HEC_REMOTE" /opt/splunk/var/log/splunk/splunkd.log 2>/dev/null >&2 || true
  exit 9
fi

echo
echo "Submitted $EXPECTED synthetic notables for track=$SCENARIO to index=$NOTABLE_INDEX."
echo "Container-native load completed without interactive CLI authentication or host-published Splunk ports."
echo
echo "Validate in Splunk Web with:"
echo "  index=$NOTABLE_INDEX host=SILK-SPECTER-ES sourcetype=stash scenario=$SCENARIO"
echo "  | stats count by rule_name urgency"
