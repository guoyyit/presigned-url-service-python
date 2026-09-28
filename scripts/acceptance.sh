#!/usr/bin/env bash
# Reproducible local acceptance: real HTTP server, temp state dir.
# Exercises: issue -> access -> replay denied -> revoke -> rotate -> restart persistence.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=8787
BASE="http://127.0.0.1:${PORT}"
WORK="$(mktemp -d)"
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT

export PRESIGN_DB_PATH="$WORK/state.db"
export PRESIGN_AUDIT_LOG_PATH="$WORK/audit.log"
export PRESIGN_CLOCK_SKEW_SECONDS=30
export PRESIGN_ROTATION_GRACE_SECONDS=300

json_get() { uv run python -c "import sys,json;print(json.load(sys.stdin)$1)"; }
check() { # check <description> <expected> <actual>
  if [ "$2" != "$3" ]; then echo "FAIL: $1 (expected=$2 actual=$3)"; exit 1; fi
  echo "ok: $1"
}

start_server() {
  uv run uvicorn main:app --port "$PORT" --log-level warning &
  SERVER_PID=$!
  for _ in $(seq 1 50); do
    curl -sf "$BASE/presign/health" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "server did not start"; exit 1
}

echo "== 1. start server (temp state: $WORK) =="
start_server

echo "== 2. issue a single-use presigned URL =="
EXP=$(( $(date +%s) + 600 ))
RESP=$(curl -sf -X POST "$BASE/presign/issue" -H 'Content-Type: application/json' \
  -H 'X-Caller-Id: alice' \
  -d "{\"resource\":\"docs/report.pdf\",\"operation\":\"read\",\"expires_at\":$EXP,\"max_uses\":1}")
URL=$(echo "$RESP" | json_get "['url']")
echo "   $URL"

echo "== 3. access succeeds, replay is denied =="
check "first access allowed" "True"  "$(curl -sf "$BASE$URL" | json_get "['allowed']")"
check "replay denied"        "False" "$(curl -sf "$BASE$URL" | json_get "['allowed']")"
check "replay reason"  "usage_exhausted" "$(curl -sf "$BASE$URL" | json_get "['reason']")"

echo "== 4. out-of-scope issuance is rejected =="
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/presign/issue" \
  -H 'Content-Type: application/json' -H 'X-Caller-Id: alice' \
  -d "{\"resource\":\"etc/shadow\",\"operation\":\"read\",\"expires_at\":$EXP}")
check "forbidden" "403" "$CODE"

echo "== 5. revoke blocks access even while valid =="
RESP=$(curl -sf -X POST "$BASE/presign/issue" -H 'Content-Type: application/json' \
  -H 'X-Caller-Id: alice' \
  -d "{\"resource\":\"docs/revoked.txt\",\"operation\":\"read\",\"expires_at\":$EXP}")
URL2=$(echo "$RESP" | json_get "['url']")
TID2=$(echo "$URL2" | sed -n 's/.*tid=\([a-f0-9]*\).*/\1/p')
curl -sf -X POST "$BASE/presign/revoke" -H 'Content-Type: application/json' \
  -H 'X-Caller-Id: alice' -d "{\"token_ids\":[\"$TID2\"]}" >/dev/null
check "revoked access denied" "revoked" "$(curl -sf "$BASE$URL2" | json_get "['reason']")"

echo "== 6. key rotation: new tokens use new key, old still verify in grace =="
curl -sf -X POST "$BASE/presign/rotate" -H 'Content-Type: application/json' \
  -H 'X-Caller-Id: alice' -d '{"new_key_id":"k2","new_secret":"rotated-secret"}' >/dev/null
RESP=$(curl -sf -X POST "$BASE/presign/issue" -H 'Content-Type: application/json' \
  -H 'X-Caller-Id: alice' \
  -d "{\"resource\":\"docs/after-rotation.txt\",\"operation\":\"read\",\"expires_at\":$EXP}")
URL3=$(echo "$RESP" | json_get "['url']")
check "new token uses k2" "kid=k2" "$(echo "$URL3" | grep -o 'kid=k2')"
check "new token accesses" "True" "$(curl -sf "$BASE$URL3" | json_get "['allowed']")"

echo "== 7. restart: used counts must not roll back =="
kill $SERVER_PID; wait $SERVER_PID 2>/dev/null || true
start_server
check "replay still denied after restart" "usage_exhausted" \
  "$(curl -sf "$BASE$URL" | json_get "['reason']")"
check "revoked still revoked after restart" "revoked" \
  "$(curl -sf "$BASE$URL2" | json_get "['reason']")"

echo "== 8. audit trail =="
wc -l < "$PRESIGN_AUDIT_LOG_PATH" | xargs echo "   audit events:"
check "audit has issue records" "3" "$(grep -c '\"event\":\"issued\"' "$PRESIGN_AUDIT_LOG_PATH")"
check "audit has deny record" "1" "$(grep -c '\"event\":\"issue_denied\"' "$PRESIGN_AUDIT_LOG_PATH")"

echo
echo "ACCEPTANCE PASSED"
