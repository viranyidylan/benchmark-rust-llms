#!/usr/bin/env bash
# smoke.sh - end-to-end demo of webhook-delivery:
#   1. starts the server (temp db, private destinations allowed, fast retries)
#   2. starts a python3 sink that logs every request
#   3. POSTs a webhook to the sink and polls until the sink logs it
#   4. POSTs a webhook to a dead port (MAX_ATTEMPTS=2) and polls /dlq until it appears
#   5. POSTs /dlq/{id}/retry to requeue it
# The script is idempotent: it builds the binary if missing, uses a fresh temp
# dir every run, and kills every process it started on exit (trap).
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${PROJECT_DIR}/target/release/webhook-delivery"
API_PORT="${SMOKE_API_PORT:-34567}"
SINK_PORT="${SMOKE_SINK_PORT:-34568}"
API="http://127.0.0.1:${API_PORT}"

TMPDIR_RUN="$(mktemp -d /tmp/webhook-smoke.XXXXXX)"
SINK_LOG="${TMPDIR_RUN}/sink.log"
SERVER_LOG="${TMPDIR_RUN}/server.log"
SERVER_PID=""
SINK_PID=""

cleanup() {
  [ -n "${SERVER_PID}" ] && kill "${SERVER_PID}" 2>/dev/null || true
  [ -n "${SINK_PID}" ] && kill "${SINK_PID}" 2>/dev/null || true
  [ -n "${SERVER_PID}" ] && wait "${SERVER_PID}" 2>/dev/null || true
  [ -n "${SINK_PID}" ] && wait "${SINK_PID}" 2>/dev/null || true
  rm -rf "${TMPDIR_RUN}"
}
trap cleanup EXIT

echo "==> building (release, if needed)"
cargo build --release --manifest-path "${PROJECT_DIR}/Cargo.toml" --quiet

echo "==> starting server on ${API} (logs: ${SERVER_LOG})"
(
  cd "${TMPDIR_RUN}"
  BIND_ADDR="127.0.0.1:${API_PORT}" \
  DATABASE_URL="sqlite://smoke.db?mode=rwc" \
  ALLOW_PRIVATE_DESTINATIONS=true \
  MAX_ATTEMPTS=2 \
  BASE_DELAY_MS=200 \
  MAX_DELAY_MS=500 \
  WORKER_POLL_MS=100 \
  HMAC_SECRET=smoke-test-secret \
  RUST_LOG=info,sqlx=warn \
  nohup "${BIN}" >"${SERVER_LOG}" 2>&1 &
  echo $! >"${TMPDIR_RUN}/server.pid"
)
SERVER_PID="$(cat "${TMPDIR_RUN}/server.pid")"

echo "==> starting python sink on 127.0.0.1:${SINK_PORT} (log: ${SINK_LOG})"
cat > "${TMPDIR_RUN}/sink.py" <<'PY'
import http.server, sys
port = int(sys.argv[1]); logpath = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with open(logpath, "a") as f:
            f.write("POST %s\nX-Webhook-Id: %s\nX-Webhook-Signature: %s\nbody: %s\n---\n" % (
                self.path,
                self.headers.get("X-Webhook-Id"),
                self.headers.get("X-Webhook-Signature"),
                body.decode("utf-8", "replace")))
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
nohup python3 "${TMPDIR_RUN}/sink.py" "${SINK_PORT}" "${SINK_LOG}" > /dev/null 2>&1 &
SINK_PID=$!

# --- helpers ---------------------------------------------------------------
have_jq() { command -v jq >/dev/null 2>&1; }
json_get() { # json_get <field>  (reads JSON on stdin)
  if have_jq; then jq -r "$1"; else python3 -c "import sys,json; d=json.load(sys.stdin); print(d$1)"; fi
}
json_get_idx() { # json_get_idx <index> <field>
  if have_jq; then jq -r ".[$1].$2"; else python3 -c "import sys,json; print(json.load(sys.stdin)[$1]['$2'])"; fi
}
wait_for() { # wait_for <seconds> <description> <command...>
  local deadline=$(( $(date +%s) + $1 )); shift; local desc="$1"; shift
  until "$@"; do
    if [ "$(date +%s)" -ge "${deadline}" ]; then
      echo "FAIL: timed out waiting for ${desc}"; echo "--- server log ---"; cat "${SERVER_LOG}"; exit 1
    fi
    sleep 0.3
  done
  echo "OK: ${desc}"
}

# --- 1. health -------------------------------------------------------------
wait_for 20 "server healthy" curl -sf "${API}/health" -o /dev/null
echo "    GET /health -> $(curl -s "${API}/health")"

# --- 2. deliver to the live sink -------------------------------------------
echo "==> POST /webhook -> sink at 127.0.0.1:${SINK_PORT}"
RESP="$(curl -s -X POST "${API}/webhook" -H 'Content-Type: application/json' \
  -d "{\"data\": {\"hello\": \"world\", \"n\": 1}, \"destination\": \"http://127.0.0.1:${SINK_PORT}/hook\"}")"
echo "    response: ${RESP}"
JOB_ID="$(printf '%s' "${RESP}" | json_get .id)"
[ -s "${SINK_LOG}" ] || true   # file may not exist yet
wait_for 20 "delivery to sink" test -s "${SINK_LOG}"
echo "--- sink log (live delivery) ---"
cat "${SINK_LOG}"
echo "--------------------------------"

# --- 3. force a job into the DLQ -------------------------------------------
echo "==> POST /webhook -> dead port 39999 (MAX_ATTEMPTS=2, fast backoff)"
RESP="$(curl -s -X POST "${API}/webhook" -H 'Content-Type: application/json' \
  -d '{"data": {"doomed": true}, "destination": "http://127.0.0.1:39999/never"}')"
echo "    response: ${RESP}"
DEAD_ID="$(printf '%s' "${RESP}" | json_get .id)"

dlq_has() { curl -s "${API}/dlq" | { if have_jq; then jq -e --arg id "${DEAD_ID}" 'any(.[]; .id == $id)' >/dev/null; else python3 -c "import sys,json; sys.exit(0 if any(e['id']=='${DEAD_ID}' for e in json.load(sys.stdin)) else 1)"; fi; }; }
wait_for 30 "job ${DEAD_ID} to appear in DLQ" dlq_has
echo "--- GET /dlq ---"
curl -s "${API}/dlq"
echo
echo "----------------"

# --- 4. retry the dead job --------------------------------------------------
echo "==> POST /dlq/${DEAD_ID}/retry"
curl -s -X POST "${API}/dlq/${DEAD_ID}/retry"
echo
wait_for 20 "retried job to re-enter the DLQ (destination still dead)" dlq_has
echo "--- GET /dlq after retry (job retried and dead again, as expected) ---"
curl -s "${API}/dlq"
echo
echo "-------------------------------------------------------------------------"

echo "==> SMOKE OK"
