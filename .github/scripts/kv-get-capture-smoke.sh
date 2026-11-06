#!/usr/bin/env bash
# Checks that `kv get` can be captured directly in a non-interactive shell (no TTY), the way
# scripts use it:
#   curl -s -H "Authorization: Bearer $(kv get TORBOX_API_KEY)" https://api.torbox.app/v1/api/user/me
#
# Default (offline): a local mock serves both the kv API and a stand-in for TorBox's
# /v1/api/user/me, which only answers success:true for the exact Bearer token kv returned.
# Live (when KV_SMOKE_API_KEY is set): the real kv server and the real TorBox API.
set -euo pipefail

KV_BIN=${KV_BIN:-target/debug/kv}
KV_BIN=$(realpath "$KV_BIN")
WORK=$(mktemp -d)
export XDG_CONFIG_HOME="$WORK/config" HOME="$WORK"
mkdir -p "$XDG_CONFIG_HOME/kv"
MOCK_PID=
trap '[ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null; rm -rf "$WORK"' EXIT
kv() { "$KV_BIN" --silent "$@"; }

if [ -n "${KV_SMOKE_API_KEY:-}" ]; then
  printf 'api_key = "%s"\n' "$KV_SMOKE_API_KEY" > "$XDG_CONFIG_HOME/kv/config.toml"
  unset KV_BASE_URL
  TORBOX_URL=https://api.torbox.app
else
  PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
  cat > "$WORK/mock.py" <<'PY'
import http.server, sys
TOKEN = "tb-smoke-token-not-a-secret"
class H(http.server.BaseHTTPRequestHandler):
    def reply(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        if self.path == "/kv/TORBOX_API_KEY":
            if self.headers.get("X-Api-Key") == "kv_smoke_api_key":
                return self.reply(200, TOKEN)
            return self.reply(401, '{"error":"unauthorized"}')
        if self.path == "/v1/api/user/me":
            if self.headers.get("Authorization") == "Bearer " + TOKEN:
                return self.reply(200, '{"success":true,"data":{}}')
            return self.reply(401, '{"success":false}')
        self.reply(404, "{}")
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
  python3 "$WORK/mock.py" "$PORT" &
  MOCK_PID=$!
  for _ in $(seq 50); do curl -s "http://127.0.0.1:$PORT/" >/dev/null && break; sleep 0.1; done
  printf 'api_key = "kv_smoke_api_key"\n' > "$XDG_CONFIG_HOME/kv/config.toml"
  export KV_BASE_URL="http://127.0.0.1:$PORT"
  TORBOX_URL="http://127.0.0.1:$PORT"
fi

# The command under test, with stdin closed and no terminal, as in a script or CI job.
RESPONSE=$(curl -s -H "Authorization: Bearer $(kv get TORBOX_API_KEY)" \
  "$TORBOX_URL/v1/api/user/me" </dev/null)

if printf '%s' "$RESPONSE" | grep -q '"success":[[:space:]]*true'; then
  echo "PASS: curl with \$(kv get TORBOX_API_KEY) succeeded"
else
  echo "FAIL: curl with \$(kv get TORBOX_API_KEY) did not succeed" >&2
  exit 1
fi
