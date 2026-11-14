#!/usr/bin/env bash
# Run the whole Ares stack locally: the Go control plane and the web UI
# together, with one Ctrl-C stopping both. The web dev server proxies its
# control-plane calls to the backend, so http://127.0.0.1:5173 is the app.
#
# Environment:
#   ARES_ADDR   control-plane listen address (default :8080)
#   ARES_DB     database path, or "memory" for an ephemeral run (default memory)
#   WEB_PORT    web dev-server port (default 5173)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

: "${ARES_ADDR:=:8080}"
: "${ARES_DB:=memory}"   # ephemeral by default; set ARES_DB=ares.db to persist between runs
: "${WEB_PORT:=5173}"
export ARES_ADDR ARES_DB

# Keep the web proxy pointed at wherever the backend actually listens.
PORT="${ARES_ADDR##*:}"
export VITE_ARES_URL="http://127.0.0.1:${PORT}"

if ! command -v bun >/dev/null 2>&1; then
  echo "bun not found. Install it from https://bun.sh (or run scripts/setup.sh)." >&2
  exit 1
fi
if [ ! -d web/node_modules ]; then
  echo "web dependencies missing. Run scripts/setup.sh first." >&2
  exit 1
fi

BIN_DIR="$(mktemp -d)"
pids=()
cleanup() {
  trap - INT TERM EXIT
  echo
  echo "Shutting down…"
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$BIN_DIR"
}
trap cleanup INT TERM EXIT

# Build once and run the binary directly: `go run` would leave the compiled
# server orphaned on Ctrl-C because it does not forward the signal to its child.
echo "==> building control plane…"
go build -o "$BIN_DIR/ares-server" ./cmd/ares-server

echo "==> control plane  http://127.0.0.1:${PORT}   (ARES_DB=${ARES_DB})"
"$BIN_DIR/ares-server" &
pids+=($!)

echo "==> web UI         http://127.0.0.1:${WEB_PORT}"
( cd web && bun run dev --port "${WEB_PORT}" ) &
pids+=($!)

echo
echo "Both running. Open http://127.0.0.1:${WEB_PORT} — press Ctrl-C to stop."

# If either process exits, bring the whole stack down rather than leaving a half-running dev env.
wait -n 2>/dev/null || true
cleanup
