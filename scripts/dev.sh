#!/usr/bin/env bash
# Run the whole Ares stack locally with one command: the Go control plane, the
# web UI, a deliberately weak practice target on loopback, and (on a Mac with
# Apple's `container` CLI) a PostgreSQL container on its own port. Ctrl-C stops
# everything this script started.
#
#   scripts/dev.sh            seeded demo: skips /setup, sign in as
#                             admin@northwind.db / admin, sample engagement and
#                             findings ready. Data persists in .dev/
#   scripts/dev.sh --fresh    same, but wipe .dev/ first and reseed
#   scripts/dev.sh --setup    clean in-memory run that lands on the /setup wizard
#   scripts/dev.sh --no-pg    do not start the PostgreSQL container
#
# Environment (all optional):
#   ARES_ADDR       control-plane listen address        (default :8080)
#   WEB_PORT        web dev-server port                 (default 5173)
#   PRACTICE_ADDR   practice target, loopback only      (default 127.0.0.1:8089)
#   DEV_DIR         where the seeded database and key live (default .dev)
#   DEV_EMAIL / DEV_PASSWORD   demo super-admin         (default admin@northwind.db / admin)
#   ARES_PG         auto | on | off — the Postgres container (default auto: on
#                   when Apple's `container` CLI is installed)
#   ARES_PG_PORT    Postgres host port                  (default 55433)
#
# The demo credential is weak on purpose and only ever written by this script's
# seeder. Never use it, or this script, for a real deployment.
#
# Written for the bash 3.2 that ships with macOS (no `wait -n`, no mapfile).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE=demo
FRESH=0
for arg in "$@"; do
  case "$arg" in
    --setup) MODE=setup ;;
    --fresh) FRESH=1 ;;
    --no-pg) ARES_PG=off ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

: "${ARES_ADDR:=:8080}"
: "${WEB_PORT:=5173}"
: "${PRACTICE_ADDR:=127.0.0.1:8089}"
: "${DEV_DIR:=$ROOT/.dev}"
: "${DEV_EMAIL:=admin@northwind.db}"
: "${DEV_PASSWORD:=admin}"
: "${ARES_PG:=auto}"

PORT="${ARES_ADDR##*:}"
API="http://127.0.0.1:${PORT}"
export ARES_ADDR
# Keep the web dev server's proxy pointed at wherever the backend listens. The
# browser stays same-origin through that proxy, so VITE_ARES_URL (which makes
# the browser call the backend directly, cross-origin) must not be set here.
export ARES_PROXY_TARGET="$API"
unset VITE_ARES_URL || true

# ---- preflight --------------------------------------------------------------
for tool in go bun curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool not found. Install it (bun: https://bun.sh) and run scripts/setup.sh." >&2
    exit 1
  fi
done
if [ ! -d web/node_modules ]; then
  echo "==> web dependencies missing; installing (bun install)…"
  ( cd web && bun install )
fi
if curl -fsS -o /dev/null "$API/healthz" 2>/dev/null; then
  echo "Something is already answering on $API. Stop it or set ARES_ADDR." >&2
  exit 1
fi

BIN_DIR="$(mktemp -d)"
pids=""
cleanup() {
  trap - INT TERM EXIT
  echo
  echo "Shutting down…"
  for p in $pids; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$BIN_DIR"
  if [ "${PG_STARTED:-0}" = 1 ]; then
    echo "(PostgreSQL keeps running for other tools; stop it with: scripts/postgres.sh down)"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM   # exiting runs the EXIT trap, which cleans up once

# Build once and run the binaries directly: `go run` would leave the compiled
# server orphaned on Ctrl-C because it does not forward the signal to its child.
echo "==> building control plane, seeder and practice target…"
go build -o "$BIN_DIR/ares-server" ./cmd/ares-server
go build -o "$BIN_DIR/ares-devseed" ./cmd/ares-devseed
go build -o "$BIN_DIR/ares-practice" ./cmd/ares-practice

# ---- PostgreSQL (Apple container, staged) ------------------------------------
PG_STARTED=0
if [ "$ARES_PG" != off ]; then
  if command -v container >/dev/null 2>&1; then
    if scripts/postgres.sh up; then
      PG_STARTED=1
      ARES_PG_URL="$(scripts/postgres.sh url)"
      export ARES_PG_URL
      echo "    note: Ares still stores its data in the embedded file store; PostgreSQL is"
      echo "          staged for the upcoming Postgres backend and is not used by the app yet."
    else
      echo "    PostgreSQL did not start; carrying on without it (the app does not need it yet)."
    fi
  elif [ "$ARES_PG" = on ]; then
    echo "ARES_PG=on but Apple's 'container' CLI is not installed." >&2
    exit 1
  fi
fi

# ---- datastore ---------------------------------------------------------------
if [ "$MODE" = setup ]; then
  # Fresh, ephemeral install: no account, no key, so the app opens on /setup.
  # The key goes to a throwaway directory so a stray ./ares.key is never used.
  export ARES_DB=memory
  export ARES_KEY_FILE="$BIN_DIR/ares.key"
  unset ARES_MASTER_KEY || true
else
  if [ "$FRESH" = 1 ] && [ -d "$DEV_DIR" ]; then
    echo "==> --fresh: removing $DEV_DIR"
    rm -rf "$DEV_DIR"
  fi
  mkdir -p "$DEV_DIR"
  export ARES_DB="$DEV_DIR/ares.db"
  export ARES_KEY_FILE="$DEV_DIR/ares.key"
  unset ARES_MASTER_KEY || true
  echo "==> seeding $ARES_DB (skipped if already seeded)"
  "$BIN_DIR/ares-devseed" prepare -db "$ARES_DB" -key "$ARES_KEY_FILE" \
    -email "$DEV_EMAIL" -password "$DEV_PASSWORD"
fi

# ---- start everything --------------------------------------------------------
echo "==> practice target  http://${PRACTICE_ADDR}   (deliberately weak, loopback only)"
"$BIN_DIR/ares-practice" -addr "$PRACTICE_ADDR" &
pids="$pids $!"

echo "==> control plane    $API   (ARES_DB=$ARES_DB)"
"$BIN_DIR/ares-server" &
pids="$pids $!"

printf "==> waiting for the control plane"
ok=0
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null "$API/healthz" 2>/dev/null; then ok=1; break; fi
  printf "."
  sleep 0.5
done
echo
if [ "$ok" != 1 ]; then
  echo "The control plane did not come up; see the log above." >&2
  exit 1
fi

if [ "$MODE" = demo ]; then
  echo "==> loading the demo engagement and sample jobs"
  "$BIN_DIR/ares-devseed" populate -api "$API" -email "$DEV_EMAIL" -password "$DEV_PASSWORD" \
    -target "http://${PRACTICE_ADDR}" -samples "$ROOT/samples" \
    || echo "    (demo jobs could not be loaded; the app still works)"
fi

echo "==> web UI           http://127.0.0.1:${WEB_PORT}"
( cd web && exec bun run dev --port "${WEB_PORT}" --strictPort ) &
pids="$pids $!"

echo
echo "────────────────────────────────────────────────────────────"
echo "  Ares is running:  http://127.0.0.1:${WEB_PORT}"
if [ "$MODE" = demo ]; then
  echo "  Sign in:          $DEV_EMAIL  /  $DEV_PASSWORD   (dev only)"
  echo "  Demo engagement:  Northwind practice lab (scoped to 127.0.0.1)"
else
  echo "  First run:        the app opens on /setup (in-memory; nothing is kept)"
fi
if [ "$PG_STARTED" = 1 ]; then
  echo "  PostgreSQL:       ${ARES_PG_URL}  (staged, not used yet)"
fi
echo "  Press Ctrl-C to stop."
echo "────────────────────────────────────────────────────────────"

# If any process exits, bring the whole stack down rather than leaving a
# half-running dev env. (A polling loop, because macOS bash has no `wait -n`.)
while :; do
  for p in $pids; do
    if ! kill -0 "$p" 2>/dev/null; then
      echo "A process exited (pid $p); stopping the rest."
      exit 1
    fi
  done
  sleep 1
done
