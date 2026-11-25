#!/usr/bin/env bash
# Run the whole Ares stack locally with one command: the Go control plane, the
# web UI, a deliberately weak practice target on loopback, a demo agent enrolled
# to the demo engagement, and (when a container runtime is available) a
# PostgreSQL container on its own port. Ctrl-C stops everything this script
# started.
#
#   scripts/dev.sh              seeded demo: skips /setup, sign in as
#                               admin@northwind.db / admin, sample engagement,
#                               findings and a connected agent ready. Data
#                               persists in .dev/ (embedded file store)
#   scripts/dev.sh --postgres   the same seeded demo, stored in the dev
#                               PostgreSQL container instead (scripts/postgres.sh)
#   scripts/dev.sh --fresh      wipe the demo data first and reseed (works with
#                               --postgres too: it empties that database)
#   scripts/dev.sh --setup      clean in-memory run that lands on the /setup wizard
#   scripts/dev.sh --no-agent   do not start the demo agent
#   scripts/dev.sh --no-pg      do not start the PostgreSQL container
#   scripts/dev.sh --rerun-jobs dispatch the sample jobs again on a seeded store
#
# Settings can also come from a .dev.env file in the repo root (copy
# scripts/dev.env.example). Environment (all optional):
#   ARES_ADDR       control-plane listen address        (default :8080)
#   WEB_PORT        web dev-server port                 (default 5173)
#   PRACTICE_ADDR   practice target, loopback only      (default 127.0.0.1:8089)
#   DEV_DIR         where the seeded database, key and agent state live (default .dev)
#   DEV_EMAIL / DEV_PASSWORD   demo super-admin         (default admin@northwind.db / admin)
#   ARES_PG         auto | on | off — the Postgres container (default auto: on
#                   when Apple's `container` CLI is installed; --postgres forces on)
#   ARES_PG_RUNTIME auto | container | docker (see scripts/postgres.sh)
#   ARES_PG_PORT    Postgres host port                  (default 55433)
#
# The demo credential is weak on purpose and only ever written by this script's
# seeder. Never use it, or this script, for a real deployment.
#
# Written for the bash 3.2 that ships with macOS (no `wait -n`, no mapfile).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Optional local settings (gitignored), loaded before the flags so a flag wins.
if [ -f "$ROOT/.dev.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/.dev.env"
  set +a
fi

MODE=demo
FRESH=0
STORE=file
RERUN=0
for arg in "$@"; do
  case "$arg" in
    --setup) MODE=setup ;;
    --fresh) FRESH=1 ;;
    --postgres|--pg) STORE=postgres ;;
    --no-pg) ARES_PG=off ;;
    --no-agent) DEV_AGENT=off ;;
    --rerun-jobs) RERUN=1 ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
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
: "${DEV_AGENT:=on}"

if [ "$STORE" = postgres ]; then
  if [ "$MODE" = setup ]; then
    echo "--postgres and --setup do not mix: --setup is an in-memory first run." >&2
    exit 2
  fi
  if [ "$ARES_PG" = off ]; then
    echo "--postgres needs the PostgreSQL container; drop --no-pg (or ARES_PG=off)." >&2
    exit 2
  fi
  ARES_PG=on
fi
[ "$MODE" = setup ] && DEV_AGENT=off

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
echo "==> building the Go binaries…"
go build -o "$BIN_DIR/ares-server" ./cmd/ares-server
go build -o "$BIN_DIR/ares-devseed" ./cmd/ares-devseed
go build -o "$BIN_DIR/ares-practice" ./cmd/ares-practice
if [ "$DEV_AGENT" = on ]; then
  go build -o "$BIN_DIR/ares-agent" ./cmd/ares-agent
fi

# ---- PostgreSQL (container) ---------------------------------------------------
# On by default only with Apple's `container` CLI (it is light and starts on
# demand); with Docker it starts when asked: --postgres or ARES_PG=on.
PG_STARTED=0
pg_wanted=0
if [ "$ARES_PG" = on ]; then
  pg_wanted=1
elif [ "$ARES_PG" = auto ] && command -v container >/dev/null 2>&1; then
  pg_wanted=1
fi
if [ "$pg_wanted" = 1 ]; then
  if scripts/postgres.sh up; then
    PG_STARTED=1
    ARES_PG_URL="$(scripts/postgres.sh url)"
    export ARES_PG_URL
  elif [ "$STORE" = postgres ] || [ "$ARES_PG" = on ]; then
    echo "PostgreSQL did not start (see above); it is needed for this run." >&2
    exit 1
  else
    echo "    PostgreSQL did not start; carrying on without it (the file-store demo does not need it)."
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
  # Each store keeps its own master key, so wiping one demo never leaves the
  # other with settings sealed under a key that no longer exists.
  if [ "$STORE" = postgres ]; then
    STORE_DIR="$DEV_DIR/postgres"
  else
    STORE_DIR="$DEV_DIR"
  fi
  if [ "$FRESH" = 1 ]; then
    echo "==> --fresh: removing the $STORE demo's data"
    if [ "$STORE" = postgres ]; then
      rm -rf "$STORE_DIR"
      scripts/postgres.sh reset
    else
      rm -f "$DEV_DIR/ares.db" "$DEV_DIR/ares.key"
    fi
  fi
  mkdir -p "$STORE_DIR"
  if [ "$STORE" = postgres ]; then
    export ARES_DB="$ARES_PG_URL"
  else
    export ARES_DB="$DEV_DIR/ares.db"
  fi
  export ARES_KEY_FILE="$STORE_DIR/ares.key"
  unset ARES_MASTER_KEY || true
  echo "==> seeding the $STORE store (skipped if already seeded)"
  "$BIN_DIR/ares-devseed" prepare -db "$ARES_DB" -key "$ARES_KEY_FILE" \
    -email "$DEV_EMAIL" -password "$DEV_PASSWORD"
fi

# ---- start everything --------------------------------------------------------
echo "==> practice target  http://${PRACTICE_ADDR}   (deliberately weak, loopback only)"
"$BIN_DIR/ares-practice" -addr "$PRACTICE_ADDR" &
pids="$pids $!"

if [ "$STORE" = postgres ]; then
  echo "==> control plane    $API   (store: PostgreSQL on 127.0.0.1:${ARES_PG_PORT:-55433})"
else
  echo "==> control plane    $API   (ARES_DB=$ARES_DB)"
fi
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
  rerun_flag=""
  [ "$RERUN" = 1 ] && rerun_flag="-rerun"
  # shellcheck disable=SC2086
  "$BIN_DIR/ares-devseed" populate -api "$API" -email "$DEV_EMAIL" -password "$DEV_PASSWORD" \
    -target "http://${PRACTICE_ADDR}" -samples "$ROOT/samples" $rerun_flag \
    || echo "    (demo jobs could not be loaded; the app still works)"
fi

AGENT_UP=0
if [ "$DEV_AGENT" = on ]; then
  # The server keeps enrolled agents in memory, so the demo agent enrolls
  # afresh on every start with a new one-time install key.
  AGENT_STATE="$DEV_DIR/agent"
  rm -rf "$AGENT_STATE"
  echo "==> demo agent       enrolling to the demo engagement (loopback, safe checks only)"
  if key="$("$BIN_DIR/ares-devseed" agent-key -api "$API" -email "$DEV_EMAIL" -password "$DEV_PASSWORD")" \
     && "$BIN_DIR/ares-agent" enroll --server "$API" --key "$key" --state "$AGENT_STATE"; then
    "$BIN_DIR/ares-agent" run --state "$AGENT_STATE" &
    pids="$pids $!"
    AGENT_UP=1
    "$BIN_DIR/ares-devseed" agent-job -api "$API" -email "$DEV_EMAIL" -password "$DEV_PASSWORD" \
      -target "http://${PRACTICE_ADDR}" \
      || echo "    (no agent jobs were dispatched; the agent is still connected)"
  else
    echo "    (the demo agent could not enroll; carrying on without it)"
  fi
  unset key
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
  if [ "$STORE" = postgres ]; then
    echo "  Datastore:        PostgreSQL (scripts/postgres.sh psql to look inside)"
  else
    echo "  Datastore:        $ARES_DB"
  fi
  if [ "$AGENT_UP" = 1 ]; then
    echo "  Demo agent:       connected (state in $AGENT_STATE; see the Agents page)"
  fi
else
  echo "  First run:        the app opens on /setup (in-memory; nothing is kept)"
fi
if [ "$PG_STARTED" = 1 ] && [ "$STORE" != postgres ]; then
  echo "  PostgreSQL:       running on 127.0.0.1:${ARES_PG_PORT:-55433} (not used by this run; try --postgres)"
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
