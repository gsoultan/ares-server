#!/usr/bin/env bash
# PostgreSQL for local development, in a container on its own port, so it never
# clashes with a Postgres or another container already on this machine. It uses
# Apple's `container` runtime (https://github.com/apple/container) when that is
# installed, and Docker (Docker Desktop, OrbStack, Colima, Linux) otherwise.
#
#   scripts/postgres.sh up       start it (creates the container and volume once)
#   scripts/postgres.sh down     stop it (data is kept in the volume)
#   scripts/postgres.sh status   show whether it is running
#   scripts/postgres.sh psql     open a psql shell inside it
#   scripts/postgres.sh url      print the connection URL
#   scripts/postgres.sh reset    empty the database, keep the container
#   scripts/postgres.sh runtime  print which container runtime would be used
#   scripts/postgres.sh destroy  stop it and delete the container and its data
#
# Environment (all optional):
#   ARES_PG_RUNTIME    auto | container | docker (default auto: container if
#                      installed, else docker)
#   ARES_PG_PORT       host port on 127.0.0.1 (default 55433)
#   ARES_PG_NAME       container name (default ares-dev-postgres)
#   ARES_PG_VOLUME     data volume name (default ares-dev-pgdata)
#   ARES_PG_IMAGE      image (default docker.io/library/postgres:17-alpine)
#   ARES_PG_USER / ARES_PG_PASSWORD / ARES_PG_DB   (default ares / ares-dev / ares)
#
# The server runs on this database when ARES_DB (or ARES_PG_URL) is its URL;
# `scripts/dev.sh --postgres` does that for the seeded demo.
set -euo pipefail

: "${ARES_PG_RUNTIME:=auto}"
: "${ARES_PG_PORT:=55433}"
: "${ARES_PG_NAME:=ares-dev-postgres}"
: "${ARES_PG_VOLUME:=ares-dev-pgdata}"
: "${ARES_PG_IMAGE:=docker.io/library/postgres:17-alpine}"
: "${ARES_PG_USER:=ares}"
: "${ARES_PG_PASSWORD:=ares-dev}"
: "${ARES_PG_DB:=ares}"

url() { echo "postgres://${ARES_PG_USER}:${ARES_PG_PASSWORD}@127.0.0.1:${ARES_PG_PORT}/${ARES_PG_DB}?sslmode=disable"; }

# pick_runtime sets RT to the container CLI to use.
pick_runtime() {
  case "$ARES_PG_RUNTIME" in
    container|docker) RT="$ARES_PG_RUNTIME" ;;
    auto)
      if command -v container >/dev/null 2>&1; then RT=container
      elif command -v docker >/dev/null 2>&1; then RT=docker
      else RT=""; fi ;;
    *) echo "ARES_PG_RUNTIME must be auto, container or docker" >&2; exit 2 ;;
  esac
}

need_runtime() {
  pick_runtime
  if [ -z "$RT" ] || ! command -v "$RT" >/dev/null 2>&1; then
    echo "No container runtime found. Install Apple's 'container' CLI (macOS 26 on" >&2
    echo "Apple silicon: https://github.com/apple/container/releases) or Docker." >&2
    exit 1
  fi
  if [ "$RT" = container ]; then
    # The runtime's background services must be up before any other command.
    if ! container system status >/dev/null 2>&1; then
      echo "==> starting the container system service…"
      container system start
    fi
  elif ! docker info >/dev/null 2>&1; then
    echo "Docker is installed but its daemon is not running (start Docker Desktop," >&2
    echo "OrbStack or Colima, then retry)." >&2
    exit 1
  fi
}

exists()  { "$RT" inspect "$ARES_PG_NAME" >/dev/null 2>&1; }
running() {
  if [ "$RT" = docker ]; then
    [ "$(docker inspect -f '{{.State.Running}}' "$ARES_PG_NAME" 2>/dev/null)" = true ]
  else
    container ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$ARES_PG_NAME"
  fi
}
volume_exists() { "$RT" volume inspect "$ARES_PG_VOLUME" >/dev/null 2>&1; }

wait_ready() {
  printf "==> waiting for PostgreSQL"
  for _ in $(seq 1 60); do
    if "$RT" exec "$ARES_PG_NAME" pg_isready -q -U "$ARES_PG_USER" -d "$ARES_PG_DB" >/dev/null 2>&1; then
      echo " ready"
      return 0
    fi
    printf "."
    sleep 1
  done
  echo
  echo "PostgreSQL did not become ready; see: $RT logs $ARES_PG_NAME" >&2
  return 1
}

up() {
  need_runtime
  if running; then
    echo "==> PostgreSQL already running ($ARES_PG_NAME on 127.0.0.1:$ARES_PG_PORT)"
  elif exists; then
    echo "==> starting existing container $ARES_PG_NAME"
    "$RT" start "$ARES_PG_NAME" >/dev/null
  else
    if ! volume_exists; then
      "$RT" volume create "$ARES_PG_VOLUME" >/dev/null
    fi
    echo "==> creating $ARES_PG_NAME ($ARES_PG_IMAGE, $RT) on 127.0.0.1:$ARES_PG_PORT"
    # PGDATA sits in a subdirectory: a fresh volume's root is not empty
    # (lost+found), which initdb refuses.
    "$RT" run -d \
      --name "$ARES_PG_NAME" \
      -p "127.0.0.1:${ARES_PG_PORT}:5432" \
      -v "${ARES_PG_VOLUME}:/var/lib/postgresql/data" \
      -e PGDATA=/var/lib/postgresql/data/pgdata \
      -e POSTGRES_USER="$ARES_PG_USER" \
      -e POSTGRES_PASSWORD="$ARES_PG_PASSWORD" \
      -e POSTGRES_DB="$ARES_PG_DB" \
      "$ARES_PG_IMAGE" >/dev/null
  fi
  wait_ready
  echo "    $(url)"
}

case "${1:-status}" in
  up) up ;;
  down) need_runtime; if running; then "$RT" stop "$ARES_PG_NAME" >/dev/null; fi; echo "==> PostgreSQL stopped (data kept in volume $ARES_PG_VOLUME)" ;;
  status)
    need_runtime
    if running; then echo "running: $ARES_PG_NAME ($RT) on 127.0.0.1:$ARES_PG_PORT"; url;
    elif exists; then echo "stopped: $ARES_PG_NAME (scripts/postgres.sh up to start)";
    else echo "not created yet (scripts/postgres.sh up)"; fi ;;
  psql) need_runtime; exec "$RT" exec -it "$ARES_PG_NAME" psql -U "$ARES_PG_USER" -d "$ARES_PG_DB" ;;
  url) url ;;
  reset)
    # Empty the database (drop and recreate the public schema) but keep the
    # container; scripts/dev.sh --postgres --fresh uses this.
    need_runtime
    running || up
    "$RT" exec "$ARES_PG_NAME" psql -q -U "$ARES_PG_USER" -d "$ARES_PG_DB" \
      -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;" >/dev/null
    echo "==> emptied database $ARES_PG_DB" ;;
  runtime) pick_runtime; echo "${RT:-none}" ;;
  destroy)
    need_runtime
    if running; then "$RT" stop "$ARES_PG_NAME" >/dev/null; fi
    if exists; then "$RT" rm "$ARES_PG_NAME" >/dev/null; fi
    if volume_exists; then "$RT" volume rm "$ARES_PG_VOLUME" >/dev/null; fi
    echo "==> removed $ARES_PG_NAME and its data" ;;
  *) sed -n '2,27p' "$0"; exit 2 ;;
esac
