#!/usr/bin/env bash
# PostgreSQL for local development, run in Apple's `container` runtime
# (https://github.com/apple/container) on its own port, so it never clashes with
# a Postgres or another container already on this machine.
#
#   scripts/postgres.sh up       start it (creates the container and volume once)
#   scripts/postgres.sh down     stop it (data is kept in the volume)
#   scripts/postgres.sh status   show whether it is running
#   scripts/postgres.sh psql     open a psql shell inside it
#   scripts/postgres.sh url      print the connection URL
#   scripts/postgres.sh destroy  stop it and delete the container and its data
#
# Environment (all optional):
#   ARES_PG_PORT       host port on 127.0.0.1 (default 55433)
#   ARES_PG_NAME       container name (default ares-dev-postgres)
#   ARES_PG_VOLUME     data volume name (default ares-dev-pgdata)
#   ARES_PG_IMAGE      image (default docker.io/library/postgres:17-alpine)
#   ARES_PG_USER / ARES_PG_PASSWORD / ARES_PG_DB   (default ares / ares-dev / ares)
#
# Note: Ares does not use PostgreSQL yet. The embedded file store is the only
# datastore wired today (the setup wizard lists PostgreSQL as "coming soon").
# This container is staged so the database is ready when that backend lands.
set -euo pipefail

: "${ARES_PG_PORT:=55433}"
: "${ARES_PG_NAME:=ares-dev-postgres}"
: "${ARES_PG_VOLUME:=ares-dev-pgdata}"
: "${ARES_PG_IMAGE:=docker.io/library/postgres:17-alpine}"
: "${ARES_PG_USER:=ares}"
: "${ARES_PG_PASSWORD:=ares-dev}"
: "${ARES_PG_DB:=ares}"

url() { echo "postgres://${ARES_PG_USER}:${ARES_PG_PASSWORD}@127.0.0.1:${ARES_PG_PORT}/${ARES_PG_DB}?sslmode=disable"; }

need_container() {
  if ! command -v container >/dev/null 2>&1; then
    echo "Apple's 'container' CLI is not installed (macOS 26 on Apple silicon:" >&2
    echo "https://github.com/apple/container/releases)." >&2
    exit 1
  fi
  # The runtime's background services must be up before any other command.
  if ! container system status >/dev/null 2>&1; then
    echo "==> starting the container system service…"
    container system start
  fi
}

exists()  { container inspect "$ARES_PG_NAME" >/dev/null 2>&1; }
running() { container ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$ARES_PG_NAME"; }

wait_ready() {
  printf "==> waiting for PostgreSQL"
  for _ in $(seq 1 60); do
    if container exec "$ARES_PG_NAME" pg_isready -q -U "$ARES_PG_USER" -d "$ARES_PG_DB" >/dev/null 2>&1; then
      echo " ready"
      return 0
    fi
    printf "."
    sleep 1
  done
  echo
  echo "PostgreSQL did not become ready; see: container logs $ARES_PG_NAME" >&2
  return 1
}

up() {
  need_container
  if running; then
    echo "==> PostgreSQL already running ($ARES_PG_NAME on 127.0.0.1:$ARES_PG_PORT)"
  elif exists; then
    echo "==> starting existing container $ARES_PG_NAME"
    container start "$ARES_PG_NAME" >/dev/null
  else
    if ! container volume inspect "$ARES_PG_VOLUME" >/dev/null 2>&1; then
      container volume create "$ARES_PG_VOLUME" >/dev/null
    fi
    echo "==> creating $ARES_PG_NAME ($ARES_PG_IMAGE) on 127.0.0.1:$ARES_PG_PORT"
    # PGDATA sits in a subdirectory: a fresh volume's root is not empty
    # (lost+found), which initdb refuses.
    container run -d \
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
  down) need_container; if running; then container stop "$ARES_PG_NAME" >/dev/null; fi; echo "==> PostgreSQL stopped (data kept in volume $ARES_PG_VOLUME)" ;;
  status)
    need_container
    if running; then echo "running: $ARES_PG_NAME on 127.0.0.1:$ARES_PG_PORT"; echo "$(url)";
    elif exists; then echo "stopped: $ARES_PG_NAME (scripts/postgres.sh up to start)";
    else echo "not created yet (scripts/postgres.sh up)"; fi ;;
  psql) need_container; exec container exec -it "$ARES_PG_NAME" psql -U "$ARES_PG_USER" -d "$ARES_PG_DB" ;;
  url) url ;;
  destroy)
    need_container
    if running; then container stop "$ARES_PG_NAME" >/dev/null; fi
    if exists; then container rm "$ARES_PG_NAME" >/dev/null; fi
    if container volume inspect "$ARES_PG_VOLUME" >/dev/null 2>&1; then container volume rm "$ARES_PG_VOLUME" >/dev/null; fi
    echo "==> removed $ARES_PG_NAME and its data" ;;
  *) sed -n '2,25p' "$0"; exit 2 ;;
esac
