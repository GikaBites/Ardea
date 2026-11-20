#!/bin/sh
# Restore an Ardea backup: sudo ./backup/restore.sh backups/ardea-2026-11-20_0200.dump
# Stops Ardea, replaces the database with the backup (and the settings key, if its .keys.tgz is next to it),
# then starts Ardea again. Everything stored after the backup is lost.
# The backup files belong to root (they hold secrets), so run it with sudo.
set -eu
cd "$(dirname "$0")/.."
f=${1:-}
[ -f "$f" ] || { echo "Usage: sudo $0 backups/ardea-YYYY-MM-DD_HHMM.dump"; exit 1; }
# Check everything BEFORE the current data is touched.
[ -r "$f" ] || { echo "Cannot read $f: run this with sudo. Nothing changed."; exit 1; }
k="${f%.dump}.keys.tgz"
if [ -f "$k" ] && ! [ -r "$k" ]; then echo "Cannot read $k: run this with sudo. Nothing changed."; exit 1; fi
envval() {  # the value of one .env line, without running .env as a script (values may hold spaces, <, $)
    v=$(grep -E "^$1=" .env | tail -1 | cut -d= -f2-)
    v=${v#\"}; v=${v%\"}; v=${v#\'}; v=${v%\'}
    printf '%s' "$v"
}
[ -f .env ] || { echo "No .env in $(pwd). Nothing changed."; exit 1; }
POSTGRES_USER=$(envval POSTGRES_USER)
POSTGRES_DB=$(envval POSTGRES_DB)
[ -n "$POSTGRES_USER" ] && [ -n "$POSTGRES_DB" ] || { echo "POSTGRES_USER or POSTGRES_DB missing in .env. Nothing changed."; exit 1; }
docker compose up -d db < /dev/null
until docker compose exec -T db pg_isready -q -U "$POSTGRES_USER" -d "$POSTGRES_DB" < /dev/null; do sleep 2; done
docker compose exec -T db pg_restore --list < "$f" >/dev/null 2>&1 \
  || { echo "$f is not a readable Ardea backup (damaged or incomplete). Nothing changed."; exit 1; }
printf 'This replaces ALL current Ardea data with %s. Type yes to continue: ' "$f"
read -r ok
[ "$ok" = "yes" ] || { echo "Nothing changed."; exit 1; }
docker compose stop publisher fetcher worker worker-tasks backup >/dev/null 2>&1 || true
docker compose exec -T db psql -q -U "$POSTGRES_USER" -d postgres \
  -c "DROP DATABASE IF EXISTS \"$POSTGRES_DB\" WITH (FORCE)" -c "CREATE DATABASE \"$POSTGRES_DB\""
docker compose exec -T db pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner < "$f"
if [ -f "$k" ]; then
    case $k in /*) kabs=$k ;; *) kabs=$(pwd)/$k ;; esac
    docker compose run --rm --no-deps -T -v "$kabs:/restore.tgz:ro" --entrypoint sh backup \
      -c 'rm -rf /keys/* && tar xzf /restore.tgz -C /keys' && echo "Settings key restored."
fi
docker compose up -d
echo "Restored $f. Ardea is starting."
