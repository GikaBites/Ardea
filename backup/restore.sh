#!/bin/sh
# Restore an Ardea backup: ./backup/restore.sh backups/ardea-2026-11-20_0200.dump
# Stops Ardea, replaces the database with the backup (and the settings key, if its .keys.tgz is next to it),
# then starts Ardea again. Everything stored after the backup is lost.
set -eu
cd "$(dirname "$0")/.."
f=${1:-}
[ -f "$f" ] || { echo "Usage: $0 backups/ardea-YYYY-MM-DD_HHMM.dump"; exit 1; }
printf 'This replaces ALL current Ardea data with %s. Type yes to continue: ' "$f"
read -r ok
[ "$ok" = "yes" ] || { echo "Nothing changed."; exit 1; }
set -a; . ./.env; set +a
docker compose stop publisher fetcher worker worker-tasks backup >/dev/null 2>&1 || true
docker compose up -d db
until docker compose exec -T db pg_isready -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"; do sleep 2; done
docker compose exec -T db psql -q -U "$POSTGRES_USER" -d postgres \
  -c "DROP DATABASE IF EXISTS \"$POSTGRES_DB\" WITH (FORCE)" -c "CREATE DATABASE \"$POSTGRES_DB\""
docker compose exec -T db pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner < "$f"
k="${f%.dump}.keys.tgz"
if [ -f "$k" ]; then
    docker compose run --rm --no-deps -T -v "$(pwd)/$k:/restore.tgz:ro" --entrypoint sh backup \
      -c 'rm -rf /keys/* && tar xzf /restore.tgz -C /keys' && echo "Settings key restored."
fi
docker compose up -d
echo "Restored $f. Ardea is starting."
