#!/bin/sh
# Ardea backups: the database (pg_dump) and the Settings page key (settings_keys volume), every night and on
# request from the Settings page. Runs in the "backup" service (postgres image, so pg_dump matches the server).
# Settings (Settings -> Backups): BACKUP_ENABLED, BACKUP_TIME (HH:00), BACKUP_KEEP_DAYS. Results: backup_runs.
set -u
DIR=${BACKUP_DIR:-/backups}
KEYS=${KEYS_DIR:-/keys}
export PGHOST="${POSTGRES_HOST:-db}" PGPORT="${POSTGRES_PORT:-5432}" PGUSER="$POSTGRES_USER" PGPASSWORD="$POSTGRES_PASSWORD" PGDATABASE="$POSTGRES_DB"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') backup: $*"; }
q() { psql -X -q -t -A -v ON_ERROR_STOP=1 "$@"; }
qv() {  # qv "SQL with :'var'" -v var=value ...   (psql only fills in variables for SQL read from stdin)
    sql=$1; shift
    printf '%s\n' "$sql" | psql -X -q -t -A -v ON_ERROR_STOP=1 "$@"
}
setting() {  # .env value, else the Settings page, else the default
    v=$(eval "printf '%s' \"\${$1:-}\"")
    [ -n "$v" ] && { printf '%s' "$v"; return; }
    v=$(qv "SELECT value FROM app_settings WHERE name = :'n' AND NOT secret" -v n="$1" 2>/dev/null)
    [ -n "$v" ] && printf '%s' "$v" || printf '%s' "$2"
}

run_backup() {  # $1 = id of the backup_runs row
    id=$1
    stamp=$(date '+%Y-%m-%d_%H%M')
    name="ardea-$stamp"
    qv "UPDATE backup_runs SET status = 'running', started_at = NOW() WHERE id = :id" -v id="$id" >/dev/null
    mkdir -p "$DIR"
    if ! out=$(pg_dump -Fc -f "$DIR/$name.dump.part" 2>&1); then
        rm -f "$DIR/$name.dump.part"
        qv "UPDATE backup_runs SET status = 'failed', finished_at = NOW(), detail = :'d' WHERE id = :id" \
           -v id="$id" -v d="$(printf '%s' "$out" | tail -c 400)" >/dev/null
        log "FAILED: $out"
        return
    fi
    mv "$DIR/$name.dump.part" "$DIR/$name.dump"
    keys=""
    if [ -d "$KEYS" ] && [ -n "$(ls -A "$KEYS" 2>/dev/null)" ]; then
        (umask 077; tar czf "$DIR/$name.keys.tgz" -C "$KEYS" .) && keys=" and the settings key"
    fi
    chmod 600 "$DIR/$name".* 2>/dev/null
    bytes=$(stat -c %s "$DIR/$name.dump")
    keep=$(setting BACKUP_KEEP_DAYS 14)
    case "$keep" in ''|*[!0-9]*) keep=14 ;; esac
    [ "$keep" -lt 1 ] && keep=1
    removed=$(find "$DIR" -maxdepth 1 -name 'ardea-*' -type f -mtime +"$((keep - 1))" -print -delete | wc -l)
    qv "UPDATE backup_runs SET status = 'ok', finished_at = NOW(), file = :'f', bytes = :b, detail = :'d' WHERE id = :id" \
       -v id="$id" -v f="$name.dump" -v b="$bytes" \
       -v d="Database$keys saved. $removed old file(s) removed (keeping $keep days)." >/dev/null
    log "saved $name.dump ($bytes bytes)$keys; removed $removed old file(s)"
}

log "waiting for the database"
until pg_isready -q; do sleep 3; done
until q -c "SELECT 1 FROM backup_runs LIMIT 1" >/dev/null 2>&1; do sleep 10; done   # created by the web UI
log "ready: backups go to the backups folder next to docker-compose.yml"
while true; do
    q -c "UPDATE backup_runs SET status = 'failed', detail = 'The backup service stopped during this backup.'
          WHERE status = 'running' AND started_at < NOW() - interval '6 hours'" >/dev/null 2>&1
    id=$(q -c "SELECT id FROM backup_runs WHERE status = 'requested' ORDER BY id LIMIT 1" 2>/dev/null)
    if [ -z "$id" ] && [ "$(setting BACKUP_ENABLED true)" = "true" ]; then
        at=$(setting BACKUP_TIME 02:00)
        hour=${at%%:*}
        now=$(date '+%H')
        if [ "$now" = "$hour" ]; then
            done_today=$(q -c "SELECT count(*) FROM backup_runs WHERE kind = 'scheduled'
                                AND created_at > NOW() - interval '20 hours'" 2>/dev/null)
            if [ "${done_today:-1}" = "0" ]; then
                id=$(q -c "INSERT INTO backup_runs (kind, status) VALUES ('scheduled', 'requested') RETURNING id" | head -1)
            fi
        fi
    fi
    [ -n "$id" ] && run_backup "$id"
    [ "${BACKUP_ONCE:-}" = "1" ] && exit 0          # tests
    sleep 30
done
