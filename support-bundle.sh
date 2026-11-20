#!/bin/sh
# Ardea support bundle: one file with the logs, versions and health of this installation, for a support request.
#
#   ./support-bundle.sh            (last 72 hours of logs)
#   ./support-bundle.sh 24         (last 24 hours)
#
# Passwords, API keys, tokens, webhook addresses, sealed settings and .env secrets are removed before the file
# is saved (worker/support_bundle.py). Nothing is sent anywhere: read the file, then send it if you want to.
# Needs the worker container (it is started for a moment if it is not running).
set -eu
cd "$(dirname "$0")"
hours=${1:-72}
case "$hours" in ''|*[!0-9]*) echo "Usage: $0 [hours of logs, default 72]"; exit 1 ;; esac

DC="docker compose"
if ! docker info >/dev/null 2>&1; then
    if sudo -n docker info >/dev/null 2>&1 || sudo docker info >/dev/null 2>&1; then DC="sudo docker compose"
    else echo "Docker is not running, or this user may not use it."; exit 1; fi
fi

umask 077
raw=$(mktemp -d)
trap 'rm -rf "$raw"' EXIT INT TERM
mkdir -p "$raw/logs"
printf '%s\n' "$hours" > "$raw/log-hours"

echo "Collecting versions and system information"
{
    echo "# Ardea"
    if command -v git >/dev/null 2>&1 && [ -d .git ]; then
        echo "version $(git describe --tags --always --dirty 2>/dev/null || echo unknown)"
        echo "commit  $(git log -1 --format='%h %cs' 2>/dev/null || echo unknown)"
        echo "changed files: $(git status --porcelain 2>/dev/null | wc -l)"
    else
        echo "version unknown (not a git checkout)"
    fi
    echo; echo "# Docker"
    docker version --format 'docker {{.Server.Version}} (client {{.Client.Version}})' 2>/dev/null || $DC version 2>/dev/null | head -1
    echo "compose $($DC version --short 2>/dev/null || echo unknown)"
    echo; echo "# Images"
    $DC images 2>/dev/null || true
} > "$raw/versions.txt" 2>&1
{
    echo "# Operating system"; uname -srm
    [ -r /etc/os-release ] && grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
    echo; echo "# CPU and memory"; echo "cpus $(nproc 2>/dev/null || echo ?)"; free -m 2>/dev/null || true
    echo; echo "# Disk (this folder)"; df -h . 2>/dev/null || true
    echo; echo "# Backups folder"; ls -la backups 2>/dev/null | tail -n 20 || echo "(none)"
    echo; echo "# Uptime"; uptime 2>/dev/null || true
} > "$raw/system.txt" 2>&1
$DC ps -a > "$raw/compose-ps.txt" 2>&1 || true

# Used only to know which values to remove: the bundle gets setting names, never .env's secret values.
[ -f .env ] && cp .env "$raw/env"
[ -f siems/siems.json ] && cp siems/siems.json "$raw/siems.json"

echo "Collecting logs (last $hours hours)"
for s in $($DC config --services 2>/dev/null); do
    $DC logs --no-color --timestamps --since "${hours}h" --tail 20000 "$s" > "$raw/logs/$s.log" 2>&1 || true
done

out="ardea-support-$(date '+%Y-%m-%d_%H%M').tar.gz"
echo "Removing secrets"
if [ -n "$($DC ps -q --status running worker 2>/dev/null)" ]; then
    run="$DC exec -T worker python support_bundle.py"
else
    run="$DC run --rm --no-deps -T worker python support_bundle.py"
fi
if tar -cf - -C "$raw" . | $run > "$out.part" && [ -s "$out.part" ]; then
    mv "$out.part" "$out"
    chmod 600 "$out"
    echo
    echo "Saved $(pwd)/$out"
    echo "Secrets were removed, but the logs can still contain names of your computers, users and alerts."
    echo "Look inside before you send it:  tar -xzf $out"
else
    rm -f "$out.part"
    echo "The support bundle could not be made (see above). Nothing was saved."
    exit 1
fi
