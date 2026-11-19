#!/usr/bin/env bash
# Ardea installer. Run it on the Linux server that will run Ardea:
#
#   curl -fsSL https://raw.githubusercontent.com/GikaBites/Ardea/main/install.sh | bash
#
# or, inside a copy of the repository:  ./install.sh
#
# It checks Docker, downloads Ardea (into ./ardea) if needed, asks four questions, writes .env with a random
# database password, starts everything and prints the address and the first admin password.
# Running it again is safe: an existing .env is kept, and Ardea is only updated and restarted.
# Non-interactive: ARDEA_ADDRESS=ardea.example.com LLM_URL=http://10.0.0.5:11434 LLM_MODEL=qwen3:14b ./install.sh --yes
set -euo pipefail

REPO="${ARDEA_REPO:-https://github.com/GikaBites/Ardea.git}"
DIR="${ARDEA_DIR:-ardea}"
YES=0
[ "${1:-}" = "--yes" ] && YES=1

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die() { printf '\n\033[31mStopped:\033[0m %s\n' "$*" >&2; exit 1; }
ask() {  # ask "Question" "default" -> answer (reads from the terminal, also when piped from curl)
    local q=$1 def=$2 a=""
    if [ "$YES" = 1 ] || ! [ -r /dev/tty ]; then printf '%s' "$def"; return; fi
    printf '%s [%s]: ' "$q" "$def" > /dev/tty
    read -r a < /dev/tty || true
    printf '%s' "${a:-$def}"
}

bold "Ardea installer"
echo

# ---------------------------------------------------------------- 1. what this server needs
bold "1. Checking this server"
[ "$(uname -s)" = "Linux" ] || die "Ardea runs on Linux. This is $(uname -s)."
SUDO=""
if ! docker info >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null && sudo docker info >/dev/null 2>&1; then SUDO="sudo"
    elif command -v docker >/dev/null 2>&1; then
        sudo docker info >/dev/null 2>&1 && SUDO="sudo" || die "Docker is installed but not running. Start it: sudo systemctl start docker"
    else
        die "Docker is not installed. Install it with: curl -fsSL https://get.docker.com | sh   then run this again."
    fi
fi
ok "Docker is running"
$SUDO docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is missing. Install the docker-compose-plugin package."
ok "Docker Compose $($SUDO docker compose version --short 2>/dev/null)"
command -v git >/dev/null 2>&1 || die "git is missing. Install it (sudo apt install git, or sudo dnf install git)."
mem=$(awk '/MemTotal/ {print int($2/1024/1024)}' /proc/meminfo)
[ "$mem" -ge 4 ] && ok "${mem} GB of memory" || warn "Only ${mem} GB of memory: Ardea itself needs about 4 GB (Ollama is extra)."
free_gb=$(df -Pk . | awk 'NR==2 {print int($4/1024/1024)}')
[ "$free_gb" -ge 10 ] && ok "${free_gb} GB of free disk" || warn "Only ${free_gb} GB of free disk: 10 GB or more is recommended."

# ---------------------------------------------------------------- 2. the code
echo; bold "2. Getting Ardea"
if [ -f docker-compose.yml ] && [ -d worker ] && [ -d publisher ]; then
    ok "Using this folder: $(pwd)"
else
    if [ -d "$DIR/.git" ]; then
        git -C "$DIR" pull --ff-only -q && ok "Updated $DIR"
    else
        git clone -q "$REPO" "$DIR" && ok "Downloaded into $(cd "$DIR" && pwd)"
    fi
    cd "$DIR"
fi

# ---------------------------------------------------------------- 3. settings
echo; bold "3. Settings"
if [ -f .env ]; then
    ok ".env exists: kept as it is"
else
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    tz=$(cat /etc/timezone 2>/dev/null || timedatectl show -p Timezone --value 2>/dev/null || echo UTC)
    echo "  Four questions. Press Enter to accept the suggestion in brackets."
    address=${ARDEA_ADDRESS:-$(ask "  Address people type in the browser (name or IP)" "${ip:-localhost}")}
    llm=${LLM_URL:-$(ask "  Where Ollama runs" "http://host.docker.internal:11434")}
    models=""
    probe=${llm/host.docker.internal/localhost}
    if command -v curl >/dev/null 2>&1 && models=$(curl -fsS --max-time 5 "$probe/api/tags" 2>/dev/null \
            | grep -o '"name":"[^"]*"' | cut -d'"' -f4 | tr '\n' ' '); then
        if [ -n "$models" ]; then ok "Ollama answers. Installed models: $models"; else warn "Ollama answers but has no model yet: ollama pull qwen3:14b"; fi
    else
        warn "Ollama does not answer at $probe yet. You can fix this later on the Settings page."
    fi
    def_model=${models%% *}
    model=${LLM_MODEL:-$(ask "  Model to use" "${def_model:-qwen3:14b}")}
    tz=${TZ_NAME:-$(ask "  Time zone" "$tz")}
    pw=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 40)
    cp .env.example .env
    sed -i "s|^TZ=.*|TZ=$tz|; s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$pw|; s|^ARDEA_SITE_ADDRESS=.*|ARDEA_SITE_ADDRESS=$address|" .env
    case "$address" in *[0-9].*[0-9]) echo "ARDEA_DEFAULT_SNI=$address" >> .env ;; esac
    {
        echo
        echo "# Written by install.sh"
        echo "LLM_URL=$llm"
        echo "LLM_MODEL=$model"
    } >> .env
    chmod 600 .env
    ok ".env written (database password generated)"
fi
mkdir -p backups

# ---------------------------------------------------------------- 4. start
echo; bold "4. Starting Ardea (the first start builds the containers: a few minutes)"
$SUDO docker compose up -d --build
echo -n "  Waiting for the web console"
for _ in $(seq 1 90); do
    [ "$($SUDO docker inspect -f '{{.State.Health.Status}}' Ardea_publisher 2>/dev/null)" = "healthy" ] && break
    echo -n "."; sleep 2
done
echo
pass=$($SUDO docker compose logs publisher 2>/dev/null | grep -o 'Temporary password: [^ ]*' | tail -1 | awk '{print $3}')
addr=$(grep '^ARDEA_SITE_ADDRESS=' .env | cut -d= -f2 | cut -d, -f1 | tr -d ' ')

echo; bold "Done."
echo "  Open:      https://${addr:-localhost}/"
echo "  Sign in:   admin"
if [ -n "$pass" ]; then
    echo "  Password:  $pass   (one-time: you choose your own on first sign-in)"
else
    echo "  Password:  the one you chose (first install: $SUDO docker compose logs publisher | grep 'Temporary password')"
fi
echo
echo "  Then open Settings → Start here: it shows what is left to set up (your Elastic SIEM and its two keys)."
echo "  The browser warns about the certificate until you install Ardea's root certificate:"
echo "    $SUDO docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./ardea-root-ca.crt"
