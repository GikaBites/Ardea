#!/usr/bin/env bash
# Lock the Ardea `lan` Docker network down to the few LAN services it needs.
# Everything else (the internet included) is rejected, so web search and ntfy can only leave through
# the searxng container or the egress proxy (allowlist in squid.conf).
#
# Run as root on the DOCKER HOST after `docker compose up` (Docker recreates DOCKER-USER on restart,
# so install it as a systemd unit, see README). Re-running it is safe (it rebuilds its own chain).
#
#   sudo ELASTIC=10.0.0.5:9200 OLLAMA=10.0.0.11:11434 SMTP=10.0.0.25:587 ./egress-proxy/firewall.sh
#   sudo ./egress-proxy/firewall.sh --remove
#
# Each of ELASTIC / OLLAMA / SMTP is a space-separated list of IP:PORT (IPs, not hostnames: rules
# are evaluated per packet). DNS needs no rule: containers resolve via Docker's embedded resolver,
# which runs in the host network namespace.
set -euo pipefail

LAN_SUBNET="${ARDEA_LAN_SUBNET:-172.30.10.0/24}"
CHAIN=ARDEA-EGRESS

if [[ "${1:-}" == "--remove" ]]; then
  iptables -D DOCKER-USER -s "$LAN_SUBNET" -j "$CHAIN" 2>/dev/null || true
  iptables -F "$CHAIN" 2>/dev/null || true
  iptables -X "$CHAIN" 2>/dev/null || true
  echo "removed $CHAIN"; exit 0
fi

: "${ELASTIC:?set ELASTIC=ip:port}"
: "${OLLAMA:?set OLLAMA=ip:port}"

iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
for target in $ELASTIC $OLLAMA ${SMTP:-}; do
  ip="${target%:*}"; port="${target##*:}"
  iptables -A "$CHAIN" -d "$ip" -p tcp --dport "$port" -j RETURN
done
iptables -A "$CHAIN" -m limit --limit 6/min -j LOG --log-prefix "ardea-egress-drop: "
iptables -A "$CHAIN" -j REJECT --reject-with icmp-port-unreachable

# hook it in once, at the top of DOCKER-USER
iptables -C DOCKER-USER -s "$LAN_SUBNET" -j "$CHAIN" 2>/dev/null || iptables -I DOCKER-USER 1 -s "$LAN_SUBNET" -j "$CHAIN"
echo "$CHAIN active for $LAN_SUBNET:"
iptables -S "$CHAIN"
