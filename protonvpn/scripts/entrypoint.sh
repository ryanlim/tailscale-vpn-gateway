#!/bin/sh
set -e

WG_CONF=${WG_CONF:-/etc/wireguard/free-us-8.conf}
WG_IFACE=$(basename "$WG_CONF" .conf)
ACTIVE_IFACE_FILE=/tmp/active_wg_iface
EGRESS_CHECK_INTERVAL=${EGRESS_CHECK_INTERVAL:-60}
EGRESS_CHECK_TIMEOUT=${EGRESS_CHECK_TIMEOUT:-8}
UNHEALTHY_THRESHOLD=${UNHEALTHY_THRESHOLD:-3}

# Tear down any stale interface from a previous run.
wg-quick down "$WG_IFACE" 2>/dev/null || true

echo "Bringing up WireGuard: $WG_IFACE"
wg-quick up "$WG_CONF"
echo "$WG_IFACE" > "$ACTIVE_IFACE_FILE"

nohup python3 /webapp/app.py > /tmp/webapp.log 2>&1 &

trap 'iface=$(cat "$ACTIVE_IFACE_FILE" 2>/dev/null); wg-quick down "${iface:-$WG_IFACE}" 2>/dev/null || true; exit 0' TERM INT

has_egress() {
    curl -sS --max-time "$EGRESS_CHECK_TIMEOUT" -o /dev/null http://1.1.1.1/ 2>/dev/null \
        || curl -sS --max-time "$EGRESS_CHECK_TIMEOUT" -o /dev/null http://www.gstatic.com/generate_204 2>/dev/null
}

UNHEALTHY=0
while true; do
    sleep "$EGRESS_CHECK_INTERVAL"

    if has_egress; then
        UNHEALTHY=0
        continue
    fi

    UNHEALTHY=$((UNHEALTHY + 1))
    echo "No egress through tunnel (count=$UNHEALTHY/$UNHEALTHY_THRESHOLD)"

    if [ "$UNHEALTHY" -ge "$UNHEALTHY_THRESHOLD" ]; then
        IFACE=$(cat "$ACTIVE_IFACE_FILE" 2>/dev/null || echo "$WG_IFACE")
        CONF="/etc/wireguard/${IFACE}.conf"
        echo "Restarting WireGuard: $IFACE"
        wg-quick down "$IFACE" 2>/dev/null || true
        sleep 2
        wg-quick up "$CONF"
        UNHEALTHY=0
    fi
done
