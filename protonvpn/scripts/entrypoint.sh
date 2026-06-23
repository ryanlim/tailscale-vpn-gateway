#!/bin/sh
set -e

WG_CONF=${WG_CONF:-/etc/wireguard/free-us-8.conf}
WG_IFACE=$(basename "$WG_CONF" .conf)
ACTIVE_IFACE_FILE=/tmp/active_wg_iface
EGRESS_CHECK_INTERVAL=${EGRESS_CHECK_INTERVAL:-60}
EGRESS_CHECK_TIMEOUT=${EGRESS_CHECK_TIMEOUT:-8}
UNHEALTHY_THRESHOLD=${UNHEALTHY_THRESHOLD:-3}

# Load legacy ip6tables modules so ip6tables NAT works in-container.
# The host kernel may use nftables and not load these automatically.
# Requires sys_module cap + /lib/modules bind-mount (set in compose).
modprobe ip6table_filter ip6table_nat 2>/dev/null || true

# Tear down any stale interface from a previous run.
wg-quick down "$WG_IFACE" 2>/dev/null || true

echo "Bringing up WireGuard: $WG_IFACE"
wg-quick up "$WG_CONF"
echo "$WG_IFACE" > "$ACTIVE_IFACE_FILE"

# wg-quick cannot set net.ipv4.conf.all.src_valid_mark in a Docker container
# (read-only sysctl), so its iptables/ip6tables masquerade rules are silently
# skipped.  Add them explicitly so forwarded traffic (e.g. from the Tailscale
# exit node) is masqueraded to the WireGuard address before entering the tunnel.
iptables-legacy  -t nat -C POSTROUTING -o "$WG_IFACE" -j MASQUERADE 2>/dev/null \
    || iptables-legacy  -t nat -A POSTROUTING -o "$WG_IFACE" -j MASQUERADE
ip6tables-legacy -t nat -C POSTROUTING -o "$WG_IFACE" -j MASQUERADE 2>/dev/null \
    || ip6tables-legacy -t nat -A POSTROUTING -o "$WG_IFACE" -j MASQUERADE || true

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
        CONF=$(find /etc/wireguard -name "${IFACE}.conf" 2>/dev/null | head -1)
        CONF="${CONF:-/etc/wireguard/${IFACE}.conf}"
        echo "Restarting WireGuard: $IFACE"
        iptables-legacy  -t nat -D POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true
        ip6tables-legacy -t nat -D POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true
        wg-quick down "${CONF:-$IFACE}" 2>/dev/null || true
        sleep 2
        wg-quick up "$CONF"
        iptables-legacy  -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null \
            || iptables-legacy  -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE
        ip6tables-legacy -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null \
            || ip6tables-legacy -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE || true
        UNHEALTHY=0
    fi
done
