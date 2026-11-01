#!/bin/bash
set -x

export PATH=/scripts:$PATH

PRIVATE_KEY_FILE=/etc/wireguard/private.key
TARGET_FILE=/etc/wireguard/.target

if [ ! -s "$PRIVATE_KEY_FILE" ]; then
  if [ -n "$NORDVPN_TOKEN" ]; then
    echo "$PRIVATE_KEY_FILE missing; extracting via NORDVPN_TOKEN."
    if ! /scripts/extract_key.sh > "$PRIVATE_KEY_FILE"; then
      rm -f "$PRIVATE_KEY_FILE"
      echo "ERROR: extract_key.sh failed. Sleeping so 'docker logs' shows this."
      sleep 60
      exit 1
    fi
  else
    echo "ERROR: $PRIVATE_KEY_FILE is missing or empty and NORDVPN_TOKEN is unset."
    echo "Either set NORDVPN_TOKEN in the environment, or extract the key manually:"
    echo "  ./nordvpn-wg/scripts/extract_key.sh > ./nordvpn-wg/wireguard/private.key"
    echo "Sleeping so 'docker logs' shows this; container will keep restarting."
    sleep 60
    exit 1
  fi
fi
chmod 600 "$PRIVATE_KEY_FILE"

RECONNECT_AFTER_HOURS=${RECONNECT_AFTER_HOURS:-1}
RECONNECT_AFTER_SECONDS=$((RECONNECT_AFTER_HOURS * 3600))

# --- Tunnel egress watchdog -------------------------------------------------
# While connected, probe real connectivity through the tunnel instead of
# blindly sleeping until the next rotation. A dead tunnel (bad server, stale
# handshake) is then caught within minutes and triggers an early reconnect to
# a freshly-picked server.
HEALTHCHECK_INTERVAL=${HEALTHCHECK_INTERVAL:-60}
# Consecutive failed probes before forcing a reconnect (interval per cycle, so
# 3 = ~3 minutes of sustained failure). Debounces transient blips.
UNHEALTHY_THRESHOLD=${UNHEALTHY_THRESHOLD:-3}
# Probe passes if ANY URL responds. First is an IP literal (no DNS) so a
# DNS-only fault — which a reconnect can't fix — won't force churn; the second
# also exercises DNS. We omit --fail: any HTTP response proves egress; only
# connect/DNS/timeout failures (curl non-zero exit) count as "no egress".
EGRESS_CHECK_URLS="${EGRESS_CHECK_URLS:-http://1.1.1.1/ http://www.gstatic.com/generate_204}"
EGRESS_CHECK_TIMEOUT="${EGRESS_CHECK_TIMEOUT:-8}"

has_egress() {
  for url in $EGRESS_CHECK_URLS; do
    if curl -sS --max-time "$EGRESS_CHECK_TIMEOUT" -o /dev/null "$url" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

# Kill switch: install BEFORE connecting so forwarded exit-node traffic can never
# leave via eth0 while no tunnel is up (see killswitch.sh).  Fail closed.
# (This used to be preceded by a bare `env`, which printed NORDVPN_TOKEN into
# `docker logs`; it was removed.)
sh /scripts/killswitch.sh add || { echo "ERROR: kill switch could not be installed"; exit 1; }

nohup python3 /webapp/app.py >/tmp/webapp.log 2>&1 &

trap 'nordvpn disconnect; exit 0' TERM INT

while true; do
  # Sticky target persists across restarts via TARGET_FILE; fall back to env.
  if [ -s "$TARGET_FILE" ]; then
    TARGET=$(cat "$TARGET_FILE")
  else
    TARGET=${NORDVPN_TARGET:-}
  fi

  if ! nordvpn connect "$TARGET"; then
    echo "Connect failed; retrying in 30s"
    sleep 30
    continue
  fi

  # Stay connected until the rotation interval elapses or the tunnel stops
  # passing traffic, whichever comes first. If the host's own internet is
  # down, the reconnect below fails at the API-lookup step and we fall into
  # the 30s retry above — so a global outage backs off instead of thrashing
  # through fresh servers that can't help.
  echo "Connected; watching egress (rotate in ${RECONNECT_AFTER_SECONDS}s)"
  ELAPSED=0
  UNHEALTHY_COUNT=0
  while [ "$ELAPSED" -lt "$RECONNECT_AFTER_SECONDS" ]; do
    sleep "$HEALTHCHECK_INTERVAL"
    ELAPSED=$((ELAPSED + HEALTHCHECK_INTERVAL))

    if has_egress; then
      UNHEALTHY_COUNT=0
      continue
    fi

    UNHEALTHY_COUNT=$((UNHEALTHY_COUNT + 1))
    echo "no egress through tunnel (count=$UNHEALTHY_COUNT/$UNHEALTHY_THRESHOLD)"
    if [ "$UNHEALTHY_COUNT" -ge "$UNHEALTHY_THRESHOLD" ]; then
      echo "tunnel not passing traffic; forcing early reconnect"
      break
    fi
  done

  echo "--- $(date +%Y%m%d_%H%M%S) reconnecting ---"
  nordvpn disconnect || true
  sleep 1
done
