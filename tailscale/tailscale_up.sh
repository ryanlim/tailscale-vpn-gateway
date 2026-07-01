#!/bin/sh

set -x

# Run any executable hooks dropped into /scripts (bind-mounted from the
# host's tailscale/scripts/) before bringing the daemon up. Useful for
# host-specific setup like installing certs or extra packages. Files
# missing the executable bit (e.g. README.txt) are skipped.
if [ -d /scripts ]; then
  for f in /scripts/*; do
    [ -f "$f" ] && [ -x "$f" ] && "$f"
  done
fi

# Load legacy ip6tables kernel modules so Tailscale can set up its IPv6
# exit-node netfilter chains (ts-forward / ts-postrouting for ip6tables).
# The host kernel may not have these loaded by default when it uses nftables
# for its own rules. Requires sys_module cap + /lib/modules bind-mount.
modprobe ip6table_filter ip6table_nat 2>/dev/null || true

tailscaled &

# Wait for the daemon's localapi to actually answer before issuing CLI
# commands. A fixed sleep race-loses on slow boots: `tailscale up` then
# runs before the daemon's state machine is ready, silently no-ops, and
# the tunnel never comes up. Poll up to ~60s.
i=0
while [ $i -lt 60 ]; do
  tailscale status >/dev/null 2>&1 && break
  sleep 1
  i=$((i + 1))
done
ps auxwwf

ACTIVE_GW_FILE="/var/lib/tailscale/active_gateway"
ACTIVE_GW_FILE_V6="/var/lib/tailscale/active_gateway_v6"

# Restore saved gateway (falls back to NordVPN if no state saved yet).
SAVED_GW=$(cat "$ACTIVE_GW_FILE" 2>/dev/null || echo "$IP_NORDVPN")
echo "$SAVED_GW" > "$ACTIVE_GW_FILE"
ip route del default 2>/dev/null || true
ip route add default via "$SAVED_GW" dev eth0

# Restore saved IPv6 gateway if one was previously configured.
SAVED_GW_V6=$(cat "$ACTIVE_GW_FILE_V6" 2>/dev/null || echo "")
if [ -n "$SAVED_GW_V6" ]; then
  ip -6 route replace default via "$SAVED_GW_V6" dev eth0 2>/dev/null || true
fi

nohup python3 /gateway_api.py >/tmp/gateway_api.log 2>&1 &

INSTANCE_NAME_=$(echo $INSTANCE_NAME | sed 's/_/-/g')

# Number of consecutive watchdog cycles where VPN is up but egress is broken
# before we kick tailscale. 10s per cycle, so 3 = ~30 seconds. Kept high to
# give the ProtonVPN watchdog time to rotate servers before tailscale acts.
UNHEALTHY_THRESHOLD=${UNHEALTHY_THRESHOLD:-3}

# Egress probe: URLs the watchdog fetches to prove real internet connectivity
# through the VPN tunnel (default route -> nordvpn-wg -> WireGuard). The probe
# passes if ANY URL responds, so a single provider blip won't trip it. The
# first is an IP literal (no DNS) so a DNS-only fault — which kicking tailscale
# can't fix — won't trigger a kick; the second also exercises DNS resolution.
# Timeout is kept well under the 10s loop interval so a real outage doesn't
# let the check itself eat the whole cycle (has_egress tries both URLs in the
# worst case, so keep this at roughly interval/2 or less).
EGRESS_CHECK_URLS="${EGRESS_CHECK_URLS:-http://1.1.1.1/ http://www.gstatic.com/generate_204}"
EGRESS_CHECK_TIMEOUT="${EGRESS_CHECK_TIMEOUT:-4}"

do_tailscale_up() {
  # Always pass --auth-key when TAILSCALE_AUTH_KEY is set: tailscale uses it
  # only when the node needs to (re)authenticate and ignores it otherwise,
  # so it's idempotent. The previous "only if `tailscale status` shows
  # 'Logged out'" check missed real failure modes ("NeedsLogin",
  # "Tailscale is starting", expired node key), leaving the daemon parked
  # waiting for an interactive auth URL.
  AUTH_KEY_ARG=""
  [ -n "$TAILSCALE_AUTH_KEY" ] && AUTH_KEY_ARG="--auth-key $TAILSCALE_AUTH_KEY"

  if [ -n "$TAILSCALE_UP_LOGIN_SERVER" ]; then
    tailscale up --advertise-exit-node --hostname $INSTANCE_NAME_ --login-server $TAILSCALE_UP_LOGIN_SERVER --accept-dns=false $AUTH_KEY_ARG
  else
    tailscale up --advertise-exit-node --hostname $INSTANCE_NAME_ --accept-dns=false $AUTH_KEY_ARG
  fi
}

is_vpn_connected() {
  # Hit the active VPN backend's status API. Reading the state file rather
  # than $IP_NORDVPN means a runtime gateway switch is reflected immediately.
  # Empty/unreachable response counts as "not connected" so we err on the
  # side of NOT kicking tailscale when the backend is down or mid-reconnect.
  local gw response
  gw=$(cat "$ACTIVE_GW_FILE" 2>/dev/null || echo "$IP_NORDVPN")
  response=$(curl -fsS --max-time 5 "http://${gw}/api/v1/status" 2>/dev/null) || return 1
  # Real JSON parsing rather than a key:value regex — a prior version of this
  # matched `"status": *"Connected"` and broke when the backend's JSON
  # serializer changed its key/value spacing. python3 is already a hard
  # dependency (gateway_api.py below), so use it instead of re-deriving a
  # regex every time the wire format shifts.
  echo "$response" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if d.get("status") != "Connected":
    sys.exit(1)
# Defer while the local agent is mid-auth. The WireGuard handshake succeeds
# immediately but the server blocks forwarding until TLS auth completes —
# kicking tailscale here cant help and would mask the real cause.
# "disconnected" = cert absent (free tier) so no auth needed; treat as ready.
if d.get("local_agent") == "connecting":
    sys.exit(1)
sys.exit(0)
'
}


has_egress() {
  # Real connectivity check: can we actually reach the internet through the
  # tunnel? Success = curl got any HTTP response (proves the full path works).
  # We deliberately omit --fail: a 3xx/4xx still proves we reached a server;
  # only connect/DNS/timeout failures (curl non-zero exit) mean "no egress".
  for url in $EGRESS_CHECK_URLS; do
    if curl -sS --max-time "$EGRESS_CHECK_TIMEOUT" -o /dev/null "$url" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

do_tailscale_up

choose_cert_files() {
  # Sets CERT_FILE / KEY_FILE to a coherent pair. If a real cert AND a
  # real key are present under /etc/nginx/cert (bind-mounted from
  # ./tailscale/cert/), use those. Otherwise generate self-signed stubs
  # into /etc/nginx/cert-stub so nginx still has something to serve and
  # HTTPS comes up — the bind-mount is read-only, so we can't write
  # there even when we want to.
  CERT_FILE=""
  for f in /etc/nginx/cert/fullchain.pem /etc/nginx/cert/cert.pem; do
    [ -f "$f" ] && CERT_FILE="$f" && break
  done
  KEY_FILE=""
  for f in /etc/nginx/cert/privkey.pem /etc/nginx/cert/key.pem; do
    [ -f "$f" ] && KEY_FILE="$f" && break
  done
  if [ -n "$CERT_FILE" ] && [ -n "$KEY_FILE" ]; then
    return
  fi

  STUB_DIR=/etc/nginx/cert-stub
  mkdir -p "$STUB_DIR"
  if [ ! -f "$STUB_DIR/fullchain.pem" ] || [ ! -f "$STUB_DIR/privkey.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/CN=ts-tailscale-stub" \
      -keyout "$STUB_DIR/privkey.pem" \
      -out "$STUB_DIR/fullchain.pem"
    chmod 600 "$STUB_DIR/privkey.pem"
  fi
  CERT_FILE="$STUB_DIR/fullchain.pem"
  KEY_FILE="$STUB_DIR/privkey.pem"
}

write_nginx_config() {
  choose_cert_files

  CONF=/etc/nginx/http.d/panel.conf
  cat <<EOF >"$CONF"
server {
    listen 80;
    location / {
        proxy_pass http://${IP_PANEL}:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

server {
    listen 443 ssl;
    http2 on;
    ssl_certificate     ${CERT_FILE};
    ssl_certificate_key ${KEY_FILE};
    location / {
        proxy_pass http://${IP_PANEL}:80;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
}

write_nginx_config
nginx -t && nginx

nohup /usr/bin/node_exporter >/tmp/node_exporter.log 2>&1 &

UNHEALTHY_COUNT=0
TS_UNHEALTHY_COUNT=0
TS_UNHEALTHY_THRESHOLD=${TS_UNHEALTHY_THRESHOLD:-2}
CONTROL_UNHEALTHY_COUNT=0
CONTROL_UNHEALTHY_THRESHOLD=${CONTROL_UNHEALTHY_THRESHOLD:-2}
while true; do
  sleep 10
  date

  pidof tailscaled >/dev/null || tailscaled &

  # Re-assert the default route in case it went missing. Read the state file
  # so a runtime gateway switch (via gateway_api.py) is honoured here too.
  ACTIVE_GW=$(cat "$ACTIVE_GW_FILE" 2>/dev/null || echo "$IP_NORDVPN")
  ip route show default | grep -q "via $ACTIVE_GW" \
    || ip route replace default via "$ACTIVE_GW" dev eth0

  # Re-assert IPv6 default route if one was established via the gateway API.
  if [ -f "$ACTIVE_GW_FILE_V6" ]; then
    ACTIVE_GW_V6=$(cat "$ACTIVE_GW_FILE_V6")
    ip -6 route show default | grep -q "via $ACTIVE_GW_V6" \
      || ip -6 route replace default via "$ACTIVE_GW_V6" dev eth0 2>/dev/null || true
  fi

  # Check BackendState regardless of VPN status. This catches NeedsLogin,
  # Stopped, and Starting — the exact states the user would otherwise have
  # to fix manually with `tailscale up` — without waiting for egress to fail.
  # Require TS_UNHEALTHY_THRESHOLD consecutive bad readings before acting so
  # a single slow/timed-out `tailscale status` call doesn't trigger a reconnect
  # that resets DERP sessions and disrupts connected clients.
  #
  # Everything below is parsed via real JSON (python3, already a hard
  # dependency for gateway_api.py) rather than grepping for specific field
  # text. We've twice been bitten by matching exact wording — first
  # BackendState's key/value spacing, then one specific phrasing of a
  # control-plane warning out of several tailscaled actually emits for the
  # same underlying failure — so an unfamiliar-but-real warning silently
  # passed the watchdog for hours. TS_ONLINE reads Self.Online directly:
  # it's the same structured field peers use to decide whether this node is
  # reachable, so it can't drift out of sync with new/reworded Health text
  # the way a message-matching regex can. TS_ACTIONABLE is a denylist, not
  # an allowlist: it counts every Health entry except the one specific,
  # known-benign "peers advertising routes" advisory, so any *new* warning
  # tailscaled starts emitting is treated as actionable by default instead
  # of silently ignored until someone notices and adds a pattern for it.
  TS_JSON=$(timeout 5 tailscale status --json 2>/dev/null)
  TS_PARSED=$(echo "$TS_JSON" | python3 -c '
import json, sys
BENIGN_HEALTH_SUBSTRINGS = ("--accept-routes",)
try:
    d = json.load(sys.stdin)
except Exception:
    d = {}
state = d.get("BackendState") or "unreachable"
online = bool((d.get("Self") or {}).get("Online"))
health = d.get("Health") or []
actionable = [h for h in health if not any(b in h for b in BENIGN_HEALTH_SUBSTRINGS)]
print(state)
print("true" if online else "false")
print(len(actionable))
')
  TS_STATE=$(echo "$TS_PARSED" | sed -n 1p)
  TS_ONLINE=$(echo "$TS_PARSED" | sed -n 2p)
  TS_ACTIONABLE=$(echo "$TS_PARSED" | sed -n 3p)
  if [ "$TS_STATE" != "Running" ]; then
    TS_UNHEALTHY_COUNT=$((TS_UNHEALTHY_COUNT + 1))
    echo "tailscale BackendState=${TS_STATE:-unreachable} (count=${TS_UNHEALTHY_COUNT}/${TS_UNHEALTHY_THRESHOLD})"
    if [ "$TS_UNHEALTHY_COUNT" -lt "$TS_UNHEALTHY_THRESHOLD" ]; then
      continue
    fi
    echo "tailscale persistently not Running; running tailscale up"
    do_tailscale_up
    TS_UNHEALTHY_COUNT=0
    UNHEALTHY_COUNT=0
    CONTROL_UNHEALTHY_COUNT=0
    sleep 30
    continue
  fi

  TS_UNHEALTHY_COUNT=0

  # BackendState can be "Running" while tailscaled's session to the
  # coordination server is broken (e.g. after a network blip that killed the
  # long-lived control HTTPS request but not the daemon). Peers learn this
  # node's liveness from the coordination server, not from us, so this means
  # other tailnet clients see this node as unreachable even though
  # BackendState and egress both look fine. React if the control server
  # doesn't consider us online, OR if there's any Health warning beyond the
  # one known-benign one (see the parser above) — `tailscale up` is
  # idempotent and re-registers with the control server, same recovery as
  # the BackendState check above.
  if [ "$TS_ONLINE" != "true" ] || [ "${TS_ACTIONABLE:-0}" -gt 0 ]; then
    CONTROL_UNHEALTHY_COUNT=$((CONTROL_UNHEALTHY_COUNT + 1))
    echo "tailscale control-plane unhealthy (online=$TS_ONLINE actionable_health=$TS_ACTIONABLE) (count=${CONTROL_UNHEALTHY_COUNT}/${CONTROL_UNHEALTHY_THRESHOLD})"
    if [ "$CONTROL_UNHEALTHY_COUNT" -ge "$CONTROL_UNHEALTHY_THRESHOLD" ]; then
      echo "tailscale control-plane persistently unhealthy; running tailscale up"
      do_tailscale_up
      CONTROL_UNHEALTHY_COUNT=0
      UNHEALTHY_COUNT=0
      sleep 30
      continue
    fi
  else
    CONTROL_UNHEALTHY_COUNT=0
  fi

  # Tailscale is Running. Only check egress when the VPN backend is also
  # Connected — if the VPN is down or mid-reconnect, egress failure is not
  # something kicking tailscale can fix.
  if ! is_vpn_connected; then
    echo "VPN not reporting Connected; deferring egress check"
    UNHEALTHY_COUNT=0
    continue
  fi

  if has_egress; then
    UNHEALTHY_COUNT=0
    continue
  fi

  UNHEALTHY_COUNT=$((UNHEALTHY_COUNT + 1))
  echo "no egress while VPN+tailscale both report healthy (count=$UNHEALTHY_COUNT/$UNHEALTHY_THRESHOLD)"
  if [ "$UNHEALTHY_COUNT" -ge "$UNHEALTHY_THRESHOLD" ]; then
    # Use `tailscale up` rather than `tailscale down`+`up`: the down step
    # tears out all DERP sessions and iOS clients don't re-establish exit-node
    # routing automatically. `tailscale up` reconfigures the daemon and
    # re-registers with the control server without evicting connected clients.
    echo "kicking tailscale (up only — preserving client sessions)"
    do_tailscale_up
    UNHEALTHY_COUNT=0
    # Cooldown: give tailscale time to re-establish the tunnel and exit-node
    # routing before the next probe, so a slow recovery doesn't re-trip us
    # into an immediate second kick.
    sleep 30
  fi
done
