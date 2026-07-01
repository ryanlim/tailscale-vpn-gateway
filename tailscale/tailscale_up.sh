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
# before we kick tailscale. 20s per cycle, so 3 = ~60 seconds. Kept high to
# give the ProtonVPN watchdog time to rotate servers before tailscale acts.
UNHEALTHY_THRESHOLD=${UNHEALTHY_THRESHOLD:-3}

# Egress probe: URLs the watchdog fetches to prove real internet connectivity
# through the VPN tunnel (default route -> nordvpn-wg -> WireGuard). The probe
# passes if ANY URL responds, so a single provider blip won't trip it. The
# first is an IP literal (no DNS) so a DNS-only fault — which kicking tailscale
# can't fix — won't trigger a kick; the second also exercises DNS resolution.
EGRESS_CHECK_URLS="${EGRESS_CHECK_URLS:-http://1.1.1.1/ http://www.gstatic.com/generate_204}"
EGRESS_CHECK_TIMEOUT="${EGRESS_CHECK_TIMEOUT:-8}"

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
  echo "$response" | grep -q '"status": *"Connected"' || return 1
  # Defer while ProtonVPN's local agent is mid-auth. The WireGuard handshake
  # succeeds immediately but the server blocks forwarding until the TLS auth
  # completes — kicking tailscale here can't help and would mask the real cause.
  # "disconnected" = cert absent (free tier) so no auth needed; treat as ready.
  echo "$response" | grep -q '"local_agent": *"connecting"' && return 1
  return 0
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
  sleep 20
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
  TS_JSON=$(timeout 10 tailscale status --json 2>/dev/null)
  TS_STATE=$(echo "$TS_JSON" \
    | grep -o '"BackendState": *"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"')
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
  # coordination server is broken (stale netmap, "unable to connect to
  # synchronize", etc. — tailscaled has emitted several differently-worded
  # Health strings for this over time, e.g. after a network blip that killed
  # the long-lived control HTTPS request but not the daemon). Match on the
  # "coordination server" substring common to all of them rather than one
  # exact message, since peers learn this node's liveness from the
  # coordination server, not from us — any of these mean other tailnet
  # clients see this node as unreachable even though BackendState and egress
  # both look fine. `tailscale up` is idempotent and re-registers with the
  # control server, same recovery as the BackendState check above.
  if echo "$TS_JSON" | grep -q "coordination server"; then
    CONTROL_UNHEALTHY_COUNT=$((CONTROL_UNHEALTHY_COUNT + 1))
    echo "tailscale control-plane session unhealthy (count=${CONTROL_UNHEALTHY_COUNT}/${CONTROL_UNHEALTHY_THRESHOLD})"
    if [ "$CONTROL_UNHEALTHY_COUNT" -ge "$CONTROL_UNHEALTHY_THRESHOLD" ]; then
      echo "tailscale control-plane session persistently unhealthy; running tailscale up"
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
