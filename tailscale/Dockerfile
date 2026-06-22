FROM tailscale/tailscale:latest

# Pre-install the auxiliary tools the entrypoint relies on (nginx for the
# reverse proxy to the control panel — terminating optional HTTPS, curl
# for the watchdog probes, mtr for diagnostics, node_exporter for
# metrics). Doing this at build time avoids a flaky apk fetch on every
# container start, which previously wedged the proxy when downloads
# stalled through the VPN tunnel.
RUN apk add --no-cache \
    bash \
    python3 \
    openssl \
    mtr \
    curl \
    kmod \
    prometheus-node-exporter \
    nginx \
 && rm -f /etc/nginx/http.d/default.conf

COPY tailscale_up.sh /tailscale_up.sh
COPY gateway_api.py /gateway_api.py
RUN chmod +x /tailscale_up.sh
