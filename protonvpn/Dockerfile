FROM ubuntu:24.04

ENV PROTON_VPN_VERSION="1.0.8"

RUN apt update && \
    apt install -y --no-install-recommends wget curl apt-transport-https ca-certificates wireguard iproute2 resolvconf iptables && \
    apt install -y --no-install-recommends mtr iputils-ping traceroute less && \
    apt install -y --no-install-recommends python3-requests python3-flask python3-flask-cors && \
    apt install -y --no-install-recommends vim-nox && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# The Ubuntu 24.04 resolvconf is a systemd-resolved shim that requires D-Bus,
# which is unavailable in this container. Replace it with a minimal script that
# writes DNS directly to /etc/resolv.conf. /usr/local/sbin precedes /usr/sbin
# in PATH so this takes precedence without touching the package-managed binary.
RUN printf '#!/bin/sh\n\
# Minimal resolvconf shim: wg-quick calls -a on up and -d on down.\n\
case "$1" in\n\
    -a) cat > /etc/resolv.conf ;;\n\
    -d) printf "nameserver 1.1.1.1\\nnameserver 8.8.8.8\\n" > /etc/resolv.conf ;;\n\
esac\n' > /usr/local/sbin/resolvconf && \
    chmod +x /usr/local/sbin/resolvconf

COPY backend /webapp
COPY scripts /scripts
RUN chmod +x /scripts/entrypoint.sh

ENTRYPOINT ["/scripts/entrypoint.sh"]
