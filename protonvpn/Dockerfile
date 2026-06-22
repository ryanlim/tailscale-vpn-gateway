FROM ubuntu:24.04

ENV PROTON_VPN_VERSION="1.0.8"

RUN apt update && \
    apt install -y --no-install-recommends wget curl apt-transport-https ca-certificates wireguard iproute2 resolvconf iptables && \
    apt install -y --no-install-recommends mtr iputils-ping traceroute less && \
    apt install -y --no-install-recommends python3-requests python3-flask python3-flask-cors && \
    apt install -y --no-install-recommends vim-nox && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

COPY NordVPN-WebInterface /webapp
COPY scripts /scripts
RUN chmod +x /scripts/entrypoint.sh

ENTRYPOINT ["/scripts/entrypoint.sh"]
