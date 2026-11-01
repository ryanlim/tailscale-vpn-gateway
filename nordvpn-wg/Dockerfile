FROM ubuntu:26.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      wireguard-tools \
      iproute2 \
      iptables \
      iputils-ping \
      mtr \
      traceroute \
      less \
      ca-certificates \
      curl \
      python3-requests \
      python3-flask \
      python3-flask-cors && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY scripts/ /scripts/
COPY NordVPN-WebInterface /webapp
RUN chmod +x /scripts/entrypoint.sh /scripts/iptables_rules.sh /scripts/nordvpn /scripts/extract_key.sh /scripts/killswitch.sh && \
    ln -s /scripts/nordvpn /usr/local/bin/nordvpn

ENTRYPOINT ["/scripts/entrypoint.sh"]
