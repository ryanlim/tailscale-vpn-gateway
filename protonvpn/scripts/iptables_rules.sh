#!/bin/bash

INTERFACE_NORD=nordtun
INTERFACE_LOCAL=eth0

ip -brief addr show $INTERFACE_NORD > /dev/null 2>&1
if [ $? -eq 1 ]; then
  echo "Interface $INTERFACE_NORD is not up. Is NordVPN running?"
  exit 1
fi

IP4_NORD=$(ip -brief addr show $INTERFACE_NORD | awk '{ print $3 }' | cut -f 1 -d /)
NET_LOCAL=$(ip route | grep "dev $INTERFACE_LOCAL proto" | awk '{ print $1}')

if [ "x$1" == "xadd" ]; then
  set -x
  iptables -t nat -I POSTROUTING 1 -o $INTERFACE_NORD -j MASQUERADE
  iptables -I INPUT 1 -i $INTERFACE_LOCAL -j ACCEPT
  iptables -I FORWARD 1 -i $INTERFACE_LOCAL -o $INTERFACE_NORD -j ACCEPT
  iptables -I FORWARD 1 -i $INTERFACE_NORD -o $INTERFACE_LOCAL -j ACCEPT
  set +x
elif [ "x$1" == "xdel" ]; then
  set -x
  iptables -t nat -D POSTROUTING -o $INTERFACE_NORD -j MASQUERADE
  iptables -D INPUT -i $INTERFACE_LOCAL -j ACCEPT
  iptables -D FORWARD -i $INTERFACE_LOCAL -o $INTERFACE_NORD -j ACCEPT
  iptables -D FORWARD -i $INTERFACE_NORD -o $INTERFACE_LOCAL -j ACCEPT
  set +x
else
  echo "$0 [add|del]"
  exit
fi
