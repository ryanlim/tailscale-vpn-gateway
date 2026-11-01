#!/bin/sh
# VPN kill switch for the gateway container.
#
# Exit-node traffic reaches this container on eth0 and is forwarded out through
# the WireGuard tunnel.  The tunnel's policy-routing rules only exist while a
# WireGuard interface is up; when it is down (rotation, crash, startup) forwarded
# traffic would fall through to the eth0 default route and leave via Docker's NAT
# with the real IP.  This closes that path:
#
#   forwarded eth0 -> eth0 traffic is dropped, unless its destination is private
#   (Docker network / LAN).  eth0 -> tunnel and tunnel -> eth0 are untouched, and
#   so is the container's own traffic (WireGuard handshake, API calls, panel).
#
# Usage: killswitch.sh [add|del|status]
#
# Environment:
#   KILLSWITCH=false              disable (rules are removed on `add`)
#   KILLSWITCH_LAN_IF=eth0        interface facing the Docker network / LAN
#   KILLSWITCH_ALLOW_CIDRS        IPv4 destinations still allowed via eth0
#   KILLSWITCH_ALLOW_CIDRS6       IPv6 destinations still allowed via eth0
#
# Rules go into both the legacy and nft iptables stacks (whichever the kernel
# enforces here); a missing stack or IPv6 support is ignored.

CHAIN=KILLSWITCH
LAN_IF="${KILLSWITCH_LAN_IF:-eth0}"
ALLOW4="${KILLSWITCH_ALLOW_CIDRS:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16}"
ALLOW6="${KILLSWITCH_ALLOW_CIDRS6:-fc00::/7 fe80::/10}"

# Cheap sanity check on user-supplied CIDRs: no shell metacharacters.
for c in $ALLOW4 $ALLOW6; do
    case "$c" in
        *[!0-9a-fA-F:./]*) echo "killswitch: invalid CIDR '$c'" >&2; exit 2 ;;
    esac
done

stacks() {
    # $1 = 4|6 ; prints the iptables binaries that exist for that family
    for suffix in legacy nft; do
        if [ "$1" = 4 ]; then bin="iptables-$suffix"; else bin="ip6tables-$suffix"; fi
        command -v "$bin" >/dev/null 2>&1 && echo "$bin"
    done
}

apply() {  # $1 = binary, $2 = allowed CIDRs
    ipt="$1"; allow="$2"
    $ipt -N "$CHAIN" 2>/dev/null || $ipt -F "$CHAIN" || return 1
    for cidr in $allow; do
        $ipt -A "$CHAIN" -i "$LAN_IF" -o "$LAN_IF" -d "$cidr" -j ACCEPT || return 1
    done
    $ipt -A "$CHAIN" -i "$LAN_IF" -o "$LAN_IF" -j DROP || return 1
    $ipt -C FORWARD -j "$CHAIN" 2>/dev/null || $ipt -I FORWARD 1 -j "$CHAIN"
}

remove() {  # $1 = binary
    ipt="$1"
    while $ipt -D FORWARD -j "$CHAIN" 2>/dev/null; do :; done
    $ipt -F "$CHAIN" 2>/dev/null
    $ipt -X "$CHAIN" 2>/dev/null
    return 0
}

action="${1:-add}"
[ "$KILLSWITCH" = "false" ] && [ "$action" = "add" ] && action=del

case "$action" in
    add)
        ok=0
        for b in $(stacks 4); do
            apply "$b" "$ALLOW4" && ok=1 && echo "killswitch: active ($b, allow: $ALLOW4)"
        done
        for b in $(stacks 6); do
            apply "$b" "$ALLOW6" 2>/dev/null && echo "killswitch: active ($b, allow: $ALLOW6)" || true
        done
        if [ "$ok" -ne 1 ]; then
            echo "killswitch: FAILED to install IPv4 rules" >&2
            exit 1
        fi
        ;;
    del)
        for b in $(stacks 4) $(stacks 6); do remove "$b"; done
        echo "killswitch: disabled"
        ;;
    status)
        for b in $(stacks 4) $(stacks 6); do
            echo "== $b"
            $b -L "$CHAIN" -n -v 2>/dev/null || echo "(no $CHAIN chain)"
        done
        ;;
    *) echo "usage: $0 [add|del|status]" >&2; exit 2 ;;
esac
