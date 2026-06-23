#!/usr/bin/env python3
"""ProtonVPN WireGuard backend — implements the BACKEND_API v1 contract."""
import logging
import os
import re
import subprocess
import threading
import time
from pathlib import Path

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

WG_DIR = Path(os.environ.get("WG_DIR", "/etc/wireguard"))
WG_CONF = os.environ.get("WG_CONF", str(WG_DIR / "free-us-8.conf"))
INSTANCE_NAME = os.environ.get("INSTANCE_NAME", "protonvpn")
ACTIVE_IFACE_FILE = Path("/tmp/active_wg_iface")

# Subnets that must never be routed through the VPN tunnel.
# Tailscale uses the CGNAT range 100.64.0.0/10 for all device addresses.
# When wg-quick adds its catch-all routing rule (pref 32765) we need our
# exemption rules already present at a lower priority number (= higher priority).
_EXEMPT_RANGES = [
    r for r in os.environ.get("VPN_EXEMPT_RANGES", "100.64.0.0/10").split(",")
    if r.strip()
]
_EXEMPT_PRIORITY = 99

_lock = threading.Lock()
_ip_cache: dict = {"v4": None, "v6": None, "ts": 0.0}
_IP_TTL = 15  # seconds


def _eth0_subnet() -> str | None:
    """Return the IPv4 subnet of eth0 (the Docker bridge), e.g. 172.18.0.0/24."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "route", "show", "dev", "eth0", "scope", "link"],
            text=True, stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            parts = line.split()
            if parts and "/" in parts[0]:
                return parts[0]
    except Exception:
        pass
    return None


def _exempt_management_add() -> None:
    """Pin management subnets to the main routing table.

    wg-quick's catch-all rule runs at pref 32765.  By adding our rules at
    pref 99 BEFORE wg-quick up, the kernel checks them first and keeps
    Tailscale (100.64.0.0/10) and the Docker bridge subnet reachable through
    the VPN transition.  Del-before-add keeps the rule set idempotent across
    multiple connect calls.
    """
    ranges = list(_EXEMPT_RANGES)
    eth0 = _eth0_subnet()
    if eth0 and eth0 not in ranges:
        ranges.append(eth0)
    for cidr in ranges:
        for flag in ("to", "from"):
            subprocess.run(
                ["ip", "rule", "del", flag, cidr, "table", "main"],
                capture_output=True,
            )
            subprocess.run(
                ["ip", "rule", "add", "priority", str(_EXEMPT_PRIORITY),
                 flag, cidr, "table", "main"],
                capture_output=True,
            )


def _exempt_management_del() -> None:
    """Remove management routing exemptions (call after wg-quick down)."""
    ranges = list(_EXEMPT_RANGES)
    eth0 = _eth0_subnet()
    if eth0 and eth0 not in ranges:
        ranges.append(eth0)
    for cidr in ranges:
        for flag in ("to", "from"):
            subprocess.run(
                ["ip", "rule", "del", flag, cidr, "table", "main"],
                capture_output=True,
            )


def _masquerade_update(old_iface: str | None, new_iface: str | None) -> None:
    """Remove masquerade rule for old_iface and add one for new_iface.

    wg-quick silently skips iptables masquerade in Docker containers because
    net.ipv4.conf.all.src_valid_mark is a read-only sysctl.  Without masquerade,
    forwarded traffic from the Tailscale exit node leaves the container with its
    Docker-bridge source IP, which the ProtonVPN endpoint rejects.  This mirrors
    what entrypoint.sh does at startup, but generalized to any interface switch.
    """
    for cmd in (["iptables"], ["ip6tables"]):
        if old_iface:
            subprocess.run(
                cmd + ["-t", "nat", "-D", "POSTROUTING", "-o", old_iface, "-j", "MASQUERADE"],
                capture_output=True,
            )
        if new_iface:
            check = subprocess.run(
                cmd + ["-t", "nat", "-C", "POSTROUTING", "-o", new_iface, "-j", "MASQUERADE"],
                capture_output=True,
            )
            if check.returncode != 0:
                subprocess.run(
                    cmd + ["-t", "nat", "-A", "POSTROUTING", "-o", new_iface, "-j", "MASQUERADE"],
                    capture_output=True,
                )


def _active_iface() -> str:
    try:
        return ACTIVE_IFACE_FILE.read_text().strip()
    except OSError:
        return Path(WG_CONF).stem


def _wg_show(iface: str | None = None) -> str:
    iface = iface or _active_iface()
    try:
        return subprocess.check_output(
            ["wg", "show", iface], text=True, stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        return ""


def _handshake_age(raw: str) -> int | None:
    """Return age of the latest handshake in seconds, or None if absent."""
    m = re.search(r"latest handshake:\s+(.+)", raw)
    if not m:
        return None
    hs = m.group(1).strip()
    if "none" in hs.lower():
        return None
    total = 0
    for val, unit in re.findall(r"(\d+)\s+(second|minute|hour|day)", hs):
        v = int(val)
        if "minute" in unit:
            v *= 60
        elif "hour" in unit:
            v *= 3600
        elif "day" in unit:
            v *= 86400
        total += v
    return total


def _is_connected(raw: str) -> bool:
    age = _handshake_age(raw)
    return age is not None and age < 180


def _status_fields(raw: str, iface: str) -> dict:
    fields: dict = {"Technology": "WireGuard", "Interface": iface}
    m = re.search(r"endpoint:\s+(\S+)", raw)
    if m:
        fields["Endpoint"] = m.group(1)
    age = _handshake_age(raw)
    if age is not None:
        fields["Latest handshake"] = f"{age}s ago"
    m = re.search(r"transfer:\s+(.+?)\s+received,\s+(.+?)\s+sent", raw)
    if m:
        fields["Received"] = m.group(1).strip()
        fields["Sent"] = m.group(2).strip()
    return fields


def _fetch_public_ip(family: int) -> dict | None:
    url = "https://ipinfo.io/json" if family == 4 else "https://v6.ipinfo.io/json"
    try:
        r = requests.get(url, timeout=6)
        if r.ok:
            d = r.json()
            return {
                "ip": d.get("ip"),
                "hostname": d.get("hostname"),
                "city": d.get("city"),
                "region": d.get("region"),
                "country_code": d.get("country"),
                "asn": d.get("org"),
            }
    except requests.RequestException:
        pass
    return None


def _get_public_ips(refresh: bool = False) -> tuple:
    now = time.time()
    if refresh or now - _ip_cache["ts"] > _IP_TTL:
        _ip_cache["v4"] = _fetch_public_ip(4)
        _ip_cache["v6"] = _fetch_public_ip(6)
        _ip_cache["ts"] = now
    return _ip_cache["v4"], _ip_cache["v6"]


# --- Routes -------------------------------------------------------------------

@app.route("/api/v1/info")
def info():
    return jsonify({"backend_type": "protonvpn", "instance": INSTANCE_NAME, "version": "1"})


@app.route("/api/v1/status")
def status():
    refresh = request.args.get("refresh") == "1"
    iface = _active_iface()
    raw = _wg_show(iface)
    connected = _is_connected(raw)
    fields = _status_fields(raw, iface) if connected else {"Technology": "WireGuard", "Interface": iface}

    ipv4, ipv6 = _get_public_ips(refresh=refresh)
    if ipv4 and ipv4.get("ip"):
        loc = ", ".join(filter(None, [ipv4.get("city"), ipv4.get("country_code")]))
        fields["Public IPv4"] = f"{ipv4['ip']} ({loc})" if loc else ipv4["ip"]
    if ipv6 and ipv6.get("ip"):
        loc = ", ".join(filter(None, [ipv6.get("city"), ipv6.get("country_code")]))
        fields["Public IPv6"] = f"{ipv6['ip']} ({loc})" if loc else ipv6["ip"]

    return jsonify({
        "status": "Connected" if connected else "Disconnected",
        "server": iface,
        "city_code": iface,
        "city": f"ProtonVPN ({iface})",
        "fields": fields,
        "details": raw,
    })


@app.route("/api/v1/connect", methods=["POST"])
def connect():
    data = request.get_json(silent=True) or {}
    target = (data.get("server") or "").strip()
    if not target:
        return jsonify({"error": "server is required"}), 400

    conf = WG_DIR / f"{target}.conf"
    if not conf.exists():
        return jsonify({"error": f"Config not found: {target}.conf"}), 400

    with _lock:
        current = _active_iface()
        if current == target:
            return jsonify({"message": f"Already connected to {target}", "output": ""})

        # Pin management routes BEFORE wg-quick touches the routing table so
        # Tailscale and the Docker bridge stay reachable through the transition.
        _exempt_management_add()

        # Remove masquerade rule for the outgoing interface.
        _masquerade_update(current, None)
        try:
            subprocess.run(["wg-quick", "down", current], capture_output=True, timeout=15)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

        try:
            result = subprocess.run(
                ["wg-quick", "up", str(conf)],
                check=True, capture_output=True, text=True, timeout=30,
            )
        except subprocess.CalledProcessError as exc:
            # New VPN failed. Restore previous connection so the container
            # isn't left stranded without a working exit path.
            _exempt_management_del()
            prev_conf = WG_DIR / f"{current}.conf"
            if prev_conf.exists():
                try:
                    _exempt_management_add()
                    subprocess.run(
                        ["wg-quick", "up", str(prev_conf)],
                        capture_output=True, timeout=30,
                    )
                    _masquerade_update(None, current)
                    ACTIVE_IFACE_FILE.write_text(current)
                except Exception:
                    _exempt_management_del()
            return jsonify({"error": f"wg-quick up failed: {exc.stderr}"}), 500

        # Re-add masquerade for the new interface. wg-quick silently skips this
        # in Docker (src_valid_mark sysctl is read-only), so we do it explicitly.
        _masquerade_update(None, target)
        ACTIVE_IFACE_FILE.write_text(target)
        return jsonify({"message": f"Connected to {target}", "output": result.stdout})


@app.route("/api/v1/disconnect", methods=["POST"])
def disconnect():
    with _lock:
        iface = _active_iface()
        try:
            result = subprocess.run(
                ["wg-quick", "down", iface],
                check=True, capture_output=True, text=True, timeout=15,
            )
            _masquerade_update(iface, None)
            _exempt_management_del()
            return jsonify({"message": f"Disconnected from {iface}", "output": result.stdout})
        except subprocess.CalledProcessError as exc:
            return jsonify({"error": exc.stderr}), 400


@app.route("/api/v1/servers")
def servers():
    confs = sorted(WG_DIR.glob("*.conf"))
    return jsonify([{"code": c.stem, "name": f"ProtonVPN ({c.stem})"} for c in confs])


@app.route("/api/v1/servers/refresh", methods=["POST"])
def servers_refresh():
    return servers()


@app.route("/api/v1/public-ip")
def public_ip():
    refresh = request.args.get("refresh") == "1"
    ipv4, ipv6 = _get_public_ips(refresh=refresh)
    return jsonify({"ipv4": ipv4, "ipv6": ipv6})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, threaded=True)
