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

_lock = threading.Lock()
_ip_cache: dict = {"v4": None, "v6": None, "ts": 0.0}
_IP_TTL = 15  # seconds


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
        try:
            subprocess.run(["wg-quick", "down", current], capture_output=True, timeout=15)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        try:
            result = subprocess.run(
                ["wg-quick", "up", str(conf)],
                check=True, capture_output=True, text=True, timeout=30,
            )
            ACTIVE_IFACE_FILE.write_text(target)
            return jsonify({"message": f"Connected to {target}", "output": result.stdout})
        except subprocess.CalledProcessError as exc:
            return jsonify({"error": f"wg-quick up failed: {exc.stderr}"}), 500


@app.route("/api/v1/disconnect", methods=["POST"])
def disconnect():
    with _lock:
        iface = _active_iface()
        try:
            result = subprocess.run(
                ["wg-quick", "down", iface],
                check=True, capture_output=True, text=True, timeout=15,
            )
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
