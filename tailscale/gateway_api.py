#!/usr/bin/env python3
"""Tiny HTTP API for switching the tailscale container's default gateway.

POST /switch  {"host": "container-name"}  — resolves host, updates default route, saves state
GET  /active                               — returns the current active gateway IP
"""
import http.server
import json
import logging
import os
import socket
import subprocess

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GATEWAY_STATE = "/var/lib/tailscale/active_gateway"
GATEWAY_STATE_V6 = "/var/lib/tailscale/active_gateway_v6"


def _active_ip():
    try:
        return open(GATEWAY_STATE).read().strip()
    except OSError:
        return ""


def _active_ip_v6():
    try:
        return open(GATEWAY_STATE_V6).read().strip()
    except OSError:
        return ""


def _resolve(hostname, family=socket.AF_INET):
    return socket.getaddrinfo(hostname, None, family)[0][4][0]


def _switch(host, ip=None, ip6=None, ipv6=False):
    # Accept pre-resolved IPs from the caller (control panel has Docker's
    # embedded resolver; the tailscale container's DNS is replaced by Tailscale
    # and cannot resolve Docker container names).
    if not ip:
        ip = _resolve(host, socket.AF_INET)
    subprocess.run(
        ["ip", "route", "replace", "default", "via", ip, "dev", "eth0"],
        check=True,
    )
    with open(GATEWAY_STATE, "w") as f:
        f.write(ip)

    if ipv6:
        if not ip6:
            try:
                ip6 = _resolve(host, socket.AF_INET6)
            except socket.gaierror as exc:
                logger.warning("IPv6 DNS failed for %s: %s", host, exc)
                ipv6 = False

        if ip6:
            try:
                subprocess.run(
                    ["ip", "-6", "route", "replace", "default", "via", ip6, "dev", "eth0"],
                    check=True,
                )
                with open(GATEWAY_STATE_V6, "w") as f:
                    f.write(ip6)
            except subprocess.CalledProcessError as exc:
                logger.warning("IPv6 route setup failed for %s: %s", host, exc)
                ipv6 = False

    if not ipv6:
        subprocess.run(["ip", "-6", "route", "del", "default"], capture_output=True)
        try:
            os.remove(GATEWAY_STATE_V6)
        except OSError:
            pass

    # Flush conntrack so existing connections re-establish through the new
    # route immediately rather than persisting through the old backend.
    subprocess.run(["conntrack", "-F"], capture_output=True)

    return ip


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # quiet

    def _send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/active":
            self._send_json(200, {"ip": _active_ip(), "ip6": _active_ip_v6()})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/switch":
            self._send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
            host = body["host"]
            if not host or "/" in host:
                raise ValueError(f"invalid host: {host!r}")
            ipv6 = bool(body.get("ipv6", False))
            ip = _switch(host, ip=body.get("ip"), ip6=body.get("ip6"), ipv6=ipv6)
            self._send_json(200, {"ok": True, "host": host, "ip": ip})
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
        except socket.gaierror as exc:
            self._send_json(502, {"error": f"DNS resolution failed: {exc}"})
        except subprocess.CalledProcessError as exc:
            self._send_json(500, {"error": f"ip route failed: {exc}"})


if __name__ == "__main__":
    port = int(os.environ.get("GATEWAY_API_PORT", 8080))
    server = http.server.HTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()
