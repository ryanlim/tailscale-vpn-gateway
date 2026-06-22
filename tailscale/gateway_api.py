#!/usr/bin/env python3
"""Tiny HTTP API for switching the tailscale container's default gateway.

POST /switch  {"host": "container-name"}  — resolves host, updates default route, saves state
GET  /active                               — returns the current active gateway IP
"""
import http.server
import json
import os
import socket
import subprocess

GATEWAY_STATE = "/tmp/active_gateway"


def _active_ip():
    try:
        return open(GATEWAY_STATE).read().strip()
    except OSError:
        return ""


def _resolve(hostname):
    return socket.getaddrinfo(hostname, None, socket.AF_INET)[0][4][0]


def _switch(host):
    ip = _resolve(host)
    subprocess.run(
        ["ip", "route", "replace", "default", "via", ip, "dev", "eth0"],
        check=True,
    )
    with open(GATEWAY_STATE, "w") as f:
        f.write(ip)
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
            self._send_json(200, {"ip": _active_ip()})
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
            ip = _switch(host)
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
