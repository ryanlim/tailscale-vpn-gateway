#!/usr/bin/env python3
"""ProtonVPN WireGuard backend — implements the BACKEND_API v1 contract."""
import json
import logging
import os
import random
import re
import socket
import ssl
import subprocess
import threading
import time
from datetime import datetime, timezone
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
INDEX_PATH = WG_DIR / "index.json"

# ProtonVPN local agent — TLS authentication required for paid servers.
# The server jails new WireGuard sessions until the client presents its
# Ed25519 certificate over TLS to 10.2.0.1:65432 inside the tunnel.
# Credentials are written to this directory by the setup script.
LOCAL_AGENT_HOST = "10.2.0.1"
LOCAL_AGENT_PORT = 65432
LOCAL_AGENT_CERT = WG_DIR / "proton_auth" / "client.pem"
LOCAL_AGENT_KEY  = WG_DIR / "proton_auth" / "client.key"

PROTON_API_BASE      = "https://vpn-api.proton.me"
CREDENTIALS_FILE     = WG_DIR / "proton_auth" / "credentials.json"
CERT_REFRESH_AHEAD   = 48 * 3600  # refresh when fewer than 48 h remain
CERT_CHECK_INTERVAL  = 6 * 3600   # poll every 6 hours


class _LocalAgent:
    """Maintain TLS connection to ProtonVPN local agent (10.2.0.1:65432).

    ProtonVPN paid servers block internet forwarding until the client
    presents a valid Ed25519 client certificate over TLS.  This class
    keeps that connection alive in a daemon thread for as long as the
    VPN session is active.
    """

    def __init__(self):
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if not LOCAL_AGENT_CERT.exists() or not LOCAL_AGENT_KEY.exists():
            return
        self.stop()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="local-agent")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None

    def _make_ctx(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(certfile=str(LOCAL_AGENT_CERT), keyfile=str(LOCAL_AGENT_KEY))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        return ctx

    def _run(self) -> None:
        ctx = self._make_ctx()
        while not self._stop.is_set():
            try:
                with socket.create_connection(
                    (LOCAL_AGENT_HOST, LOCAL_AGENT_PORT), timeout=10
                ) as raw:
                    with ctx.wrap_socket(raw, server_hostname=LOCAL_AGENT_HOST) as s:
                        s.settimeout(5)
                        data = s.recv(4096)
                        if len(data) > 4:
                            try:
                                msg = json.loads(data[4:])
                                state = msg.get("status", {}).get("state", "")
                                if state == "connected":
                                    logger.info("Local agent: connected")
                                else:
                                    err = msg.get("error", {})
                                    code = err.get("code", 0)
                                    desc = err.get("description", "unknown")
                                    logger.warning("Local agent rejected (code %s): %s", code, desc)
                                    if code == 86202:
                                        # WireGuard key doesn't match certificate —
                                        # permanent config error, no point retrying.
                                        return
                            except (json.JSONDecodeError, KeyError):
                                pass

                        # Keep connection alive until stopped or server closes it.
                        while not self._stop.is_set():
                            s.settimeout(5)
                            try:
                                chunk = s.recv(4096)
                                if not chunk:
                                    break
                            except TimeoutError:
                                pass
            except OSError as exc:
                if not self._stop.is_set():
                    logger.debug("Local agent connection failed: %s", exc)
                    self._stop.wait(10)


_local_agent = _LocalAgent()


class _CertRefresher:
    """Background thread that refreshes the ProtonVPN client certificate before expiry.

    Reads API credentials from proton_auth/credentials.json (written once by
    extract_credentials.py on the host) and calls POST /vpn/v1/certificate when
    fewer than 48 hours of validity remain.  Handles access-token expiry
    transparently via /auth/refresh.  On success it overwrites client.pem and
    restarts the local agent so the new cert takes effect without a container
    restart or VPN reconnect.
    """

    def __init__(self):
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="cert-refresher")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # --- internal helpers ---

    def _cert_seconds_remaining(self) -> float | None:
        """Seconds until client cert expires, or None if the cert is unreadable."""
        try:
            r = subprocess.run(
                ["openssl", "x509", "-noout", "-enddate", "-in", str(LOCAL_AGENT_CERT)],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode != 0:
                return None
            m = re.search(r"notAfter=(.+)", r.stdout)
            if not m:
                return None
            expiry = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            return (expiry - datetime.now(timezone.utc)).total_seconds()
        except Exception as exc:
            logger.warning("cert-refresher: could not read cert expiry: %s", exc)
            return None

    def _load_creds(self) -> dict | None:
        try:
            return json.loads(CREDENTIALS_FILE.read_text())
        except OSError:
            return None  # not yet created — normal until extract_credentials.py runs
        except Exception as exc:
            logger.warning("cert-refresher: credentials.json unreadable: %s", exc)
            return None

    def _save_creds(self, creds: dict) -> None:
        try:
            CREDENTIALS_FILE.write_text(json.dumps(creds, indent=2))
            CREDENTIALS_FILE.chmod(0o600)
        except Exception as exc:
            logger.warning("cert-refresher: could not write credentials.json: %s", exc)

    def _api_headers(self, creds: dict) -> dict:
        return {
            "x-pm-appversion": creds.get("appversion", "Other"),
            "User-Agent": creds.get("user_agent", "None"),
            "x-pm-uid": creds["uid"],
            "Authorization": f"Bearer {creds['access_token']}",
        }

    def _refresh_token(self, creds: dict) -> dict | None:
        """Exchange the refresh token for a new access token. Returns updated creds or None."""
        try:
            r = requests.post(
                f"{PROTON_API_BASE}/auth/refresh",
                json={
                    "ResponseType": "token",
                    "GrantType": "refresh_token",
                    "RefreshToken": creds["refresh_token"],
                    "RedirectURI": "http://protonmail.ch",
                },
                headers={
                    "x-pm-appversion": creds.get("appversion", "Other"),
                    "User-Agent": creds.get("user_agent", "None"),
                    "x-pm-uid": creds["uid"],
                },
                timeout=15,
            )
            if r.ok:
                data = r.json()
                creds = {**creds, "access_token": data["AccessToken"], "refresh_token": data["RefreshToken"]}
                self._save_creds(creds)
                logger.info("cert-refresher: access token refreshed")
                return creds
            logger.warning("cert-refresher: token refresh HTTP %s — re-run extract_credentials.py", r.status_code)
        except Exception as exc:
            logger.warning("cert-refresher: token refresh error: %s", exc)
        return None

    def _get_pubkey_pem(self) -> str | None:
        """Derive Ed25519 public key PEM from client.key."""
        try:
            r = subprocess.run(
                ["openssl", "pkey", "-in", str(LOCAL_AGENT_KEY), "-pubout"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                return r.stdout.strip()
        except Exception as exc:
            logger.warning("cert-refresher: could not derive public key: %s", exc)
        return None

    def _fetch_cert(self, creds: dict, pubkey_pem: str) -> tuple[str | None, dict]:
        """POST /vpn/v1/certificate. Returns (cert_pem, updated_creds) or (None, creds)."""
        body = {"ClientPublicKey": pubkey_pem, "Duration": "10080 min"}
        for attempt in range(2):
            try:
                r = requests.post(
                    f"{PROTON_API_BASE}/vpn/v1/certificate",
                    json=body,
                    headers=self._api_headers(creds),
                    timeout=15,
                )
                if r.status_code == 401 and attempt == 0:
                    logger.info("cert-refresher: access token expired, refreshing...")
                    new_creds = self._refresh_token(creds)
                    if new_creds is None:
                        return None, creds
                    creds = new_creds
                    continue
                if r.ok:
                    cert_pem = r.json().get("Certificate")
                    if cert_pem:
                        return cert_pem, creds
                    logger.warning("cert-refresher: API response missing 'Certificate' field")
                    return None, creds
                logger.warning("cert-refresher: cert fetch HTTP %s: %s", r.status_code, r.text[:200])
                return None, creds
            except Exception as exc:
                logger.warning("cert-refresher: cert fetch error: %s", exc)
                return None, creds
        return None, creds

    def _do_refresh(self) -> bool:
        """Run one certificate refresh cycle. Returns True on success."""
        creds = self._load_creds()
        if creds is None:
            logger.info("cert-refresher: credentials.json absent — skipping (run extract_credentials.py)")
            return False
        pubkey_pem = self._get_pubkey_pem()
        if pubkey_pem is None:
            return False
        cert_pem, _creds = self._fetch_cert(creds, pubkey_pem)
        if cert_pem is None:
            return False
        LOCAL_AGENT_CERT.write_text(cert_pem)
        LOCAL_AGENT_CERT.chmod(0o600)
        logger.info("cert-refresher: new certificate written to %s", LOCAL_AGENT_CERT)
        _local_agent.start()
        logger.info("cert-refresher: local agent restarted with new certificate")
        return True

    def _run(self) -> None:
        self._stop.wait(30)  # brief startup delay
        while not self._stop.is_set():
            try:
                remaining = self._cert_seconds_remaining()
                if remaining is None:
                    logger.debug("cert-refresher: cert not yet provisioned")
                elif remaining < CERT_REFRESH_AHEAD:
                    logger.info(
                        "cert-refresher: %.0f h remaining — refreshing certificate",
                        remaining / 3600,
                    )
                    if self._do_refresh():
                        logger.info("cert-refresher: certificate refreshed successfully")
                    else:
                        logger.warning("cert-refresher: certificate refresh FAILED")
                else:
                    logger.info(
                        "cert-refresher: %.1f days remaining — no refresh needed",
                        remaining / 86400,
                    )
            except Exception as exc:
                logger.warning("cert-refresher: unexpected error: %s", exc)
            self._stop.wait(CERT_CHECK_INTERVAL)


_cert_refresher = _CertRefresher()

# index.json cache — loaded once at first use.
_index_lock = threading.Lock()
_index_cache: list | None = None


def _load_index() -> list:
    global _index_cache
    with _index_lock:
        if _index_cache is None:
            try:
                _index_cache = json.loads(INDEX_PATH.read_text()).get("servers", [])
                logger.info("Loaded %d servers from index.json", len(_index_cache))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Could not load index.json: %s", exc)
                _index_cache = []
        return _index_cache


def _find_conf(stem: str) -> Path | None:
    """Locate a .conf file by its interface name (stem), checking root then subdirs."""
    p = WG_DIR / f"{stem}.conf"
    if p.exists():
        return p
    hits = list(WG_DIR.rglob(f"{stem}.conf"))
    return hits[0] if hits else None


def _conf_has_ipv6(conf: Path) -> bool:
    """Return True if the config's Interface Address includes an IPv6 CIDR."""
    try:
        for line in conf.read_text().splitlines():
            if line.strip().lower().startswith("address"):
                return ":" in line
    except OSError:
        pass
    return False

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


def _masquerade_update(old_iface: str | None, new_iface: str | None, ipv6: bool = True) -> None:
    """Remove masquerade rule for old_iface and add one for new_iface.

    wg-quick silently skips iptables masquerade in Docker containers because
    net.ipv4.conf.all.src_valid_mark is a read-only sysctl.  Without masquerade,
    forwarded traffic from the Tailscale exit node leaves the container with its
    Docker-bridge source IP, which the ProtonVPN endpoint rejects.  This mirrors
    what entrypoint.sh does at startup, but generalized to any interface switch.

    Pass ipv6=False when the new config has no IPv6 interface address — adding
    ip6tables MASQUERADE without a source address would drop IPv6 traffic.
    """
    # Use iptables-legacy: in this container the kernel's NAT hook is registered
    # by the legacy netfilter stack, not nftables. iptables-nft rules are silently
    # ignored for POSTROUTING SNAT/MASQUERADE (they match 0 packets).
    commands = [["iptables-legacy"]]
    if ipv6:
        commands.append(["ip6tables-legacy"])
    for cmd in commands:
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
                add = subprocess.run(
                    cmd + ["-t", "nat", "-A", "POSTROUTING", "-o", new_iface, "-j", "MASQUERADE"],
                    capture_output=True,
                )
                if add.returncode != 0:
                    logger.warning("MASQUERADE add failed (%s -o %s): %s",
                                   cmd[0], new_iface, add.stderr.decode().strip())


def _active_iface() -> str:
    try:
        return ACTIVE_IFACE_FILE.read_text().strip()
    except OSError:
        return Path(WG_CONF).stem


def _wg_down(iface: str, timeout: float = 15) -> None:
    """Bring down a WireGuard interface, resolving subdirectory config paths.

    wg-quick down requires the .conf file to remove routes.  For configs that
    live under a subdirectory (e.g. US/Dallas/us-tx_425.conf), passing only
    the interface name would cause wg-quick to look in /etc/wireguard/ and fail.
    """
    conf = _find_conf(iface)
    cmd = ["wg-quick", "down", str(conf)] if conf and conf.exists() \
        else ["wg-quick", "down", iface]
    subprocess.run(cmd, capture_output=True, timeout=timeout)


def _wg_show(iface: str | None = None) -> str:
    iface = iface or _active_iface()
    try:
        return subprocess.check_output(
            ["wg", "show", iface], text=True, stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        return ""


def _wait_for_handshake(iface: str, timeout: float = 10.0) -> bool:
    """Poll wg show until a handshake appears or timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _is_connected(_wg_show(iface)):
            return True
        time.sleep(0.5)
    return False


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

    # City-level selection: auto-pick the lowest-load server for COUNTRY/CITY.
    if target.startswith("_city:"):
        parts = target.split(":", 2)
        if len(parts) != 3:
            return jsonify({"error": f"Invalid city code: {target}"}), 400
        _, country, city = parts
        index = _load_index()
        candidates = [
            s for s in index
            if s.get("country", "").upper() == country.upper()
            and (s.get("city") or "") == city
        ]
        if not candidates:
            return jsonify({"error": f"No servers found for {country}/{city}"}), 404
        best = random.choice(candidates)
        target = Path(best["path"]).stem
        logger.info("City random-select %s/%s → %s", country, city, target)

    conf = _find_conf(target)
    if conf is None:
        return jsonify({"error": f"Config not found: {target}.conf"}), 400

    # The WireGuard interface name is always the config basename (stem), regardless
    # of whether target was supplied as a path ("US/Dallas/us-tx_477") or bare name.
    iface = conf.stem

    with _lock:
        current = _active_iface()
        if current == iface:
            return jsonify({"message": f"Already connected to {iface}", "output": ""})

        # Pin management routes BEFORE wg-quick touches the routing table so
        # Tailscale and the Docker bridge stay reachable through the transition.
        _exempt_management_add()

        # Remove masquerade rule for the outgoing interface.
        _masquerade_update(current, None)
        try:
            _wg_down(current)
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
            prev_conf = _find_conf(current)
            if prev_conf and prev_conf.exists():
                try:
                    _exempt_management_add()
                    subprocess.run(
                        ["wg-quick", "up", str(prev_conf)],
                        capture_output=True, timeout=30,
                    )
                    _masquerade_update(None, current, _conf_has_ipv6(prev_conf))
                    ACTIVE_IFACE_FILE.write_text(current)
                finally:
                    # Always remove management rules — leaving them breaks routing
                    # (pref-99 "from eth0-subnet table main" overrides WireGuard).
                    _exempt_management_del()
            return jsonify({"error": f"wg-quick up failed: {exc.stderr}"}), 500

        # Remove management exemption rules now that the new tunnel is up.
        # They must not persist: the pref-99 "from <eth0-subnet> table main" rule
        # overrides wg-quick's pref-32765 rule and sends all outbound traffic
        # through the Docker bridge instead of the WireGuard tunnel.
        _exempt_management_del()

        # Wait for the WireGuard handshake with the new server before returning.
        # wg-quick up exits as soon as the interface is configured; the actual
        # handshake with the peer happens asynchronously and takes 1–3 seconds.
        # Returning before the handshake means the caller sees "Connected" while
        # traffic is still being dropped by the peer.
        if not _wait_for_handshake(iface):
            logger.warning("No WireGuard handshake within 10s for %s", iface)

        # Authenticate with the ProtonVPN local agent (10.2.0.1:65432) so that
        # paid servers release the session from "jailed" (no egress) to "connected".
        _local_agent.start()

        # Re-add masquerade for the new interface. wg-quick silently skips iptables
        # in Docker (src_valid_mark sysctl is read-only), so we do it explicitly.
        # Only add ip6tables rule if the new config actually has an IPv6 address —
        # configs downloaded without --ipv6 have no IPv6 interface address and
        # MASQUERADE would have no valid source.
        _masquerade_update(None, iface, _conf_has_ipv6(conf))
        ACTIVE_IFACE_FILE.write_text(iface)
        return jsonify({"message": f"Connected to {target}", "output": result.stdout})


@app.route("/api/v1/disconnect", methods=["POST"])
def disconnect():
    with _lock:
        iface = _active_iface()
        try:
            conf = _find_conf(iface)
            cmd = ["wg-quick", "down", str(conf)] if conf and conf.exists() \
                else ["wg-quick", "down", iface]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=15)
            _local_agent.stop()
            _masquerade_update(iface, None)
            _exempt_management_del()
            return jsonify({"message": f"Disconnected from {iface}", "output": result.stdout})
        except subprocess.CalledProcessError as exc:
            return jsonify({"error": exc.stderr}), 400


@app.route("/api/v1/countries")
def countries():
    """List countries available in the index.json manifest."""
    index = _load_index()
    seen: set[str] = set()
    for s in index:
        cc = s.get("country", "")
        if cc:
            seen.add(cc)
    return jsonify(sorted(seen))


@app.route("/api/v1/cities")
def cities():
    """Return cities for a country, sorted by minimum server load.

    GET /api/v1/cities?country=US
    Each entry has code=_city:COUNTRY:CITY which connect() resolves to the
    lowest-load server in that city at connect time.
    """
    country = request.args.get("country", "").upper()
    if not country:
        return jsonify([])
    index = _load_index()
    city_map: dict[str, dict] = {}
    for s in index:
        if s.get("country", "").upper() != country:
            continue
        city = s.get("city") or "Unknown"
        load = s.get("load")
        if city not in city_map:
            city_map[city] = {"min_load": None, "count": 0}
        city_map[city]["count"] += 1
        if load is not None:
            prev = city_map[city]["min_load"]
            if prev is None or load < prev:
                city_map[city]["min_load"] = load

    result = []
    for city, data in city_map.items():
        result.append({
            "code": f"_city:{country}:{city}",
            "name": f"{city}  ({data['count']} servers)",
            "city": city,
        })
    result.sort(key=lambda x: x["city"])
    return jsonify(result)



@app.route("/api/v1/servers")
def servers():
    """Return the curated root-level configs (IPv6-capable, no country filter needed)."""
    confs = sorted(WG_DIR.glob("*.conf"))
    return jsonify([
        {"code": c.stem, "name": c.stem, "ipv6": _conf_has_ipv6(c)}
        for c in confs
    ])


@app.route("/api/v1/reload-cert", methods=["POST"])
def reload_cert():
    """Re-read the client certificate from disk and restart the local agent.

    Called by refresh_cert.py after it writes a fresh certificate.  The local
    agent thread is restarted so it picks up the new cert without requiring a
    container restart or a VPN reconnect.
    """
    if not LOCAL_AGENT_CERT.exists() or not LOCAL_AGENT_KEY.exists():
        return jsonify({"error": "cert files not found in proton_auth/"}), 404
    _local_agent.start()
    logger.info("reload-cert: local agent restarted with updated certificate")
    return jsonify({"message": "local agent restarted with updated certificate"})


@app.route("/api/v1/servers/refresh", methods=["POST"])
def servers_refresh():
    return servers()


@app.route("/api/v1/public-ip")
def public_ip():
    refresh = request.args.get("refresh") == "1"
    ipv4, ipv6 = _get_public_ips(refresh=refresh)
    return jsonify({"ipv4": ipv4, "ipv6": ipv6})


if __name__ == "__main__":
    _cert_refresher.start()
    app.run(host="0.0.0.0", port=80, threaded=True)
