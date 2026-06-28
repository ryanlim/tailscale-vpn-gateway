#!/usr/bin/env python3
"""ProtonVPN WireGuard backend — implements the BACKEND_API v1 contract."""
import base64
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

import proton_srp

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

_CC_TO_NAME: dict[str, str] = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan",
    "AL": "Albania", "AM": "Armenia", "AO": "Angola", "AR": "Argentina",
    "AT": "Austria", "AU": "Australia", "AZ": "Azerbaijan", "BA": "Bosnia",
    "BD": "Bangladesh", "BE": "Belgium", "BG": "Bulgaria", "BH": "Bahrain",
    "BN": "Brunei", "BO": "Bolivia", "BR": "Brazil", "BT": "Bhutan",
    "BY": "Belarus", "CA": "Canada", "CD": "DR Congo", "CH": "Switzerland",
    "CI": "Ivory Coast", "CL": "Chile", "CM": "Cameroon", "CO": "Colombia",
    "CR": "Costa Rica", "CU": "Cuba", "CY": "Cyprus", "CZ": "Czech Republic",
    "DE": "Germany", "DK": "Denmark", "DO": "Dominican Republic", "DZ": "Algeria",
    "EC": "Ecuador", "EE": "Estonia", "EG": "Egypt", "ER": "Eritrea",
    "ES": "Spain", "ET": "Ethiopia", "FI": "Finland", "FR": "France",
    "GA": "Gabon", "GE": "Georgia", "GH": "Ghana", "GL": "Greenland",
    "GN": "Guinea", "GR": "Greece", "GT": "Guatemala", "HK": "Hong Kong",
    "HN": "Honduras", "HR": "Croatia", "HT": "Haiti", "HU": "Hungary",
    "ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IN": "India",
    "IQ": "Iraq", "IS": "Iceland", "IT": "Italy", "JM": "Jamaica",
    "JO": "Jordan", "JP": "Japan", "KE": "Kenya", "KG": "Kyrgyzstan",
    "KH": "Cambodia", "KM": "Comoros", "KR": "South Korea", "KW": "Kuwait",
    "KZ": "Kazakhstan", "LA": "Laos", "LB": "Lebanon", "LI": "Liechtenstein",
    "LK": "Sri Lanka", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia",
    "LY": "Libya", "MA": "Morocco", "MC": "Monaco", "MD": "Moldova",
    "ME": "Montenegro", "MK": "North Macedonia", "MM": "Myanmar", "MN": "Mongolia",
    "MO": "Macau", "MR": "Mauritania", "MT": "Malta", "MU": "Mauritius",
    "MX": "Mexico", "MY": "Malaysia", "MZ": "Mozambique", "NG": "Nigeria",
    "NI": "Nicaragua", "NL": "Netherlands", "NO": "Norway", "NP": "Nepal",
    "NZ": "New Zealand", "OM": "Oman", "PA": "Panama", "PE": "Peru",
    "PG": "Papua New Guinea", "PH": "Philippines", "PK": "Pakistan",
    "PL": "Poland", "PR": "Puerto Rico", "PS": "Palestine", "PT": "Portugal",
    "PY": "Paraguay", "QA": "Qatar", "RO": "Romania", "RS": "Serbia",
    "RU": "Russia", "RW": "Rwanda", "SA": "Saudi Arabia", "SD": "Sudan",
    "SE": "Sweden", "SG": "Singapore", "SI": "Slovenia", "SK": "Slovakia",
    "SN": "Senegal", "SO": "Somalia", "SS": "South Sudan", "SV": "El Salvador",
    "SY": "Syria", "TD": "Chad", "TG": "Togo", "TH": "Thailand",
    "TJ": "Tajikistan", "TM": "Turkmenistan", "TN": "Tunisia", "TR": "Turkey",
    "TW": "Taiwan", "TZ": "Tanzania", "UA": "Ukraine", "UG": "Uganda",
    "UK": "United Kingdom", "US": "United States", "UY": "Uruguay",
    "UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam", "XK": "Kosovo",
    "YE": "Yemen", "ZA": "South Africa", "ZW": "Zimbabwe",
}

PROTON_API_BASE      = "https://vpn-api.proton.me"
CREDENTIALS_FILE     = WG_DIR / "proton_auth" / "credentials.json"
CERT_REFRESH_AHEAD   = 48 * 3600  # refresh when fewer than 48 h remain
CERT_CHECK_INTERVAL  = 6 * 3600   # poll every 6 hours

# App headers sent during login (match what extract_credentials.py produces)
PROTON_APP_VERSION = "linux-vpn-cli@5.2.5+x86-64"
PROTON_USER_AGENT  = "ProtonVPN/5.2.5 (Linux; ubuntu/24.04)"

# Auth API base — separate from the VPN API base used for cert operations.
# download_wg_configs.py authenticates here successfully; vpn-api.proton.me
# is only used for post-auth operations (cert refresh, certificate fetch).
PROTON_AUTH_BASE = "https://api.protonvpn.ch"

# In-memory store for partial 2FA sessions {token: {uid, access_token, refresh_token, expires}}
_pending_2fa: dict[str, dict] = {}
_PENDING_2FA_TTL = 300  # 5 minutes


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
        self._raw: socket.socket | None = None  # closed by stop() to interrupt recv

    def start(self) -> None:
        if not LOCAL_AGENT_CERT.exists() or not LOCAL_AGENT_KEY.exists():
            return
        self.stop()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="local-agent")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        raw = self._raw
        if raw is not None:
            try:
                raw.close()  # interrupts any blocking recv() on the TLS wrapper
            except OSError:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
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
                    self._raw = raw
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
                                        return
                            except (json.JSONDecodeError, KeyError):
                                pass

                        s.settimeout(1)
                        while not self._stop.is_set():
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
            finally:
                self._raw = None


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

    def _fetch_cert(self, creds: dict, pubkey_pem: str) -> tuple[str | None, dict, bool]:
        """POST /vpn/v1/certificate. Returns (cert_pem, updated_creds, False) or (None, creds, False).

        Handles one automatic retry:
          attempt 0 → 401: refresh the access token and retry

        No DevicePublicKey is sent.  The local-agent gateway validates authentication
        mathematically: it derives the X25519 key from the presented Ed25519 cert key
        and checks that SHA512(X25519) == SHA512(WireGuard session Curve25519 key).
        This works as long as the WireGuard private key is the X25519 key derived from
        the Ed25519 private key via crypto_sign_ed25519_sk_to_curve25519 (the key in
        client.key).  Sending a random DevicePublicKey causes 409/2500 conflicts.
        """
        body: dict = {"ClientPublicKey": pubkey_pem, "Duration": "10080 min"}
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
                        return None, creds, False
                    creds = new_creds
                    continue
                if r.status_code == 409:
                    try:
                        err_code = r.json().get("Code", 0)
                    except Exception:
                        err_code = 0
                    if err_code == 2500:
                        logger.error(
                            "cert-refresher: 409/2500 fingerprint conflict — "
                            "re-download the WireGuard config from account.proton.me "
                            "to restore the device→cert binding"
                        )
                    else:
                        logger.warning("cert-refresher: cert fetch HTTP 409: %s", r.text[:200])
                    return None, creds, False
                if r.ok:
                    cert_pem = r.json().get("Certificate")
                    if cert_pem:
                        return cert_pem, creds, False
                    logger.warning("cert-refresher: API response missing 'Certificate' field")
                    return None, creds, False
                logger.warning("cert-refresher: cert fetch HTTP %s: %s", r.status_code, r.text[:200])
                return None, creds, False
            except Exception as exc:
                logger.warning("cert-refresher: cert fetch error: %s", exc)
                return None, creds, False
        return None, creds, False

    def _reconnect_tunnel(self) -> None:
        """Reconnect the active WireGuard tunnel (e.g. after changing the WireGuard key)."""
        try:
            iface = _active_iface()
            if not iface:
                return
            conf = _find_conf(iface)
            if conf is None or not conf.exists():
                return
            logger.info("cert-refresher: reconnecting tunnel %s", iface)
            _wg_down(iface)
            time.sleep(1)
            subprocess.run(
                ["wg-quick", "up", str(conf)],
                capture_output=True, timeout=30,
            )
            # wg-quick skips iptables MASQUERADE in containers (read-only sysctl);
            # re-add it explicitly so forwarded traffic is NATted correctly.
            _masquerade_update(None, iface, _conf_has_ipv6(conf))
            logger.info("cert-refresher: tunnel %s reconnected", iface)
        except Exception as exc:
            logger.warning("cert-refresher: tunnel reconnect failed: %s", exc)

    def _do_refresh(self) -> bool:
        """Run one certificate refresh cycle. Returns True on success."""
        creds = self._load_creds()
        if creds is None:
            logger.info("cert-refresher: credentials.json absent — skipping (run extract_credentials.py)")
            return False
        pubkey_pem = self._get_pubkey_pem()
        if pubkey_pem is None:
            return False
        cert_pem, _creds, _ = self._fetch_cert(creds, pubkey_pem)
        if cert_pem is None:
            return False
        LOCAL_AGENT_CERT.write_text(cert_pem)
        LOCAL_AGENT_CERT.chmod(0o600)
        logger.info("cert-refresher: new certificate written to %s", LOCAL_AGENT_CERT)
        _local_agent.stop()
        _local_agent.start()
        logger.info("cert-refresher: local agent restarted with new certificate")
        return True

    def trigger(self) -> None:
        """Run one certificate refresh immediately in a background thread."""
        threading.Thread(target=self._do_refresh, daemon=True, name="triggered-cert-refresh").start()

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
_iface_city_map: dict | None = None  # stem → "_city:CC:City"


def _load_index() -> list:
    global _index_cache, _iface_city_map
    with _index_lock:
        if _index_cache is None:
            try:
                _index_cache = json.loads(INDEX_PATH.read_text()).get("servers", [])
                _iface_city_map = {
                    Path(s["path"]).stem: f"_city:{s['country']}:{s['city']}"
                    for s in _index_cache
                    if s.get("path") and s.get("country") and s.get("city")
                }
                logger.info("Loaded %d servers from index.json", len(_index_cache))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Could not load index.json: %s", exc)
                _index_cache = []
                _iface_city_map = {}
        return _index_cache


def _iface_to_city_code(iface: str) -> str | None:
    """Return the _city:CC:City code for a WireGuard interface stem, or None."""
    _load_index()
    return (_iface_city_map or {}).get(iface)


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
_ip_refresh_event = threading.Event()  # set to trigger an immediate background refresh

# Timestamp (time.time()) when the current WireGuard tunnel came up.
# Initialised from ACTIVE_IFACE_FILE mtime so container restarts don't
# reset the displayed uptime; updated by connect(), cleared by disconnect().
def _load_connect_time() -> float:
    try:
        if ACTIVE_IFACE_FILE.read_text().strip():
            return ACTIVE_IFACE_FILE.stat().st_mtime
    except OSError:
        pass
    return 0.0

_connect_time: float = _load_connect_time()


def _uptime_str(since: float) -> str:
    secs = max(0, int(time.time() - since))
    d, secs = divmod(secs, 86400)
    h, secs = divmod(secs, 3600)
    m, s   = divmod(secs, 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    if not parts or s:
        parts.append(f"{s}s")
    return " ".join(parts)


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
    if not iface:
        return
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
    url = "https://ip.limau.net/?format=json" if family == 4 else "https://ip6.limau.net/?format=json"
    try:
        r = requests.get(url, timeout=6)
        if r.ok:
            candidates = r.json().get("ip_candidates", [])
            if not candidates:
                return None
            c = candidates[0]
            geo = c.get("geoip_data") or {}
            asn = c.get("ip_asn") or []
            return {
                "ip": c.get("ip"),
                "hostname": c.get("hostname"),
                "city": geo.get("city"),
                "region": geo.get("region"),
                "country_code": geo.get("country_code"),
                "asn": " ".join(asn) if asn else None,
            }
    except requests.RequestException:
        pass
    return None


def _refresh_ips_now() -> None:
    """Fetch IPv4 and IPv6 public IPs concurrently and update the cache."""
    results: list = [None, None]

    def _do(idx: int, family: int) -> None:
        results[idx] = _fetch_public_ip(family)

    t4 = threading.Thread(target=_do, args=(0, 4), daemon=True)
    t6 = threading.Thread(target=_do, args=(1, 6), daemon=True)
    t4.start()
    t6.start()
    t4.join(timeout=8)
    t6.join(timeout=8)
    if results[0] is not None:
        _ip_cache["v4"] = results[0]
    if results[1] is not None:
        _ip_cache["v6"] = results[1]
    # Only advance the timestamp when at least one lookup succeeded — if both
    # fail (tunnel not yet established) keep ts stale so the poller retries
    # on the next wakeup rather than resetting the 60 s window.
    if results[0] is not None or results[1] is not None:
        _ip_cache["ts"] = time.time()


class _IpPoller:
    """Background thread that keeps the public-IP cache fresh.

    Runs every 60 seconds, or immediately when _ip_refresh_event is set.
    The status endpoint reads from the cache without blocking.
    """
    _INTERVAL = 60  # seconds between automatic refreshes

    def start(self) -> None:
        t = threading.Thread(target=self._run, daemon=True, name="ip-poller")
        t.start()

    def _run(self) -> None:
        while True:
            _ip_refresh_event.wait(timeout=self._INTERVAL)
            _ip_refresh_event.clear()
            try:
                _refresh_ips_now()
            except Exception:
                pass


_ip_poller = _IpPoller()


def _get_public_ips(refresh: bool = False) -> tuple:
    """Return cached public IPs. If refresh=True, schedule an immediate background fetch."""
    if refresh:
        _ip_refresh_event.set()
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

    if connected and _connect_time > 0:
        fields["Uptime"] = _uptime_str(_connect_time)

    ipv4, ipv6 = _get_public_ips(refresh=refresh)
    if ipv4 and ipv4.get("ip"):
        loc = ", ".join(filter(None, [ipv4.get("city"), ipv4.get("country_code")]))
        fields["Public IPv4"] = f"{ipv4['ip']} ({loc})" if loc else ipv4["ip"]
    if ipv6 and ipv6.get("ip"):
        loc = ", ".join(filter(None, [ipv6.get("city"), ipv6.get("country_code")]))
        fields["Public IPv6"] = f"{ipv6['ip']} ({loc})" if loc else ipv6["ip"]

    city_code = _iface_to_city_code(iface) or iface
    return jsonify({
        "status": "Connected" if connected else "Disconnected",
        "server": iface,
        "city_code": city_code,
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
        # Prefer IPv6-capable servers: the WireGuard tunnel address (2a07:b944::2:2/128)
        # only works if the server has the ipv6 feature; non-IPv6 servers drop IPv6 packets.
        ipv6_candidates = [s for s in candidates if "ipv6" in s.get("features", [])]
        pool = ipv6_candidates if ipv6_candidates else candidates
        best = random.choice(pool)
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
        if current and current == iface and _wg_show(iface):
            return jsonify({"message": f"Already connected to {iface}", "output": ""})

        # Clear stale IP cache so the status endpoint shows no IPs rather than
        # the previous server's location while the new tunnel is establishing.
        _ip_cache["v4"] = None
        _ip_cache["v6"] = None

        _exempt_management_add()
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
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
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
                    _exempt_management_del()
            err = getattr(exc, 'stderr', None) or 'wg-quick timed out'
            return jsonify({"error": f"wg-quick up failed: {err}"}), 500

        _exempt_management_del()

        # Apply masquerade and record the active iface immediately so the status
        # endpoint reflects the new server without waiting for the handshake.
        global _connect_time
        _connect_time = time.time()
        _masquerade_update(None, iface, _conf_has_ipv6(conf))
        ACTIVE_IFACE_FILE.write_text(iface)

        # Wait for the WireGuard handshake and start the local agent in the
        # background so the HTTP response returns as soon as wg-quick up exits.
        # Distant servers (e.g. Asia from the US) can take several seconds to
        # complete the handshake; blocking here made the control panel appear hung.
        _iface_snapshot = iface
        def _post_up() -> None:
            if not _wait_for_handshake(_iface_snapshot, timeout=30.0):
                logger.warning("WireGuard handshake with %s did not complete within 30s", _iface_snapshot)
            _local_agent.start()
            # Refresh public IPs now that the tunnel is established, so the
            # status shows the new server's location rather than stale data.
            _ip_refresh_event.set()
        threading.Thread(target=_post_up, daemon=True, name=f"post-up-{iface}").start()

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
            # Clear the active interface record so a subsequent connect() that
            # randomly picks the same interface name does not short-circuit with
            # "Already connected" while the tunnel is actually down.
            global _connect_time
            _connect_time = 0.0
            ACTIVE_IFACE_FILE.write_text("")
            return jsonify({"message": f"Disconnected from {iface}", "output": result.stdout})
        except subprocess.CalledProcessError as exc:
            return jsonify({"error": exc.stderr}), 400


@app.route("/api/v1/countries")
def countries():
    """Return empty list — server list is presented as a flat Country - City dropdown."""
    return jsonify([])


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
    """Return a flat Country - City list from the index, sorted alphabetically."""
    index = _load_index()
    seen: set[tuple] = set()
    result = []
    for s in index:
        cc = s.get("country", "")
        city = s.get("city", "")
        if not cc or not city:
            continue
        key = (cc, city)
        if key in seen:
            continue
        seen.add(key)
        country_name = _CC_TO_NAME.get(cc, cc)
        result.append({
            "code": f"_city:{cc}:{city}",
            "name": f"{country_name} - {city}",
        })
    result.sort(key=lambda x: x["name"])
    return jsonify(result)


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


@app.route("/api/v1/proton/refresh-cert", methods=["POST"])
def proton_refresh_cert():
    """Re-register the client certificate with ProtonVPN and restart the local agent.

    Fetches a new cert from /vpn/v1/certificate (including DevicePublicKey to update
    the gateway's cert-fingerprint mapping), then reconnects the WireGuard tunnel so
    the gateway creates a fresh session with the updated mapping, and finally restarts
    the local agent.  Use this to fix local-agent 86202 rejections after a key
    regeneration or any time the cert and the gateway mapping are out of sync.

    Body (optional): {"reconnect": true|false}  — default true.
    Requires credentials.json to be present (log in via /proton/login first).
    """
    if _cert_refresher._load_creds() is None:
        return jsonify({"error": "credentials.json missing — log in first"}), 400
    data = request.get_json(silent=True) or {}
    do_reconnect = data.get("reconnect", True)

    def _run() -> None:
        ok = _cert_refresher._do_refresh()
        if ok and do_reconnect:
            _cert_refresher._reconnect_tunnel()
            _local_agent.stop()
            _local_agent.start()
            logger.info("refresh-cert: tunnel reconnected and local agent restarted")

    threading.Thread(target=_run, daemon=True, name="force-refresh-cert").start()
    return jsonify({"message": "Certificate refresh + reconnect triggered — check logs"})


_REFRESH_SCRIPT = Path("/scripts/download_wg_configs.py")
_refresh_lock   = threading.Lock()
_refresh_status: dict = {"state": "idle", "message": "", "started": 0.0}


def _extract_private_key() -> str | None:
    """Return the WireGuard private key from any .conf file in WG_DIR."""
    for conf in WG_DIR.rglob("*.conf"):
        try:
            m = re.search(r"^PrivateKey\s*=\s*(\S+)", conf.read_text(), re.MULTILINE)
            if m:
                return m.group(1)
        except OSError:
            continue
    return None


def _run_servers_refresh() -> None:
    global _refresh_status, _index_cache, _iface_city_map
    with _refresh_lock:
        _refresh_status = {"state": "running", "message": "Starting download…", "started": time.time()}

    try:
        creds = _cert_refresher._load_creds()
        if creds is None:
            with _refresh_lock:
                _refresh_status = {"state": "error",
                                   "message": "credentials.json missing — log in first",
                                   "started": _refresh_status["started"]}
            return

        privkey = _extract_private_key()
        if privkey is None:
            with _refresh_lock:
                _refresh_status = {"state": "error",
                                   "message": "No WireGuard private key found in existing configs",
                                   "started": _refresh_status["started"]}
            return

        cmd = [
            "python3", str(_REFRESH_SCRIPT),
            "--uid",          creds["uid"],
            "--access-token", creds["access_token"],
            "--private-key",  privkey,
            "--output-dir",   str(WG_DIR),
        ]
        logger.info("servers-refresh: running %s", " ".join(cmd[:4] + ["..."]))

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
        )

        if result.returncode != 0:
            msg = (result.stderr or result.stdout or "unknown error").strip()[-300:]
            logger.warning("servers-refresh: script failed: %s", msg)
            with _refresh_lock:
                _refresh_status = {"state": "error", "message": msg,
                                   "started": _refresh_status["started"]}
            return

        # Reload the in-memory index so the next /servers request picks up new data
        with _index_lock:
            _index_cache    = None
            _iface_city_map = None
        _load_index()

        lines  = [l for l in result.stdout.splitlines() if l.strip()]
        summary = lines[-1] if lines else "Done"
        logger.info("servers-refresh: complete — %s", summary)
        with _refresh_lock:
            _refresh_status = {"state": "done", "message": summary,
                               "started": _refresh_status["started"]}

    except subprocess.TimeoutExpired:
        logger.warning("servers-refresh: timed out after 300 s")
        with _refresh_lock:
            _refresh_status = {"state": "error", "message": "Timed out after 5 minutes",
                               "started": _refresh_status["started"]}
    except Exception as exc:
        logger.exception("servers-refresh: unexpected error")
        with _refresh_lock:
            _refresh_status = {"state": "error", "message": str(exc),
                               "started": _refresh_status["started"]}


@app.route("/api/v1/servers/refresh", methods=["POST"])
def servers_refresh():
    """Trigger a background re-download of all WireGuard configs from Proton."""
    with _refresh_lock:
        if _refresh_status["state"] == "running":
            return jsonify({"state": "running", "message": "Already in progress"}), 409
    threading.Thread(target=_run_servers_refresh, daemon=True, name="servers-refresh").start()
    return jsonify({"state": "running", "message": "Download started"})


@app.route("/api/v1/servers/refresh/status", methods=["GET"])
def servers_refresh_status():
    with _refresh_lock:
        return jsonify(dict(_refresh_status))


@app.route("/api/v1/public-ip")
def public_ip():
    refresh = request.args.get("refresh") == "1"
    ipv4, ipv6 = _get_public_ips(refresh=refresh)
    return jsonify({"ipv4": ipv4, "ipv6": ipv6})


# --- Credential management ----------------------------------------------------

@app.route("/api/v1/proton/credential-status")
def credential_status():
    """Report the health of credentials.json and client.pem."""
    creds = _cert_refresher._load_creds()
    remaining = _cert_refresher._cert_seconds_remaining()

    if creds is None:
        return jsonify({"status": "warning", "message": "credentials.json missing — log in to enable certificate refresh"})

    if remaining is None:
        return jsonify({"status": "warning", "message": "Client certificate not yet provisioned — refresh will run within 6 h"})

    if remaining <= 0:
        return jsonify({"status": "error", "message": "Client certificate has expired — log in again"})

    if remaining < CERT_REFRESH_AHEAD:
        h = int(remaining / 3600)
        return jsonify({"status": "warning", "message": f"Certificate expiring in {h} h — refresh imminent"})

    days = remaining / 86400
    return jsonify({"status": "ok", "message": f"Certificate valid for {days:.1f} days"})


def _b64d(s: str) -> bytes:
    """Decode a base-64 string that may be missing padding."""
    pad = (4 - len(s) % 4) % 4
    return base64.b64decode(s + "=" * pad)


def _login_headers(uid: str | None = None, token: str | None = None) -> dict:
    h = {
        "x-pm-appversion": PROTON_APP_VERSION,
        "x-pm-apiversion": "3",
        "User-Agent":      PROTON_USER_AGENT,
        "Accept":          "application/json",
        "Content-Type":    "application/json",
    }
    if uid:
        h["x-pm-uid"] = uid
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


@app.route("/api/v1/proton/login", methods=["POST"])
def proton_login():
    """Authenticate with ProtonVPN via SRP and write credentials.json.

    Body: {"username": "...", "password": "..."}

    If the account has 2FA enabled, returns {"needs_2fa": true, "session_token": "..."}
    and expects a follow-up POST to /api/v1/proton/login/2fa.
    """
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    # Use a single session so the Session-Id cookie from auth/info is
    # automatically forwarded to the auth proof request — Proton requires it.
    session = requests.Session()
    session.headers.update(_login_headers())

    # Step 1: get SRP challenge
    try:
        r1 = session.post(
            f"{PROTON_AUTH_BASE}/auth/info",
            json={"Username": username},
            timeout=15,
        )
    except requests.RequestException as exc:
        return jsonify({"error": f"Network error: {exc}"}), 502

    if not r1.ok:
        logger.error("proton-login: /auth/info HTTP %s: %s", r1.status_code, r1.text[:300])
        return jsonify({"error": f"Auth info request failed (HTTP {r1.status_code})"}), 502

    info = r1.json()
    version = info.get("Version", 4)
    # Use the server's canonical username for SRP (may differ from what was entered).
    srp_username = info.get("Username") or username
    logger.info("proton-login: SRP version=%s SRPSession=%s entered=%r srp_username=%r",
                version, info.get("SRPSession", "")[:8], username, srp_username)
    if version < 3:
        return jsonify({"error": f"Unsupported SRP version {version}"}), 400

    try:
        modulus_bytes    = proton_srp.extract_pgp_content(info["Modulus"])
        salt_bytes       = _b64d(info["Salt"])
        server_eph_bytes = _b64d(info["ServerEphemeral"])
    except (KeyError, Exception) as exc:
        return jsonify({"error": f"Could not parse server challenge: {exc}"}), 502

    logger.info("proton-login: modulus=%d bytes, salt=%d bytes server_eph=%d bytes",
                len(modulus_bytes), len(salt_bytes), len(server_eph_bytes))

    # Step 2: compute SRP proof using canonical username from server
    try:
        M1, A = proton_srp.compute_proof(srp_username, password, salt_bytes, modulus_bytes, server_eph_bytes)
    except Exception as exc:
        logger.exception("SRP computation failed")
        return jsonify({"error": f"SRP error: {exc}"}), 500

    logger.info("proton-login: computed M1=%s A=%s", M1.hex()[:16], A.hex()[:16])

    # Step 3: submit proof (session carries Session-Id cookie from step 1)
    try:
        r2 = session.post(
            f"{PROTON_AUTH_BASE}/auth",
            json={
                "Username":        username,
                "SRPSession":      info["SRPSession"],
                "ClientEphemeral": base64.b64encode(A).decode(),
                "ClientProof":     base64.b64encode(M1).decode(),
            },
            timeout=15,
        )
    except requests.RequestException as exc:
        return jsonify({"error": f"Network error: {exc}"}), 502

    logger.info("proton-login: /auth response HTTP %s: %s", r2.status_code, r2.text[:200])

    if r2.status_code in (401, 422):
        msg = r2.json().get("Error", "Invalid username or password")
        return jsonify({"error": msg}), 401
    if not r2.ok:
        return jsonify({"error": f"Authentication failed (HTTP {r2.status_code})"}), 502

    auth = r2.json()

    # Check whether 2FA is required before credentials can be used
    two_fa = auth.get("2FA", {})
    if two_fa.get("Enabled", 0):
        token = base64.b64encode(os.urandom(16)).decode()
        _pending_2fa[token] = {
            "uid":           auth["UID"],
            "access_token":  auth["AccessToken"],
            "refresh_token": auth.get("RefreshToken", ""),
            "expires":       time.time() + _PENDING_2FA_TTL,
        }
        logger.info("proton-login: 2FA required for %s", username)
        return jsonify({"needs_2fa": True, "session_token": token})

    # No 2FA — save credentials and trigger cert refresh
    _save_login_creds(auth)
    logger.info("proton-login: login successful for %s", username)
    return jsonify({"message": "Logged in. Certificate refresh triggered."})


@app.route("/api/v1/proton/login/2fa", methods=["POST"])
def proton_login_2fa():
    """Complete a 2FA-gated login with a TOTP code.

    Body: {"session_token": "...", "totp": "123456"}
    """
    import base64
    # Expire stale sessions
    now = time.time()
    for k in [k for k, v in _pending_2fa.items() if now > v.get("expires", 0)]:
        _pending_2fa.pop(k, None)

    data  = request.get_json(silent=True) or {}
    token = data.get("session_token", "")
    totp  = (data.get("totp") or "").strip()

    state = _pending_2fa.pop(token, None)
    if not state:
        return jsonify({"error": "Invalid or expired session — please log in again"}), 400
    if not totp:
        return jsonify({"error": "totp is required"}), 400

    try:
        r = requests.post(
            f"{PROTON_AUTH_BASE}/auth/2fa",
            json={"TwoFactorCode": totp},
            headers=_login_headers(uid=state["uid"], token=state["access_token"]),
            timeout=15,
        )
    except requests.RequestException as exc:
        return jsonify({"error": f"Network error: {exc}"}), 502

    if r.status_code in (401, 422):
        msg = r.json().get("Error", "Invalid 2FA code")
        return jsonify({"error": msg}), 401
    if not r.ok:
        return jsonify({"error": f"2FA verification failed (HTTP {r.status_code})"}), 502

    # Tokens remain the same after successful 2FA; scope is promoted server-side
    _save_login_creds(state)
    logger.info("proton-login: 2FA verified successfully")
    return jsonify({"message": "2FA verified. Certificate refresh triggered."})


def _save_login_creds(auth: dict) -> None:
    """Write credentials.json from an auth response dict and trigger cert refresh."""
    creds = {
        "uid":           auth["uid"] if "uid" in auth else auth["UID"],
        "access_token":  auth["access_token"] if "access_token" in auth else auth["AccessToken"],
        "refresh_token": auth.get("refresh_token") or auth.get("RefreshToken", ""),
        "appversion":    PROTON_APP_VERSION,
        "user_agent":    PROTON_USER_AGENT,
    }
    CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
    CREDENTIALS_FILE.write_text(json.dumps(creds, indent=2))
    CREDENTIALS_FILE.chmod(0o600)
    _cert_refresher.trigger()


if __name__ == "__main__":
    _cert_refresher.start()
    _ip_poller.start()
    # Start the local agent at launch if the tunnel is already up (entrypoint.sh
    # brings up wg-quick before starting this process).  Without this, the agent
    # is only started on connect() or cert refresh, so a container restart with a
    # still-valid cert would leave the tunnel unauthenticated until reconnect.
    _local_agent.start()
    app.run(host="0.0.0.0", port=80, threaded=True)
