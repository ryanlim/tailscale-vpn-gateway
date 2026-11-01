#!/usr/bin/env python3
"""ProtonVPN WireGuard backend — implements the BACKEND_API v1 contract."""
import base64
import hashlib
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
# Default city/server to connect to on startup (e.g. "_city:US:San Jose").
# Persisted to .target_city in the wireguard volume so restarts reconnect to
# the last-used location rather than the entrypoint's WG_CONF fallback.
PROTONVPN_CITY = os.environ.get("PROTONVPN_CITY", "")
CITY_TARGET_FILE = WG_DIR / ".target_city"
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

# When a portal-registered WireGuard private key is supplied
# (PROTONVPN_WG_PRIVATE_KEY), the key is pre-authorized on the account, so the
# server never jails the session and the whole local-agent + certificate flow
# is unnecessary — it's plain WireGuard, exactly like a manually-downloaded
# portal config or the NordVPN backend. Skip the agent and cert-refresher in
# that mode; it's simpler and avoids the cert-fingerprint/renewal machinery.
USE_LOCAL_AGENT = not os.environ.get("PROTONVPN_WG_PRIVATE_KEY", "").strip()

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
        self._auth_event = threading.Event()    # set when server confirms "connected"

    @property
    def state(self) -> str:
        """Current state: 'disabled', 'connected', 'connecting', or 'disconnected'."""
        if not USE_LOCAL_AGENT:
            return "disabled"  # portal-key mode — no agent needed
        if self._stop.is_set() or not (self._thread and self._thread.is_alive()):
            return "disconnected"
        return "connected" if self._auth_event.is_set() else "connecting"

    def wait_for_auth(self, timeout: float = 75.0) -> bool:
        """Block until the local agent is authenticated, or return True if no cert is needed.

        Returns True on success (authenticated, cert absent, or agent disabled),
        False on timeout.
        """
        if not USE_LOCAL_AGENT:
            return True  # portal-key mode — session is pre-authorized, no wait
        if not LOCAL_AGENT_CERT.exists() or not LOCAL_AGENT_KEY.exists():
            return True  # free tier or cert not yet provisioned — no auth required
        return self._auth_event.wait(timeout=timeout)

    def start(self) -> None:
        if not USE_LOCAL_AGENT:
            return
        if not LOCAL_AGENT_CERT.exists() or not LOCAL_AGENT_KEY.exists():
            return
        self.stop()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="local-agent")
        self._thread.start()

    def stop(self) -> None:
        self._auth_event.clear()
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
                                    self._auth_event.set()
                                else:
                                    err = msg.get("error", {})
                                    code = err.get("code", 0)
                                    desc = err.get("description", "unknown")
                                    logger.warning("Local agent rejected (code %s): %s", code, desc)
                                    if code == 86202:
                                        self._auth_event.clear()
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
                        self._auth_event.clear()  # connection dropped; will reconnect
            except OSError as exc:
                if not self._stop.is_set():
                    logger.warning("Local agent connection lost: %s", exc)
                    self._auth_event.clear()
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

    # "rejected" (Proton refused the token) or "network" (couldn't reach Proton)
    last_refresh_failure: str | None = None

    # Proton rotates the refresh token on every use and may revoke the session if a
    # rotated-away token is presented again.  Refreshes therefore must never run
    # concurrently, and each must start from the newest token on disk.
    _refresh_lock = threading.Lock()

    @staticmethod
    def _fp(token: str) -> str:
        """Short non-reversible fingerprint of a token, safe to log."""
        return hashlib.sha256(token.encode()).hexdigest()[:8]

    def _refresh_token(self, creds: dict) -> dict | None:
        """Exchange the refresh token for a new access token. Returns updated creds or None.
        On failure, last_refresh_failure says whether Proton rejected it or was unreachable."""
        with self._refresh_lock:
            latest = self._load_creds()
            if latest and latest.get("uid") == creds.get("uid"):
                creds = latest  # another thread may have rotated the token since the caller read it
            return self._refresh_token_locked(creds)

    def _refresh_token_locked(self, creds: dict) -> dict | None:
        self.last_refresh_failure = None
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
            old_fp = self._fp(creds["refresh_token"])
            if r.ok:
                data = r.json()
                creds = {**creds, "access_token": data["AccessToken"], "refresh_token": data["RefreshToken"]}
                self._save_creds(creds)
                logger.info("cert-refresher: access token refreshed (refresh token %s -> %s)",
                            old_fp, self._fp(creds["refresh_token"]))
                return creds
            logger.warning("cert-refresher: token refresh HTTP %s (refresh token %s): %s — "
                           "re-run headless_extract_credentials.sh",
                           r.status_code, old_fp, r.text[:300])
            self.last_refresh_failure = "network" if r.status_code >= 500 else "rejected"
        except Exception as exc:
            logger.warning("cert-refresher: token refresh error: %s", exc)
            self.last_refresh_failure = "network"
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


def _iface_to_name(iface: str) -> str | None:
    """Friendly ProtonVPN server name (e.g. 'US-CA#36') for an interface stem,
    looked up from index.json; None if the server isn't in the manifest."""
    for s in _load_index():
        if s.get("path") and Path(s["path"]).stem == iface:
            return s.get("name")
    return None


def _find_conf(stem: str) -> Path | None:
    """Locate a .conf file by its interface name (stem), checking root then subdirs."""
    p = WG_DIR / f"{stem}.conf"
    if p.exists():
        return p
    hits = list(WG_DIR.rglob(f"{stem}.conf"))
    return hits[0] if hits else None


_endpoint_cache: dict[str, str | None] = {}  # conf path → endpoint host (IP), cached


def _conf_endpoint_host(conf: Path | None) -> str | None:
    """Endpoint host (IP, no port) from a WireGuard .conf, cached by path.

    ProtonVPN fronts many logical servers — distinct names and configs — with a
    single physical machine that shares one Endpoint IP. Keying on that host lets
    callers dedup or exclude by the real box rather than the config label, so a
    "reconnect" reaches a genuinely different server instead of the same one under
    a new name. Endpoints are static per config; the cache is cleared on refresh.
    """
    if conf is None:
        return None
    key = str(conf)
    if key not in _endpoint_cache:
        host = None
        try:
            for line in conf.read_text().splitlines():
                stripped = line.strip()
                if stripped.startswith("Endpoint"):
                    _, _, val = stripped.partition("=")
                    host = val.strip().rsplit(":", 1)[0].strip() or None
                    break
        except OSError:
            host = None
        _endpoint_cache[key] = host
    return _endpoint_cache[key]


def _server_host(entry: dict) -> str | None:
    """Endpoint IP for an index.json server entry.

    Prefers the recorded "host" field (written by download_wg_configs.py) so
    dedup needs no disk reads; falls back to parsing the .conf for indexes
    generated before that field existed.
    """
    host = entry.get("host")
    if host:
        return host
    path = entry.get("path")
    return _conf_endpoint_host(WG_DIR / path) if path else None


def _host_for_iface(stem: str) -> str | None:
    """Endpoint IP for a WireGuard interface stem, via its index entry or .conf."""
    for s in _load_index():
        if s.get("path") and Path(s["path"]).stem == stem:
            return _server_host(s)
    return _conf_endpoint_host(_find_conf(stem))


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

    # Surface the friendly ProtonVPN server name (e.g. "US-CA#36") for the UI,
    # falling back to the interface stem if the server isn't in index.json.
    server_name = _iface_to_name(iface) or iface
    fields["Server"] = server_name

    if connected and _connect_time > 0:
        fields["Uptime"] = _uptime_str(_connect_time)

    ipv4, ipv6 = _get_public_ips(refresh=refresh)
    if ipv4 and ipv4.get("ip"):
        loc = ", ".join(filter(None, [ipv4.get("city"), ipv4.get("country_code")]))
        fields["Public IPv4"] = f"{ipv4['ip']} ({loc})" if loc else ipv4["ip"]
    if ipv6 and ipv6.get("ip"):
        loc = ", ".join(filter(None, [ipv6.get("city"), ipv6.get("country_code")]))
        fields["Public IPv6"] = f"{ipv6['ip']} ({loc})" if loc else ipv6["ip"]

    city_code = _iface_to_city_code(iface)
    if not city_code:
        # Server absent from index.json (e.g. removed from ProtonVPN's list since last
        # download but still on disk). Derive city from the conf path: CC/City/server.conf.
        conf = _find_conf(iface)
        if conf:
            try:
                rel = conf.relative_to(WG_DIR)
                if len(rel.parts) >= 3:
                    cc = rel.parts[-3].upper()
                    city_name = rel.parts[-2].replace("_", " ")
                    city_code = f"_city:{cc}:{city_name}"
            except ValueError:
                pass
    city_code = city_code or iface
    return jsonify({
        "status": "Connected" if connected else "Disconnected",
        "server": iface,
        "server_name": server_name,
        "city_code": city_code,
        "city": f"ProtonVPN ({server_name})",
        "fields": fields,
        "details": raw,
        "local_agent": _local_agent.state,
    })


def _connect_to_target(target: str, exclude: set[str] | None = None) -> tuple[str | None, str, str | None]:
    """Connect to a server stem or city code.

    Returns (message, wg_output, error). Exactly one of message/error is set.
    Persists the chosen target to CITY_TARGET_FILE so container restarts
    reconnect to the same location.
    """
    original_target = target

    # Accept NordVPN-style Country/City_Name format (e.g. "US/San_Jose").
    # Underscores in the city part are treated as spaces to match index.json.
    if "/" in target and not target.startswith("_city:"):
        cc, _, city_slug = target.partition("/")
        target = f"_city:{cc.upper()}:{city_slug.replace('_', ' ')}"

    # City-level selection: auto-pick the lowest-load server for COUNTRY/CITY.
    if target.startswith("_city:"):
        parts = target.split(":", 2)
        if len(parts) != 3:
            return None, "", f"Invalid city code: {target}"
        _, country, city = parts
        index = _load_index()
        candidates = [
            s for s in index
            if s.get("country", "").upper() == country.upper()
            and (s.get("city") or "") == city
        ]
        if not candidates:
            return None, "", f"No servers found for {country}/{city}"
        # Deprioritize free-tier servers to lowest priority: they're shared across
        # every free account regardless of what this (paid) account is entitled
        # to, so they run hot and unreliable. Prefer paid servers everywhere and
        # only fall back to free if a location genuinely has nothing else.
        paid_candidates = [s for s in candidates if s.get("tier") != "free"]
        if paid_candidates:
            candidates = paid_candidates
        # Prefer IPv6-capable servers: the WireGuard tunnel address (2a07:b944::2:2/128)
        # only works if the server has the ipv6 feature; non-IPv6 servers drop IPv6 packets.
        ipv6_candidates = [s for s in candidates if "ipv6" in s.get("features", [])]
        pool = ipv6_candidates if ipv6_candidates else candidates
        # ProtonVPN maps many logical servers (distinct names/configs) onto a single
        # physical machine sharing one Endpoint IP. Filter and dedup on that endpoint
        # rather than the config name: excluding only the current *name* on reconnect
        # can land straight back on the same box under a different label. Translate
        # the excluded interfaces to the endpoint IPs we must avoid.
        exclude_hosts = {
            h for stem in (exclude or ())
            if (h := _host_for_iface(stem))
        }
        # Keep one representative (lowest load) per distinct endpoint and drop any box
        # we were told to avoid. Servers whose endpoint can't be resolved are kept
        # as-is so an unreadable config never silently removes a usable server.
        rep_by_host: dict[str, dict] = {}
        unknown: list[dict] = []
        for s in pool:
            host = _server_host(s)
            if host is None:
                unknown.append(s)
                continue
            if host in exclude_hosts:
                continue
            cur = rep_by_host.get(host)
            if cur is None or s.get("load", 100) < cur.get("load", 100):
                rep_by_host[host] = s
        deduped = list(rep_by_host.values()) + unknown
        if deduped:
            pool = deduped
        # else: excluding the current box emptied the pool (the city has only that one
        # machine) — fall back to the original pool so we still reconnect somewhere.
        best = random.choice(pool)
        target = Path(best["path"]).stem
        logger.info("City random-select %s/%s → %s", country, city, target)

    conf = _find_conf(target)
    if conf is None:
        return None, "", f"Config not found: {target}.conf"

    # The WireGuard interface name is always the config basename (stem), regardless
    # of whether target was supplied as a path ("US/Dallas/us-tx_477") or bare name.
    iface = conf.stem

    with _lock:
        current = _active_iface()
        if current and current == iface and _wg_show(iface):
            # Persist city so reconnect() knows the target on next watchdog cycle.
            try:
                CITY_TARGET_FILE.write_text(original_target)
            except OSError:
                pass
            return f"Already connected to {iface}", "", None

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
            return None, "", f"wg-quick up failed: {err}"

        _exempt_management_del()

        # Apply masquerade and record the active iface immediately so the status
        # endpoint reflects the new server without waiting for the handshake.
        global _connect_time
        _connect_time = time.time()
        _masquerade_update(None, iface, _conf_has_ipv6(conf))
        ACTIVE_IFACE_FILE.write_text(iface)

        # Persist so the next container restart reconnects here instead of
        # falling back to the entrypoint's WG_CONF default.
        try:
            CITY_TARGET_FILE.write_text(original_target)
        except OSError as exc:
            logger.warning("Could not write %s: %s", CITY_TARGET_FILE, exc)

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

        return f"Connected to {original_target}", result.stdout, None


def _city_from_conf_path(conf_path: Path) -> str:
    """Derive a _city:CC:City code from a conf path like .../CC/City_Name/server.conf."""
    try:
        rel = conf_path.relative_to(WG_DIR)
        if len(rel.parts) >= 3:
            cc = rel.parts[-3].upper()
            city_name = rel.parts[-2].replace("_", " ")
            return f"_city:{cc}:{city_name}"
    except ValueError:
        pass
    return ""


def _startup_connect() -> None:
    """Connect to the saved target (or PROTONVPN_CITY default) after startup.

    Runs in a background thread so it doesn't block the Flask server from
    starting. Waits briefly for the entrypoint's wg-quick tunnel to settle
    before switching to the preferred city/server.
    """
    time.sleep(8)
    target = ""
    try:
        target = CITY_TARGET_FILE.read_text().strip()
    except OSError:
        pass
    if not target:
        target = PROTONVPN_CITY
    if not target:
        # Derive city from WG_CONF path so a fresh container (no saved target,
        # no PROTONVPN_CITY env) still rotates away from the hardcoded default.
        target = _city_from_conf_path(Path(WG_CONF))
        if target:
            logger.info("startup-connect: derived city from WG_CONF path → %s", target)
    if not target:
        logger.info("startup-connect: no city target known, keeping entrypoint default")
        return
    # Rotate away from the entrypoint's default iface so a dead startup server
    # doesn't become permanent.
    default_iface = Path(WG_CONF).stem
    logger.info("startup-connect: connecting to %s (exclude=%s)", target, default_iface)
    message, _, error = _connect_to_target(target, exclude={default_iface})
    if error:
        logger.warning("startup-connect: %s", error)
    else:
        logger.info("startup-connect: %s", message)


@app.route("/api/v1/connect", methods=["POST"])
def connect():
    data = request.get_json(silent=True) or {}
    target = (data.get("server") or "").strip()
    if not target:
        return jsonify({"error": "server is required"}), 400
    message, output, error = _connect_to_target(target)
    if error:
        status = 404 if "No servers found" in error else (400 if "Config not found" in error or "Invalid city" in error else 500)
        return jsonify({"error": error}), status
    return jsonify({"message": message, "output": output})


@app.route("/api/v1/reconnect", methods=["POST"])
def reconnect():
    """Reconnect to a different server in the same city, then wait for local agent auth.

    Used by the entrypoint.sh watchdog instead of raw wg-quick restarts.  By
    delegating here the watchdog gets server rotation (avoids a dead server) and
    a synchronous signal that forwarding is actually unblocked — not just that
    wg-quick exited.

    Body (optional): {"target": "US/San_Jose"}  — defaults to the persisted city
    """
    data = request.get_json(silent=True) or {}
    current_iface = _active_iface()

    target = (data.get("target") or "").strip()
    if not target:
        try:
            target = CITY_TARGET_FILE.read_text().strip()
        except OSError:
            pass
    if not target:
        target = _iface_to_city_code(current_iface) or ""
    if not target:
        conf = _find_conf(current_iface)
        if conf:
            target = _city_from_conf_path(conf)
    if not target:
        target = PROTONVPN_CITY
    if not target:
        return jsonify({"error": "No city target known — set PROTONVPN_CITY or connect manually first"}), 400

    logger.info("reconnect: rotating away from %s → %s", current_iface, target)
    message, _output, error = _connect_to_target(target, exclude={current_iface})
    if error:
        return jsonify({"status": "failed", "error": error}), 500

    # Block until the local agent authenticates (or cert absent → returns True immediately).
    # This is the key difference from /connect: the caller knows forwarding is unblocked.
    auth_ok = _local_agent.wait_for_auth(timeout=75.0)
    new_iface = _active_iface()
    logger.info("reconnect: %s local_agent=%s auth_ok=%s", new_iface, _local_agent.state, auth_ok)
    return jsonify({
        "status": "connected" if auth_ok else "connected_pending_auth",
        "server": new_iface,
        "message": message,
        "local_agent": _local_agent.state,
    })


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
    Requires credentials.json to be present (create it with scripts/headless_extract_credentials.sh).
    """
    if _cert_refresher._load_creds() is None:
        return jsonify({"error": f"credentials.json missing — {_RELOGIN_HINT}"}), 400
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
                                   "message": f"No Proton session — {_RELOGIN_HINT}",
                                   "started": _refresh_status["started"]}
            return

        # The stored access token is short-lived; exchange the refresh token for
        # a fresh one first, otherwise /vpn/logicals returns 401.
        refreshed = None
        for attempt in range(4):
            refreshed = _cert_refresher._refresh_token(creds)
            if refreshed is not None or _cert_refresher.last_refresh_failure != "network":
                break
            time.sleep(5)  # DNS/tunnel blips (e.g. during a server rotation)
        if refreshed is None:
            network = _cert_refresher.last_refresh_failure == "network"
            if not network:
                _session_check_reset(False)
            msg = ("Can't reach Proton right now (network/DNS) — try again in a moment"
                   if network else
                   f"Proton session expired — {_RELOGIN_HINT}")
            with _refresh_lock:
                _refresh_status = {"state": "error", "message": msg,
                                   "started": _refresh_status["started"]}
            return
        _session_check_reset(True)
        creds = refreshed

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
            _endpoint_cache.clear()
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

# Shown wherever the Proton session is missing/expired.  The panel cannot log in
# itself (Proton demands a CAPTCHA that only its own sites may display).
_RELOGIN_HINT = "sign in again on the host (see \"How to fix\")"


# Portal-key mode has no certificate, but "Refresh configs" still needs a valid
# Proton session.  Validate it by exchanging the refresh token, at most once per
# _SESSION_CHECK_TTL, and cache the result.  Reset when refreshes succeed or fail.
_SESSION_CHECK_TTL = 3600
_session_check: dict = {"ok": None, "at": 0.0, "mtime": None, "running": False}
_session_check_lock = threading.Lock()


def _creds_mtime() -> float | None:
    try:
        return CREDENTIALS_FILE.stat().st_mtime
    except OSError:
        return None


def _session_check_reset(ok: bool | None = None) -> None:
    with _session_check_lock:
        _session_check.update(ok=ok, at=time.time() if ok is not None else 0.0,
                              mtime=_creds_mtime())


def _session_check_bg() -> None:
    try:
        creds = _cert_refresher._load_creds()
        if creds is not None:
            if _cert_refresher._refresh_token(creds) is not None:
                _session_check_reset(True)
            elif _cert_refresher.last_refresh_failure == "network":
                # Proton unreachable (e.g. tunnel still coming up): not an expired
                # session.  Leave the result unknown so the next poll retries.
                _session_check_reset(None)
            else:
                _session_check_reset(False)
    finally:
        with _session_check_lock:
            _session_check["running"] = False


def _session_ok() -> bool | None | str:
    """True/False if the saved Proton session is valid, None if there is none,
    "checking" while the first validation is in flight.  Never blocks on Proton:
    a stale result is served while a refresh runs in the background."""
    if _cert_refresher._load_creds() is None:
        return None
    with _session_check_lock:
        # Also stale when credentials.json was replaced externally (e.g. by
        # extract_credentials.py); our own saves update "mtime" via the reset.
        stale = (_session_check["ok"] is None
                 or time.time() - _session_check["at"] > _SESSION_CHECK_TTL
                 or _session_check["mtime"] != _creds_mtime())
        if stale and not _session_check["running"]:
            _session_check["running"] = True
            threading.Thread(target=_session_check_bg, daemon=True, name="session-check").start()
        ok = _session_check["ok"]
    return "checking" if ok is None else ok


@app.route("/api/v1/proton/credential-status")
def credential_status():
    """Report the health of credentials.json and client.pem."""
    if not USE_LOCAL_AGENT:
        # Portal-key mode: no certificate to manage, but the saved Proton login is
        # still used by "Refresh configs", so report on that.
        ok = _session_ok()
        if ok == "checking":
            return jsonify({"status": "checking", "message": "Checking Proton session…"})
        if ok is None:
            return jsonify({"status": "warning",
                            "message": f"No Proton session — {_RELOGIN_HINT}"})
        if not ok:
            return jsonify({"status": "error",
                            "message": f"Proton session expired — {_RELOGIN_HINT}"})
        return jsonify({"status": "ok", "message": "Proton session valid"})
    creds = _cert_refresher._load_creds()
    remaining = _cert_refresher._cert_seconds_remaining()

    if creds is None:
        return jsonify({"status": "warning", "message": f"credentials.json missing — {_RELOGIN_HINT}"})

    if remaining is None:
        return jsonify({"status": "warning", "message": "Client certificate not yet provisioned — refresh will run within 6 h"})

    if remaining <= 0:
        return jsonify({"status": "error", "message": f"Client certificate has expired — {_RELOGIN_HINT}"})

    if remaining < CERT_REFRESH_AHEAD:
        h = int(remaining / 3600)
        return jsonify({"status": "warning", "message": f"Certificate expiring in {h} h — refresh imminent"})

    days = remaining / 86400
    return jsonify({"status": "ok", "message": f"Certificate valid for {days:.1f} days"})


if __name__ == "__main__":
    if USE_LOCAL_AGENT:
        _cert_refresher.start()
    else:
        logger.info("PROTONVPN_WG_PRIVATE_KEY set — using pre-authorized portal "
                    "key; local agent and certificate refresh are disabled.")
    _ip_poller.start()
    # Start the local agent at launch if the tunnel is already up (entrypoint.sh
    # brings up wg-quick before starting this process).  Without this, the agent
    # is only started on connect() or cert refresh, so a container restart with a
    # still-valid cert would leave the tunnel unauthenticated until reconnect.
    _local_agent.start()
    # Connect to the saved target or PROTONVPN_CITY default in the background,
    # giving the entrypoint's wg-quick tunnel a moment to settle first.
    threading.Thread(target=_startup_connect, daemon=True, name="startup-connect").start()
    app.run(host="0.0.0.0", port=80, threaded=True)
