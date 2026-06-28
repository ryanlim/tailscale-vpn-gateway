#!/usr/bin/env python3
"""
ProtonVPN WireGuard Config Downloader

Fetches the ProtonVPN server list and generates WireGuard .conf files organised
into a country/city directory tree, plus an index.json manifest so clients can
pick a random server without touching the API or scanning the filesystem.

Output layout:
  <output-dir>/
    index.json          <- machine-readable manifest of all generated configs
    US/
      New_York/
        us-plus-1.conf
        us-plus-2.conf
      Los_Angeles/
        us-free-8.conf
    NL/
      Amsterdam/
        nl-plus-1.conf

index.json structure:
  {
    "generated": "<ISO timestamp>",
    "countries": ["NL", "US", ...],
    "servers": [
      {
        "name":     "US-PLUS#1",
        "country":  "US",
        "city":     "New York",
        "tier":     "plus",
        "load":     23,
        "features": ["p2p"],
        "path":     "US/New_York/us-plus-1.conf"
      }, ...
    ]
  }

Before using this script:
  1. Download any one WireGuard config from the ProtonVPN portal
     (account.proton.me -> Downloads -> WireGuard configuration).
     ProtonVPN generates the key pair and registers it automatically.
  2. Copy the PrivateKey line from that downloaded .conf file.
  3. Pass it to this script via --private-key or WG_PRIVATE_KEY.
     The same key works for every server — it is account/device-scoped.

Authentication uses your main ProtonVPN account username and password.

Requirements:
  pip install requests bcrypt

Usage examples:
  # Generate every available server (recommended starting point)
  ./download_wg_configs.py -u user@proton.me -p yourpassword -k <privkey>

  # Only Plus servers
  ./download_wg_configs.py -u user@proton.me -p yourpassword -k <privkey> --tier plus

  # Only servers under 50% load
  ./download_wg_configs.py -u user@proton.me -p yourpassword -k <privkey> --max-load 50

  # List what would be generated without writing files
  ./download_wg_configs.py -u user@proton.me -p yourpassword --list

  # Narrow to a single country
  ./download_wg_configs.py -u user@proton.me -p yourpassword -k <privkey> --country JP
"""

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: 'requests' library required.  pip install requests")
    sys.exit(1)

try:
    import bcrypt as _bcrypt
except ImportError:
    _bcrypt = None

API_BASE = "https://api.protonvpn.ch"
WG_PORT = 51820

# Fallback headers used when no official client keyring is found.
# These match the ProtonVPN Linux CLI 5.2.5 release; update if the installed
# client version changes and captcha challenges return.
_DEFAULT_APP_VERSION = "linux-vpn-cli@5.2.5+x86-64"
_DEFAULT_USER_AGENT  = "ProtonVPN/5.2.5 (Linux; ubuntu/24.04)"
DEFAULT_DNS = "10.2.0.1"
INTERFACE_ADDR_V4 = "10.2.0.2/32"
INTERFACE_ADDR_V6 = "2a07:b944::2:2/128"

TIERS = {"free": 0, "basic": 1, "plus": 2, "visionary": 3, "business": 3}
TIER_NAMES = {0: "free", 1: "basic", 2: "plus", 3: "visionary"}

FEATURES = {
    "secure-core": 1,
    "tor": 2,
    "p2p": 4,
    "xor": 8,
    "ipv6": 16,
}

# ---------------------------------------------------------------------------
# Proton SRP authentication
# Proton SRP — heavily modified SRP-6a variant
# Sources: proton/session/srp/_pysrp.py and util.py (proton-python-client package)
# ---------------------------------------------------------------------------
#
# Key differences from standard SRP-6a:
#   - PMHash: SHA512(data+\x00) ‖ SHA512(data+\x01) ‖ SHA512(data+\x02) ‖ SHA512(data+\x03)
#     → 256-byte digest (NOT plain SHA-512)
#   - Salt padding: (salt + b"proton")[:16]  — literal "proton", NOT zero bytes
#   - Password hash: PMHash(bcrypt(pw, padded_salt) | modulus)  — modulus is included!
#   - k = PMHash(g_256le | N_256le)  — g first (as full 256 bytes), then N
#   - K = S as raw 256-byte LE  (no hashing of S)
#   - M1 = PMHash(A | B | K)  — no username/salt/XOR in the proof
# ---------------------------------------------------------------------------

_STD_B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BCR_B64 = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_TO_BCR  = bytes.maketrans(_STD_B64, _BCR_B64)

_PM_MOD_SIZE = 256  # 2048-bit modulus = 256 bytes


def _pmhash(data: bytes) -> bytes:
    """Proton's custom 256-byte hash function (PMHash)."""
    return b"".join(hashlib.sha512(data + bytes([i])).digest() for i in range(4))


def _to_int(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _to_bytes(n: int, size: int = _PM_MOD_SIZE) -> bytes:
    return n.to_bytes(size, "little")


def _strip_pgp_modulus(signed: str) -> bytes:
    """Extract raw modulus bytes from a PGP-signed cleartext message."""
    body: list[str] = []
    past_header = False
    for line in signed.strip().split("\n"):
        if "-----BEGIN PGP SIGNATURE-----" in line:
            break
        if past_header and line.strip():
            body.append(line.strip())
        if not line.strip() and not past_header:
            past_header = True
    return base64.b64decode("".join(body))


def _hash_password(password: str, salt_bytes: bytes, modulus: bytes, version: int) -> bytes:
    """Proton v4 password hash: PMHash(bcrypt(pw, (salt+b'proton')[:16]) | modulus)."""
    if version >= 4:
        if _bcrypt is None:
            print("Error: 'bcrypt' required for ProtonVPN auth.  pip install bcrypt")
            sys.exit(1)
        padded = (salt_bytes + b"proton")[:16]
        bcrypt_b64 = base64.b64encode(padded).translate(_TO_BCR)[:22]
        bcrypt_salt = b"$2y$10$" + bcrypt_b64
        try:
            hashed = _bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt_salt)
        except ValueError as exc:
            print(f"bcrypt failed ({exc}); bcrypt_salt={bcrypt_salt!r}")
            sys.exit(1)
        return _pmhash(hashed + modulus)
    # Version < 4: no bcrypt (legacy accounts not supported since 2018)
    return password.encode("utf-8")


def _srp_proofs(
    modulus: bytes,
    server_ephemeral: bytes,
    salt: bytes,
    hashed_pw: bytes,
) -> tuple[bytes, bytes]:
    """
    Compute SRP client ephemeral (A) and proof (M1).
    hashed_pw is the output of _hash_password() — a 256-byte PMHash digest.
    Returns (A_bytes, M1_bytes).
    """
    N = _to_int(modulus)
    g = 2

    # k = PMHash(g_256le | N_256le) — g as full 256 bytes, g before N
    k = _to_int(_pmhash(_to_bytes(g) + modulus))

    # a: 32-byte random with MSB set
    a = _to_int(os.urandom(32)) | (1 << 255)
    A = pow(g, a, N)
    A_b = _to_bytes(A)

    B = _to_int(server_ephemeral)
    u = _to_int(_pmhash(A_b + server_ephemeral))
    x = _to_int(hashed_pw)

    S = pow((B - k * pow(g, x, N)) % N, a + u * x, N)

    # K = S as raw bytes (no hashing)
    K = _to_bytes(S)

    # M1 = PMHash(A | B | K)
    M1 = _pmhash(A_b + server_ephemeral + K)

    return A_b, M1


def find_keyring_session(username: str | None = None) -> dict | None:
    """
    Scan the ProtonVPN Linux client keyring (~/.config/Proton/) for a saved
    session.  Returns a dict with uid, token, account, app_version, user_agent
    or None if nothing usable is found.

    The keyring files are written by the official ProtonVPN Linux app and
    contain a valid UID + AccessToken that can be used directly without SRP
    auth, along with the exact x-pm-appversion and User-Agent strings that
    the installed client version uses — which avoids captcha detection.
    """
    import glob
    keyring_dir = Path.home() / ".config" / "Proton"
    for path in sorted(glob.glob(str(keyring_dir / "keyring-proton-sso-account-*.json"))):
        try:
            data = json.loads(Path(path).read_text())
        except (json.JSONDecodeError, OSError):
            continue
        uid   = data.get("UID", "")
        token = data.get("AccessToken", "")
        if not uid or not token:
            continue
        account = data.get("AccountName", "")
        if username and account.lower() != username.lower():
            continue
        last_use = data.get("LastUseData", {})
        return {
            "uid":         uid,
            "token":       token,
            "account":     account,
            "app_version": last_use.get("appversion", _DEFAULT_APP_VERSION),
            "user_agent":  last_use.get("user_agent",  _DEFAULT_USER_AGENT),
        }
    return None


def _api_session(uid: str = "", token: str = "",
                 app_version: str = _DEFAULT_APP_VERSION,
                 user_agent: str = _DEFAULT_USER_AGENT) -> requests.Session:
    s = requests.Session()
    headers = {
        "x-pm-appversion": app_version,
        "x-pm-apiversion": "3",
        "User-Agent":      user_agent,
        "Accept":          "application/json",
        "x-pm-locale":     "en_US",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if uid:
        headers["x-pm-uid"] = uid
    s.headers.update(headers)
    return s


def proton_authenticate(username: str, password: str,
                        app_version: str = _DEFAULT_APP_VERSION,
                        user_agent: str = _DEFAULT_USER_AGENT) -> tuple[str, str]:
    """
    Authenticate with the ProtonVPN API using SRP.
    Returns (uid, access_token) for use in subsequent requests.
    """
    session = _api_session(app_version=app_version, user_agent=user_agent)
    session.headers["Content-Type"] = "application/json"

    # Step 1: Obtain SRP parameters
    try:
        r = session.post(
            f"{API_BASE}/auth/info",
            json={"Username": username},
            timeout=30,
        )
        r.raise_for_status()
    except requests.HTTPError as exc:
        print(f"Auth info failed ({exc.response.status_code}): {exc.response.text[:300]}")
        sys.exit(1)

    info = r.json()
    modulus          = _strip_pgp_modulus(info["Modulus"])
    server_ephemeral = base64.b64decode(info["ServerEphemeral"])
    salt             = base64.b64decode(info["Salt"])
    srp_session      = info["SRPSession"]
    version          = info.get("Version", 4)

    # Step 2: Derive SRP proof
    hashed_pw = _hash_password(password, salt, modulus, version)
    A_b, M1   = _srp_proofs(modulus, server_ephemeral, salt, hashed_pw)

    # Step 3: Complete authentication
    try:
        r = session.post(
            f"{API_BASE}/auth",
            json={
                "Username":       username,
                "SRPSession":     srp_session,
                "ClientEphemeral": base64.b64encode(A_b).decode(),
                "ClientProof":    base64.b64encode(M1).decode(),
            },
            timeout=30,
        )
        r.raise_for_status()
    except requests.HTTPError as exc:
        code = exc.response.status_code
        body = exc.response.text[:400]
        print(f"Auth failed (HTTP {code}): {body}")
        sys.exit(1)

    auth = r.json()
    return auth["UID"], auth["AccessToken"]


# ---------------------------------------------------------------------------
# Argument parsing helpers
# ---------------------------------------------------------------------------

def parse_tier(value: str) -> int:
    if value.isdigit():
        v = int(value)
        if v not in TIER_NAMES:
            raise argparse.ArgumentTypeError(f"Tier must be 0-3, got {v}")
        return v
    lower = value.lower()
    if lower not in TIERS:
        raise argparse.ArgumentTypeError(
            f"Unknown tier '{value}'.  Use: free, basic, plus, visionary (or 0-3)"
        )
    return TIERS[lower]


def parse_features(value: str) -> int:
    if value.isdigit():
        return int(value)
    total = 0
    for part in value.split(","):
        part = part.strip().lower()
        if part not in FEATURES:
            raise argparse.ArgumentTypeError(
                f"Unknown feature '{part}'.  Valid: {', '.join(FEATURES)}"
            )
        total |= FEATURES[part]
    return total


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def fetch_logicals(username: str, password: str,
                   uid: str = "", token: str = "",
                   app_version: str = _DEFAULT_APP_VERSION,
                   user_agent: str = _DEFAULT_USER_AGENT) -> list:
    if uid and token:
        print("Using saved session (skipping SRP auth).")
        session = _api_session(uid=uid, token=token,
                               app_version=app_version, user_agent=user_agent)
    else:
        print("Authenticating …", end=" ", flush=True)
        uid, token = proton_authenticate(username, password,
                                         app_version=app_version, user_agent=user_agent)
        print("OK")
        session = _api_session(uid=uid, token=token,
                               app_version=app_version, user_agent=user_agent)
    try:
        resp = session.get(f"{API_BASE}/vpn/logicals", timeout=30)
        resp.raise_for_status()
    except requests.HTTPError as exc:
        print(f"API error ({exc.response.status_code}): {exc}")
        sys.exit(1)
    except requests.RequestException as exc:
        print(f"Network error: {exc}")
        sys.exit(1)

    data = resp.json()
    if data.get("Code") not in (1000, 1001, None):
        print(f"Unexpected API response: {data.get('Code')} — {data.get('Error', '')}")
        sys.exit(1)

    return data.get("LogicalServers", [])


# ---------------------------------------------------------------------------
# Filtering & sorting
# ---------------------------------------------------------------------------

def filter_logicals(
    logicals: list,
    *,
    country: str | None,
    city: str | None,
    tier: int | None,
    max_tier: int | None,
    feature_mask: int | None,
    max_load: int | None,
    online_only: bool,
) -> list:
    out = []
    for s in logicals:
        if online_only and s.get("Status", 0) != 1:
            continue
        if country and s.get("ExitCountry", "").upper() != country.upper():
            continue
        if city and city.lower() not in (s.get("City") or "").lower():
            continue
        if tier is not None and s.get("Tier") != tier:
            continue
        if max_tier is not None and s.get("Tier", 99) > max_tier:
            continue
        if feature_mask is not None and (s.get("Features", 0) & feature_mask) != feature_mask:
            continue
        if max_load is not None and s.get("Load", 100) > max_load:
            continue
        out.append(s)
    return out


def sort_logicals(logicals: list, key: str) -> list:
    if key == "load":
        return sorted(logicals, key=lambda s: s.get("Load", 100))
    if key == "country":
        return sorted(logicals, key=lambda s: (s.get("ExitCountry", ""), s.get("Name", "")))
    return sorted(logicals, key=lambda s: s.get("Name", ""))


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def safe_slug(text: str) -> str:
    return re.sub(r"[^\w\-]", "_", text).strip("_")


def wg_iface_name(label: str) -> str:
    """
    Derive a wg-quick-compatible interface name from a server label.
    Rules: [a-zA-Z0-9_=+.-], max 15 chars.
    e.g. 'US-FREE#8' -> 'us-free_8'  (10 chars, valid)
    """
    name = safe_slug(label).lower()
    if len(name) > 15:
        # Trim from the left to keep the trailing number (most unique part).
        name = name[-15:].lstrip("_-")
    return name


def conf_path(logical: dict, label: str) -> Path:
    country = logical.get("ExitCountry", "XX").upper()
    city    = safe_slug(logical.get("City") or "Unknown")
    return Path(country) / city / (wg_iface_name(label) + ".conf")


# ---------------------------------------------------------------------------
# WireGuard config
# ---------------------------------------------------------------------------

def make_wg_conf(label: str, private_key: str, server_pubkey: str,
                 endpoint_ip: str, dns: str, ipv6: bool) -> str:
    addrs = INTERFACE_ADDR_V4
    if ipv6:
        addrs += f", {INTERFACE_ADDR_V6}"
    return (
        f"[Interface]\n"
        f"# Key for {label}\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {addrs}\n"
        f"DNS = {dns}\n"
        f"MTU = 1420\n"
        f"\n"
        f"[Peer]\n"
        f"# {label}\n"
        f"PublicKey = {server_pubkey}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {endpoint_ip}:{WG_PORT}\n"
        f"PersistentKeepalive = 25\n"
    )


# ---------------------------------------------------------------------------
# index.json
# ---------------------------------------------------------------------------

def write_index(out_dir: Path, entries: list[dict], timestamp: str) -> None:
    index = {
        "generated": timestamp,
        "countries": sorted({e["country"] for e in entries}),
        "servers":   entries,
    }
    (out_dir / "index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False) + "\n"
    )
    print(f"  wrote  {out_dir / 'index.json'}  ({len(entries)} entries)")


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------

def list_logicals(logicals: list) -> None:
    def feat_labels(mask: int) -> str:
        return ", ".join(k for k, v in FEATURES.items() if mask & v) or "—"

    header = f"{'Name':<28} {'Country':<9} {'City':<22} {'Tier':<10} {'Load':>5}  Features"
    print(header)
    print("-" * len(header))
    for s in logicals:
        load = s.get("Load")
        print(
            f"{s['Name']:<28} "
            f"{s.get('ExitCountry', '?'):<9} "
            f"{(s.get('City') or '?'):<22} "
            f"{TIER_NAMES.get(s.get('Tier', 0), '?'):<10} "
            f"{(str(load) + '%') if load is not None else '?':>5}  "
            f"{feat_labels(s.get('Features', 0))}"
        )
    print(f"\n{len(logicals)} server(s) matched.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Download ALL ProtonVPN WireGuard configs, organised by country/city, "
            "with an index.json for easy random selection."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    auth = p.add_argument_group("credentials")
    auth.add_argument("--username", "-u",
        default=os.environ.get("PROTONVPN_USERNAME"), metavar="USER",
        help="ProtonVPN account username/email  (or env PROTONVPN_USERNAME)")
    auth.add_argument("--password", "-p",
        default=os.environ.get("PROTONVPN_PASSWORD"), metavar="PASS",
        help="ProtonVPN account password  (or env PROTONVPN_PASSWORD)")
    auth.add_argument("--private-key", "-k",
        default=os.environ.get("WG_PRIVATE_KEY"), metavar="KEY",
        help="WireGuard private key from any downloaded .conf  (or env WG_PRIVATE_KEY)")
    auth.add_argument("--uid",
        default=os.environ.get("PROTONVPN_UID"), metavar="UID",
        help="Pre-existing session UID — skip SRP auth  (or env PROTONVPN_UID)")
    auth.add_argument("--access-token",
        default=os.environ.get("PROTONVPN_ACCESS_TOKEN"), metavar="TOKEN",
        help="Pre-existing access token — skip SRP auth  (or env PROTONVPN_ACCESS_TOKEN)")

    filt = p.add_argument_group("filters  (all optional — omit to include everything)")
    filt.add_argument("--country", "-c", metavar="CC",
        help="2-letter exit-country code, e.g. US, NL, JP")
    filt.add_argument("--city", metavar="NAME",
        help="City name (case-insensitive substring match)")
    filt.add_argument("--tier", "-t", type=parse_tier, metavar="TIER",
        help="Exact tier: free|basic|plus|visionary  (or 0-3)")
    filt.add_argument("--max-tier", type=parse_tier, metavar="TIER",
        help="Include tiers UP TO this value, e.g. --max-tier plus = free+basic+plus")
    filt.add_argument("--feature", "-f", type=parse_features, metavar="FEAT",
        help="Required feature(s): secure-core, tor, p2p, xor, ipv6  (comma-separated)")
    filt.add_argument("--max-load", type=int, metavar="PCT",
        help="Exclude servers above this load %% (0-100)")
    filt.add_argument("--sort", choices=["load", "name", "country"], default="name",
        help="Sort order  (default: name)")
    filt.add_argument("--top", type=int, metavar="N",
        help="Keep only the top N servers after filtering and sorting")
    filt.add_argument("--include-offline", action="store_true",
        help="Include servers currently offline or in maintenance")

    out = p.add_argument_group("output")
    out.add_argument("--output-dir", "-o", default="./wireguard", metavar="DIR",
        help="Root output directory  (default: ./wireguard)")
    out.add_argument("--dns", default=DEFAULT_DNS, metavar="IP",
        help=f"DNS written into each config  (default: {DEFAULT_DNS})")
    out.add_argument("--ipv6", action="store_true",
        help="Include IPv6 interface address in configs")
    out.add_argument("--list", "-l", action="store_true",
        help="List matching servers and exit without writing any files")
    out.add_argument("--dry-run", "-n", action="store_true",
        help="Print what would be written without actually writing")

    return p


def main() -> None:
    import datetime

    parser = build_parser()
    args = parser.parse_args()

    # Resolve UID + token: explicit flags > keyring auto-detect > SRP auth.
    uid   = args.uid or ""
    token = args.access_token or ""
    app_version = _DEFAULT_APP_VERSION
    user_agent  = _DEFAULT_USER_AGENT

    if not uid or not token:
        keyring = find_keyring_session(args.username)
        if keyring:
            if not uid or not token:
                uid   = keyring["uid"]
                token = keyring["token"]
                print(f"Found keyring session for {keyring['account']}.")
            # Always prefer the installed client's version strings to avoid captcha.
            app_version = keyring["app_version"]
            user_agent  = keyring["user_agent"]

    using_token = bool(uid and token)
    missing = []
    if not using_token:
        if not args.username:
            missing.append("--username  (or PROTONVPN_USERNAME)")
        if not args.password:
            missing.append("--password  (or PROTONVPN_PASSWORD)")
    if not args.list and not args.private_key:
        missing.append("--private-key  (or WG_PRIVATE_KEY)  [not needed with --list]")
    if missing:
        parser.error("Missing required arguments:\n  " + "\n  ".join(missing))

    print("Fetching ProtonVPN server list …", flush=True)
    all_logicals = fetch_logicals(
        args.username or "",
        args.password or "",
        uid=uid,
        token=token,
        app_version=app_version,
        user_agent=user_agent,
    )
    print(f"{len(all_logicals)} servers total.")

    matched = filter_logicals(
        all_logicals,
        country=args.country,
        city=args.city,
        tier=args.tier,
        max_tier=args.max_tier,
        feature_mask=args.feature,
        max_load=args.max_load,
        online_only=not args.include_offline,
    )

    if not matched:
        print("No servers matched the given filters.")
        sys.exit(0)

    matched = sort_logicals(matched, args.sort)
    if args.top:
        matched = matched[: args.top]

    if args.list:
        list_logicals(matched)
        return

    out_dir   = Path(args.output_dir)
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    index_entries: list[dict] = []
    generated = skipped = 0

    for logical in matched:
        physicals = logical.get("Servers", [])
        for idx, physical in enumerate(physicals):
            pub_key  = physical.get("X25519PublicKey")
            entry_ip = physical.get("EntryIP")
            if not pub_key or not entry_ip:
                skipped += 1
                continue

            label    = logical["Name"] if len(physicals) == 1 else f"{logical['Name']}-{idx}"
            rel_path = conf_path(logical, label)
            abs_path = out_dir / rel_path

            feat_list = [k for k, v in FEATURES.items() if logical.get("Features", 0) & v]
            index_entries.append({
                "name":     label,
                "country":  logical.get("ExitCountry", "XX").upper(),
                "city":     logical.get("City") or "Unknown",
                "tier":     TIER_NAMES.get(logical.get("Tier", 0), "unknown"),
                "load":     logical.get("Load"),
                "features": feat_list,
                "path":     str(rel_path),
            })

            server_ipv6 = bool(logical.get("Features", 0) & FEATURES["ipv6"])
            if args.dry_run:
                print(f"[dry-run]  {abs_path}")
            else:
                abs_path.parent.mkdir(parents=True, exist_ok=True)
                abs_path.write_text(make_wg_conf(
                    label=label,
                    private_key=args.private_key,
                    server_pubkey=pub_key,
                    endpoint_ip=entry_ip,
                    dns=args.dns,
                    ipv6=args.ipv6 or server_ipv6,
                ))
                abs_path.chmod(0o600)   # wg-quick warns if config is world-readable
                print(f"  wrote  {abs_path}")
            generated += 1

    if skipped:
        print(f"  (skipped {skipped} physical server(s) with missing WireGuard key or IP)")

    if not args.dry_run and index_entries:
        write_index(out_dir, index_entries, timestamp)

    action = "Would generate" if args.dry_run else "Generated"
    print(f"\n{action} {generated} config(s) in {out_dir}/")


if __name__ == "__main__":
    main()
