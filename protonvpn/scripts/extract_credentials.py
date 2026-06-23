#!/usr/bin/env python3
"""Extract ProtonVPN session credentials for in-container certificate refresh.

Run this ONCE on the host (where the ProtonVPN keyring session is stored) to
bootstrap the in-container _CertRefresher thread in app.py.  The credentials
are written to proton_auth/credentials.json inside the bind-mounted wireguard
volume, making them accessible to the container without installing the
proton-vpn-session library in the Docker image.

The container reads credentials.json to call POST /vpn/v1/certificate directly
and refreshes access tokens via /auth/refresh as needed.  credentials.json is
updated in-place whenever tokens are refreshed, so this script only needs to
run once (or after a full re-login).

Usage:
    ./extract_credentials.py [--cert-dir PATH]
"""

import argparse
import json
import sys
from pathlib import Path

try:
    from proton.sso import ProtonSSO
    from proton.vpn.session import VPNSession
except ImportError:
    print("ERROR: proton-vpn-session not installed.", file=sys.stderr)
    sys.exit(1)

_SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CERT_DIR = _SCRIPT_DIR.parent / "wireguard" / "proton_auth"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--cert-dir", type=Path, default=DEFAULT_CERT_DIR,
        help="Directory to write credentials.json (default: ../wireguard/proton_auth/)"
    )
    args = parser.parse_args()

    sso = ProtonSSO()
    sess = sso.get_default_session(VPNSession)

    if not sess.authenticated:
        print("ERROR: no active ProtonVPN session found in keyring.", file=sys.stderr)
        print("       Log in first:  protonvpn-cli login <username>", file=sys.stderr)
        sys.exit(1)

    state = sess.__getstate__()
    creds = {
        "uid":           state["UID"],
        "access_token":  state["AccessToken"],
        "refresh_token": state["RefreshToken"],
        "appversion":    state.get("LastUseData", {}).get("appversion", "Other"),
        "user_agent":    state.get("LastUseData", {}).get("user_agent", "None"),
    }

    args.cert_dir.mkdir(parents=True, exist_ok=True)
    out = args.cert_dir / "credentials.json"
    out.write_text(json.dumps(creds, indent=2))
    out.chmod(0o600)

    print(f"Wrote {out}")
    print(f"  uid        : {creds['uid'][:8]}...")
    print(f"  appversion : {creds['appversion']}")
    print(f"  user_agent : {creds['user_agent']}")
    print()
    print("The container's cert-refresher thread will pick this up on the next check (within 6 h).")
    print("Rebuild and restart the container if it is already running:")
    print("  docker compose up -d --build protonvpn")


if __name__ == "__main__":
    main()
