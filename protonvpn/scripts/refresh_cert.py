#!/usr/bin/env python3
"""Refresh the ProtonVPN client certificate before it expires.

Reads the stored ProtonVPN session from the system keyring, fetches a fresh
certificate from the ProtonVPN API when the library recommends it, writes the
new PEM files to proton_auth/, and signals the running container to reload the
local agent without restarting the VPN.

Run this from a systemd timer or cron job on the HOST (not inside the container)
since it needs the proton-vpn-session library and the stored login session.

Usage:
    ./refresh_cert.py [options]

Options:
    --cert-dir PATH     Directory containing client.pem / client.key
                        (default: ../wireguard/proton_auth/ relative to this script)
    --reload-url URL    Container API endpoint to signal a cert reload
                        (default: http://10.1.4.7/api/v1/reload-cert)
    --force             Refresh even if the library says it is not due yet
    --dry-run           Print expiry info without refreshing

Scheduling (run once as root or the user who owns the keyring):
    systemctl --user enable --now protonvpn-cert-refresh.timer
    (see install-cert-refresh-timer.sh for setup instructions)
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

try:
    from proton.sso import ProtonSSO
    from proton.vpn.session import VPNSession
except ImportError:
    print("ERROR: proton-vpn-session not installed.", file=sys.stderr)
    sys.exit(1)

try:
    import requests as _requests
except ImportError:
    _requests = None

_SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CERT_DIR = _SCRIPT_DIR.parent / "wireguard" / "proton_auth"
DEFAULT_RELOAD_URL = "http://10.1.4.7/api/v1/reload-cert"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("refresh_cert")


async def _do_fetch(sess) -> None:
    await sess.fetch_certificate()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cert-dir", type=Path, default=DEFAULT_CERT_DIR)
    parser.add_argument("--reload-url", default=DEFAULT_RELOAD_URL)
    parser.add_argument("--force", action="store_true", help="Refresh even if not yet due")
    parser.add_argument("--dry-run", action="store_true", help="Print expiry info and exit")
    args = parser.parse_args()

    sso = ProtonSSO()
    sess = sso.get_default_session(VPNSession)
    pk = sess.vpn_account.vpn_credentials.pubkey_credentials

    validity = pk.certificate_validity_remaining
    to_refresh = pk.remaining_time_to_next_refresh
    log.info(
        "Certificate validity: %.0f s (%.1f days) | time to next refresh: %.0f s (%.1f days)",
        validity, validity / 86400,
        to_refresh, to_refresh / 86400,
    )

    if args.dry_run:
        return

    if to_refresh > 0 and not args.force:
        log.info("Not due for refresh yet — nothing to do")
        return

    log.info("Fetching new certificate from ProtonVPN API...")
    asyncio.run(_do_fetch(sess))

    new_validity = pk.certificate_validity_remaining
    log.info("New certificate valid for %.0f s (%.1f days)", new_validity, new_validity / 86400)

    # Write PEM files so the container picks them up (wireguard/ is bind-mounted)
    args.cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = args.cert_dir / "client.pem"
    key_path  = args.cert_dir / "client.key"

    cert_path.write_text(pk.certificate_pem)
    cert_path.chmod(0o600)
    key_path.write_text(pk.get_ed25519_sk_pem())
    key_path.chmod(0o600)
    log.info("Wrote %s and %s", cert_path, key_path)

    # Signal the container to reload the cert without restarting
    if _requests is None:
        log.warning("'requests' not installed — skipping container reload (restart manually)")
        return
    try:
        r = _requests.post(args.reload_url, timeout=5)
        if r.ok:
            log.info("Container acknowledged reload: %s", r.json().get("message", "ok"))
        else:
            log.warning("Container reload returned HTTP %s", r.status_code)
    except Exception as exc:
        log.warning("Could not reach container at %s: %s", args.reload_url, exc)


if __name__ == "__main__":
    main()
