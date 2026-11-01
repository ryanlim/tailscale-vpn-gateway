#!/usr/bin/env bash
# Sign in to Proton VPN and extract credentials.json on a headless host (SSH only).
#
# extract_credentials.py needs an unlocked Secret Service keyring.  Over SSH the
# desktop keyring is locked and nothing can unlock it, so Proton's library falls
# back to a stale session.  This script runs `protonvpn signin` and the extractor
# together inside a private D-Bus session with a throwaway keyring, which avoids
# the problem.
#
# Usage:
#     ./headless_extract_credentials.sh [USERNAME] [--cert-dir PATH] [--keep-keyring]
#
# USERNAME is your Proton account name; it is prompted for if omitted.
#
# The throwaway keyring lives in a temp dir and is deleted afterwards unless
# --keep-keyring is given.  It holds your Proton session while it exists.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/../wireguard/proton_auth"
KEEP=0
USERNAME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cert-dir)     CERT_DIR="$2"; shift 2 ;;
        --keep-keyring) KEEP=1; shift ;;
        -h|--help)      sed -n '2,17p' "$0"; exit 0 ;;
        -*) echo "Unknown argument: $1" >&2; exit 2 ;;
        *)  USERNAME="$1"; shift ;;
    esac
done

for cmd in dbus-run-session gnome-keyring-daemon protonvpn python3; do
    command -v "$cmd" >/dev/null || { echo "ERROR: '$cmd' not found" >&2; exit 1; }
done

if [[ -z "$USERNAME" ]]; then
    read -r -p "Proton username: " USERNAME
fi
[[ -n "$USERNAME" ]] || { echo "ERROR: username required" >&2; exit 2; }

KR_DIR="$(mktemp -d "${TMPDIR:-/tmp}/proton-keyring.XXXXXX")"
chmod 700 "$KR_DIR"
cleanup() { [[ $KEEP -eq 1 ]] && echo "Keyring kept at $KR_DIR" || rm -rf "$KR_DIR"; }
trap cleanup EXIT

export XDG_DATA_HOME="$KR_DIR"
export CERT_DIR SCRIPT_DIR USERNAME

dbus-run-session -- bash -c '
    set -euo pipefail
    # The password only protects this temporary keyring.
    echo -n "throwaway" | gnome-keyring-daemon --unlock --components=secrets >/dev/null
    echo -n "throwaway" | gnome-keyring-daemon --start  --components=secrets >/dev/null

    echo "Signing in to Proton VPN (captcha/2FA are handled by Proton'"'"'s own client)..."
    protonvpn signin "$USERNAME"

    python3 "$SCRIPT_DIR/extract_credentials.py" --cert-dir "$CERT_DIR"
'

echo
echo "Done. Reload the control panel; the Account badge should turn green."
echo "Do not rerun this after the backend has renewed the session unless it expires:"
echo "Proton rotates the refresh token on every renewal."
