# TODO

## Control Panel: ProtonVPN credential management

> **Note:** This whole section applies only to the **legacy local-agent
> certificate flow**. Setting `PROTONVPN_WG_PRIVATE_KEY` in `.env` (a
> portal-registered key) skips the certificate flow entirely — no
> `credentials.json`, no cert refresh, no expiry to manage — which is now the
> recommended setup (see README → "ProtonVPN first-time setup"). The items
> below are only relevant if you deliberately use the cert flow instead.

**Context:** `proton_auth/credentials.json` must be bootstrapped by running
`extract_credentials.py` on the host whenever the refresh token expires. This
is a manual step that requires host access and knowledge of the script.

**Goal:** Let the user manage ProtonVPN credentials entirely from the control
panel UI, without ever needing shell access to the host.

### Ideas

- ~~**Login form**~~ — Not feasible: Proton answers password logins from this
  client with a CAPTCHA (code 9001) that only Proton's own domains may frame, so
  the panel can't present it.  Sign-in happens on the host with
  `protonvpn/scripts/headless_extract_credentials.sh <username>`, which the panel's
  "How to fix" dialog explains.

- **Credential status indicator** — Show a badge in the control panel
  reflecting the state of `credentials.json`:
  - **OK** — tokens present, cert-refresher running normally
  - **Warning** — cert expiry < 48 h and credentials.json is missing or the
    last refresh attempt failed (token likely expired)
  - **Error** — cert has already expired
  
  A new backend endpoint (`GET /api/v1/proton/credential-status`) could return
  this state so the UI can surface it without the user having to watch logs.

- **Re-login prompt** — When the status is Warning or Error, show a banner in
  the control panel prompting the user to refresh credentials (the "How to fix"
  dialog shows the host command).
