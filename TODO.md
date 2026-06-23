# TODO

## Control Panel: ProtonVPN credential management

**Context:** `proton_auth/credentials.json` must be bootstrapped by running
`extract_credentials.py` on the host whenever the refresh token expires. This
is a manual step that requires host access and knowledge of the script.

**Goal:** Let the user manage ProtonVPN credentials entirely from the control
panel UI, without ever needing shell access to the host.

### Ideas

- **Login form** — Present a ProtonVPN username/password form in the control
  panel. On submit, POST the credentials to a new backend endpoint
  (`/api/v1/proton/login` or similar) on the ProtonVPN container, which runs
  the SRP authentication against `https://vpn-api.proton.me/auth` and writes
  the resulting UID/tokens to `credentials.json`.  Requires installing
  `proton-vpn-session` (or implementing SRP auth from scratch) in the Docker
  image.

- **Credential status indicator** — Show a badge in the control panel
  reflecting the state of `credentials.json`:
  - **OK** — tokens present, cert-refresher running normally
  - **Warning** — cert expiry < 48 h and credentials.json is missing or the
    last refresh attempt failed (token likely expired)
  - **Error** — cert has already expired
  
  A new backend endpoint (`GET /api/v1/proton/credential-status`) could return
  this state so the UI can surface it without the user having to watch logs.

- **Re-login prompt** — When the status is Warning or Error, show a banner in
  the control panel prompting the user to log in again (linking to the login
  form above).
