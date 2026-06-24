# tailscale-vpn-gateway

A dockerized Tailscale exit node that egresses through one or more VPN
backends (NordVPN and ProtonVPN, with more to follow), fronted by a small
web control panel reachable over your tailnet.

## Architecture

```
[ tailnet client ] ──► [ tailscale ]  (also runs nginx as reverse proxy)
                            │
                            ▼  (default route)
                       [ vpn-backend ]  ──►  internet
                            ▲
                            │  (proxied API calls)
                       [ control-panel ]  ──►  serves UI on :80 / :443
```

- **`tailscale`** — the exit node. Runs `tailscaled`, owns the default
  route via the VPN backend, and runs nginx to terminate HTTP/HTTPS for
  the control panel.
- **A VPN backend container** (e.g. `nordvpn-wg`) — establishes the
  outbound tunnel and exposes a small `/api/v1/*` HTTP API for the
  panel to drive. The full contract is in [`BACKEND_API.md`](./BACKEND_API.md).
- **`control-panel`** — Flask app that serves the UI and proxies
  `/api/v1/backends/<name>/*` to whichever backend the user has
  selected. Knows nothing about specific VPN providers.

The current backends are:

| Backend       | Status     | How it connects                           |
|---------------|------------|-------------------------------------------|
| `nordvpn-wg`  | active     | NordVPN's WireGuard (NordLynx)            |
| `protonvpn`   | active     | ProtonVPN's WireGuard configs             |
| `nordvpn`     | maintained | NordVPN's official CLI (OpenVPN/NordLynx) |

## Requirements

- A docker host with `docker compose`.
- A VPN subscription — NordVPN (access token) and/or ProtonVPN (account credentials).
- A tailnet (official Tailscale, or your own headscale).

## Quick start

```sh
cp .env.example .env
$EDITOR .env                                     # see Configuration below

cp control-panel/config/backends.json.example \
   control-panel/config/backends.json
$EDITOR control-panel/config/backends.json       # name + url per backend

docker compose up -d --build
```

The panel is reachable at `http://<tailscale-hostname>/` and
`https://<tailscale-hostname>/` over your tailnet. With no certs
provided, HTTPS is served with a self-signed cert (browser warning is
expected; see *TLS* below).

## Configuration

### `.env`

| Variable                       | Purpose                                           |
|--------------------------------|---------------------------------------------------|
| `INSTANCE_NAME`                | Suffix on container names; lets you run several stacks side by side. |
| `IP_SUBNET` / `IP_TAILSCALE` / `IP_NORDVPN` / `IP_PANEL` | Static IPs on the internal docker network. |
| `TAILSCALE_AUTH_KEY`           | One-time auth/preauth key. Used only if `tailscale status` reports logged out — safe to leave set across restarts. |
| `TAILSCALE_UP_LOGIN_SERVER`    | Set if you're using headscale or another control server. |
| `NORDVPN_TOKEN`                | NordVPN access token. The wg backend auto-extracts the WireGuard private key on first start. |
| `NORDVPN_ENDPOINT`             | Initial target city (e.g. `San_Francisco`). The control panel can change this at runtime. |
| `NORDVPN_RECONNECT_AFTER_HOURS`| Backend rotates to a fresh server on this cadence. |
| `NORDVPN_TECHNOLOGY` / `NORDVPN_OPENVPN_PROTOCOL` | Only used by the legacy `nordvpn` backend. |

ProtonVPN credentials are not stored in `.env`. Instead, use the **Log in**
button in the control panel to authenticate with your ProtonVPN account over
SRP. Credentials are persisted inside the container's bind-mounted volume and
refreshed automatically.

### `control-panel/config/backends.json`

The panel discovers backends from this file. Entries are arbitrary —
add more, label them, point them at any container that speaks the
v1 API contract.

```json
{
  "backends": [
    { "name": "wg-us",     "label": "NordVPN-WG (US)",  "url": "http://ts-nordvpn-vpn-generic-wg:80" },
    { "name": "wg-uk",     "label": "NordVPN-WG (UK)",  "url": "http://ts-nordvpn-vpn-generic-wg-uk:80" },
    { "name": "protonvpn", "label": "ProtonVPN",         "url": "http://ts-protonvpn-vpn-generic-wg:80" }
  ]
}
```

- `name` — internal id used in API URLs (`/api/v1/backends/<name>/…`).
- `label` — what the dropdown shows; falls back to `name`.
- `url` — base URL of the backend container on the internal docker
  network.

The file is re-read on each request, so edits take effect without a
restart. The panel UI remembers the last-selected backend in
`localStorage` and falls back to the first entry on a fresh browser.

## TLS certs

nginx in the tailscale container always serves both `:80` (plain HTTP)
and `:443` (HTTPS). The cert it uses is decided at startup:

1. **Bring-your-own** — drop both files into `tailscale/cert/` on the
   host. Accepted filenames:
   - certificate: `fullchain.pem` *or* `cert.pem`
   - private key: `privkey.pem` *or* `key.pem`

   The directory is bind-mounted read-only into the container at
   `/etc/nginx/cert/`. The `fullchain.pem`/`privkey.pem` naming matches
   Let's Encrypt; the `cert.pem`/`key.pem` naming matches what
   `tailscale cert` and a lot of manual setups produce. Restart the
   tailscale container after dropping new files in:
   ```sh
   docker compose restart tailscale
   ```

2. **Self-signed fallback** — if either file above is missing, the
   entrypoint generates a self-signed RSA 2048 cert (10-year, CN
   `ts-tailscale-stub`) into `/etc/nginx/cert-stub/` so HTTPS still
   comes up. Persists across restarts of the same container; thrown
   away on `docker compose build tailscale`.

The `tailscale/cert/` directory is gitignored.

## Adding more VPN backends

### Another instance of an existing type

Compose multiple stacks with different `INSTANCE_NAME`s, each running
its own `nordvpn-wg` container, then list them all in
`control-panel/config/backends.json`. The panel selector switches
between them at runtime. Each backend independently connects /
disconnects.

### A whole new VPN provider

Implement [`BACKEND_API.md`](./BACKEND_API.md) (a single Flask app
exposing `/api/v1/{info,status,connect,disconnect,servers,servers/refresh,public-ip}`),
ship it as a container in the same docker network, and add an entry to
`backends.json`. The panel needs no changes.

## Local helper scripts

Anything dropped into `tailscale/scripts/` is bind-mounted to
`/scripts/` inside the tailscale container. The entrypoint runs every
file there with the executable bit set, in alphabetical order, *before*
starting `tailscaled` — useful for host-specific cert distribution,
package installs, etc. Non-executable files (`README.txt`) and
subdirectories are skipped.

The directory is gitignored apart from `README.txt` so your local
helpers don't get committed.

## Common operations

```sh
# Rebuild a single service after editing its Dockerfile/scripts
docker compose build tailscale
docker compose up -d tailscale

# Inspect a backend's API directly
curl -s http://10.1.1.3/api/v1/status

# Watch the tailscale container
docker compose logs -f tailscale

# Get a shell in the tailscale container
docker compose exec tailscale /bin/sh
```
