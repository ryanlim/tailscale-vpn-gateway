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
| `IP_PROTONVPN`                 | Static IP for the protonvpn container on the docker network. Required when running that service. |
| `IP_SUBNET_V6`                 | Docker network IPv6 CIDR (e.g. `fd00:cafe:1::/64`). Required for ProtonVPN (IPv6 exit support). |
| `IP_VPN_V6`                    | ProtonVPN container's static IPv6 address within `IP_SUBNET_V6` (e.g. `fd00:cafe:1::10`). |
| `PROTONVPN_WG_CONF`            | Path inside the container to the WireGuard config to use on startup. Defaults to `US/San_Jose/us-ca_10.conf` if unset. |
| `PROTONVPN_CITY`               | Default city to connect to on startup, e.g. `US/San_Jose`. Uses `Country/City_Name` format (underscores for spaces), matching the wireguard directory layout. Persisted across restarts — once set, the container reconnects to the last-used city regardless of `WG_CONF`. |

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

## ProtonVPN first-time setup

The `protonvpn/wireguard/` directory is **gitignored** — it contains your
WireGuard private key and must be populated before the container will start.
The `download_wg_configs.py` script handles this: it authenticates with the
ProtonVPN API, fetches the full server list, and writes a `.conf` file per
server organised as `<COUNTRY>/<City>/<server>.conf`.

### Step 1 — get a WireGuard private key

Download any single WireGuard config from the ProtonVPN portal
(`account.proton.me → Downloads → WireGuard configuration`). ProtonVPN
generates and registers the key pair automatically. Copy the `PrivateKey`
line from the downloaded file — the same key works for every server.

### Step 2 — run the downloader

```sh
cd /path/to/ts-vpn-01

# Authenticate with username/password (SRP — no plain-text password stored):
python3 protonvpn/scripts/download_wg_configs.py \
  -u your@proton.me -p yourpassword \
  --private-key 'YOUR_PRIVATE_KEY_HERE=' \
  --output-dir protonvpn/wireguard

# Or skip SRP auth with a pre-existing session UID + access token:
python3 protonvpn/scripts/download_wg_configs.py \
  --uid <uid> --access-token <token> \
  --private-key 'YOUR_PRIVATE_KEY_HERE=' \
  --output-dir protonvpn/wireguard
```

Useful filters (see `--help` for full list):

```sh
# Only Plus-tier servers
--tier plus

# Only servers under 50% load
--max-load 50

# Single country
--country JP

# Preview what would be written without touching disk
--dry-run
```

### Step 3 — configure `.env` and start

Add the ProtonVPN network variables to `.env` (see the `.env` table above),
then start the service:

```sh
docker compose up -d --build protonvpn
```

The default `WG_CONF` is `US/San_Jose/us-ca_10.conf`. Override it with
`PROTONVPN_WG_CONF` in `.env` to pick a different server on startup.

### Transferring configs to another host

Because the wireguard directory is gitignored, a fresh clone on a new host
starts empty. Either run the downloader again, or rsync from a working host:

```sh
rsync -av /path/to/ts-vpn-01/protonvpn/wireguard/ \
  <other-host>:/path/to/ts-vpn-01/protonvpn/wireguard/
```

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
