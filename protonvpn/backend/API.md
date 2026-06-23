# NordVPN Control API

Base URL: `http://<host>/api/v1`

An interactive Swagger UI is available at `http://<host>/api/docs`.

---

## Endpoints

### Servers

#### `GET /servers`

Returns the cached list of online NordVPN city endpoints, sorted alphabetically.
The cache is refreshed automatically every 6 hours or on demand via [`POST /servers/refresh`](#post-serversrefresh).

**Response `200`**

```json
[
  { "name": "Germany - Berlin",          "code": "de|berlin"   },
  { "name": "United States - New York",  "code": "us|new_york" }
]
```

| Field  | Type   | Description                                             |
|--------|--------|---------------------------------------------------------|
| `name` | string | Human-readable label: `"Country - City"`                |
| `code` | string | Machine-readable code for use with `POST /connect`      |

**Response `502`** — NordVPN API unreachable.

```json
{ "error": "Failed to fetch server list" }
```

---

#### `POST /servers/refresh`

Invalidates the in-memory cache and fetches a fresh server list from the NordVPN API.

**Response `200`** — same schema as `GET /servers`.

**Response `502`** — NordVPN API unreachable.

```json
{ "error": "Failed to fetch server list" }
```

---

### Connection

#### `GET /status`

Returns the current VPN connection status.

**Response `200` — Connected**

```json
{
  "status":    "Connected",
  "server":    "us8765",
  "city_code": "us|new_york",
  "city":      "United States - New York",
  "details":   "Status: Connected\nHostname: us8765.nordvpn.com\n..."
}
```

**Response `200` — Disconnected**

```json
{
  "status":    "Disconnected",
  "server":    null,
  "city_code": null,
  "city":      null,
  "details":   "Status: Disconnected"
}
```

| Field       | Type           | Description                                               |
|-------------|----------------|-----------------------------------------------------------|
| `status`    | string         | `"Connected"` or `"Disconnected"`                         |
| `server`    | string \| null | Hostname prefix of the active server (e.g. `"us8765"`)    |
| `city_code` | string \| null | Location code matching the format returned by `/servers`  |
| `city`      | string \| null | Human-readable connected location                         |
| `details`   | string         | Raw output from `nordvpn status`                          |

---

#### `POST /connect`

Connects to the NordVPN server in the specified city.
Use [`GET /servers`](#get-servers) to obtain valid `server` codes.

**Request body** (`Content-Type: application/json`)

```json
{ "server": "us|new_york" }
```

| Field    | Type   | Required | Description                                      |
|----------|--------|----------|--------------------------------------------------|
| `server` | string | yes      | Location code in the format `country_code\|city_name` |

**Response `200`**

```json
{
  "message": "VPN connected!",
  "output":  "You are connected to United States #8765 (us8765.nordvpn.com)!"
}
```

**Response `400`** — invalid code or server not found.

```json
{ "error": "The specified server does not exist" }
```

---

#### `POST /disconnect`

Disconnects from the active VPN connection.
Returns `200` whether or not the client was already disconnected.

**Response `200`**

```json
{ "message": "VPN disconnected!", "output": "You are disconnected from NordVPN." }
```

**Response `400`** — unexpected error from the nordvpn CLI.

```json
{ "error": "<raw CLI output>" }
```

---

## Data types

### `City`

```json
{ "name": "United States - New York", "code": "us|new_york" }
```

### `MessageResponse`

```json
{ "message": "VPN connected!", "output": "<raw CLI output>" }
```

### `Error`

```json
{ "error": "<description>" }
```

---

## Server code format

All location codes follow the pattern:

```
{country_code}|{city_name}
```

- `country_code` — two-letter ISO 3166-1 alpha-2 code, **lowercase** (e.g. `us`, `de`, `gb`)
- `city_name` — city name with spaces replaced by underscores, **lowercase** (e.g. `new_york`, `los_angeles`)

Always retrieve codes from `GET /servers` rather than constructing them manually,
as not every city within a country is available.

---

## Examples

### Shell (curl)

```bash
# List available locations
curl http://localhost/api/v1/servers

# Check status
curl http://localhost/api/v1/status

# Connect to a server
curl -X POST http://localhost/api/v1/connect \
     -H "Content-Type: application/json" \
     -d '{"server": "us|new_york"}'

# Disconnect
curl -X POST http://localhost/api/v1/disconnect

# Force-refresh the server list cache
curl -X POST http://localhost/api/v1/servers/refresh
```

### Python (requests)

```python
import requests

BASE = "http://localhost/api/v1"

# List available locations
cities = requests.get(f"{BASE}/servers").json()

# Connect to the first available city
city = cities[0]["code"]
resp = requests.post(f"{BASE}/connect", json={"server": city})
print(resp.json()["message"])

# Poll status
status = requests.get(f"{BASE}/status").json()
print(status["status"], status.get("city"))

# Disconnect
requests.post(f"{BASE}/disconnect")
```
