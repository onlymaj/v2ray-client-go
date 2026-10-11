# v2ray-client-go HTTP API

The web UI (`web/`) uses this contract. The Vite mock (`web/mock/`) implements it, and the Go server must follow it.

## Conventions

- All endpoints are under `/api`. Request and response bodies are JSON (`Content-Type: application/json`).
- Every endpoint except `POST /api/login` requires the session cookie. Without it, the response is `401`.
- Every `POST`, `PUT` and `DELETE` must send `Content-Type: application/json`, including requests with no body (logout, toggle, check, refresh, deletes). Without the header, the response is `415`. This is the CSRF guard: a cross-site form cannot set this header.
- The server may omit fields whose value is empty (`omitempty`). Clients must treat a missing field as its zero value.
- Errors have a non-2xx status with the body `{"error": "human readable message"}`. The UI shows `error` to the user. Status codes in use: `400` validation, `401` no or bad session, `404` unknown id, `405` wrong method, `415` missing JSON content type, `409` conflict (for example, deleting a group that a rule uses).
- A successful request with no body returns `204`.
- Times are RFC 3339 strings in UTC. An empty string `""` means never. Rates are bytes per second. Counters are bytes.
- The server assigns ids (opaque strings). The server ignores ids in POST bodies.

## Auth

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/api/login` | `{"password": "..."}` | `204` + `Set-Cookie` (HttpOnly, SameSite=Strict); `401 {"error":"wrong password"}` |
| POST | `/api/logout` | — | `204`, clears the cookie |
| GET | `/api/me` | — | `200 {"user":"admin"}` or `401` |

The mock accepts the password `admin`.

## Clients

```jsonc
{
  "id": "c1",
  "name": "DE Hetzner Reality",
  "enabled": true,
  "protocol": "vless",          // "vless" | "vmess"
  "address": "91.107.188.24",
  "port": 443,
  "uuid": "28841b8b-5df8-41f1-bc5f-fea0b0a4a9c7",
  "flow": "xtls-rprx-vision",   // vless only: "" | "xtls-rprx-vision"
  "security": "none",           // vless: "none"; vmess cipher: auto|aes-128-gcm|chacha20-poly1305|none|zero
  "network": "tcp",             // "tcp" | "ws" | "grpc"
  "tls": "reality",             // "none" | "tls" | "reality" (reality is vless only)
  "sni": "www.microsoft.com",
  "fingerprint": "chrome",      // "chrome" | "firefox" | "safari" | "random"
  "alpn": ["h2", "http/1.1"],   // tls only
  "allowInsecure": false,       // tls only; never taken from share links or subscriptions
  "publicKey": "...",           // reality: required
  "shortId": "6f42d83d",        // reality: hex, 0-16 chars
  "spiderX": "/",               // reality
  "path": "/ws",                // ws
  "host": "cdn.example.com",    // ws Host header
  "serviceName": "GunService",  // grpc
  "multiMode": false,           // grpc
  "authority": "",              // grpc
  "subscriptionId": "s1",       // optional; set when a subscription created the client
  "untrusted": true,            // read-only; omitted = false. See below.
  "status": {                   // read-only
    "state": "up",              // "up" | "down" | "unknown" | "disabled"
    "tcpMs": 63,                // null when unknown or down
    "delayMs": 197,             // null when unknown or down
    "lastError": "",
    "lastSuccess": "2026-10-08T00:01:02Z",
    "lastCheck": "2026-10-08T00:01:02Z"
  },
  "traffic": { "up": 0, "down": 0, "upRate": 0, "downRate": 0, "conns": 0 }   // read-only
}
```

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/clients` | — | `[Client]` in configured order |
| POST | `/api/clients` | Client without `id`/`status`/`traffic` | `201 Client` |
| GET | `/api/clients/:id` | — | `Client` |
| PUT | `/api/clients/:id` | full Client (the server ignores `status`/`traffic`) | `Client` |
| DELETE | `/api/clients/:id` | — | `204`. The server also removes the client from groups and deletes the rules that target it. Traffic those rules matched then falls through to the later rules. If the default rule was one of them, the rules listed after it are deleted as well and unmatched traffic follows the kill switch. |
| POST | `/api/clients/:id/toggle` | — | `Client` with `enabled` flipped |
| POST | `/api/clients/:id/check` | — | `202`. Starts a health check now. The result arrives as a `ping` event (and a `status` event if the state changes). |
| GET | `/api/clients/:id/link` | — | `{"link": "vless://..."}` (or `vmess://` base64 JSON) |

`untrusted` is true for clients created by `POST /api/import` or by a subscription. Like subscription clients, they may not use private/CGNAT server addresses unless `settings.allowPrivateServers` is on. `POST /api/clients` and `PUT /api/clients/:id` (the editor) always store `untrusted: false`: saving a client is the admin vouching for it. A subscription client stays restricted through its `subscriptionId`, and every refresh sets `untrusted` back to true.

`allowInsecure` turns off TLS certificate verification, so an on-path attacker can read the traffic. Share links cannot set it: the server ignores `allowInsecure`/`insecure` in links and never writes it into exported links. Subscription refreshes always reset it to false. Only the editor can turn it on. VMess allows its chunk nonce to wrap only inside REALITY or TLS with `allowInsecure` off.

The server validates these fields: `name` and `address` must not be empty. `port` must be 1–65535. `uuid` must be a UUID. The enum fields must have one of the values listed above. `reality` requires `vless` and a `publicKey`.

## Import and subscriptions

`POST /api/import` `{"text": "..."}` → `{"added": [Client], "errors": [{"line": 3, "text": "ss://...", "error": "unsupported scheme"}], "skipped": 1}`

- `text` contains one `vless://` or `vmess://` link per line. The server ignores blank lines and lines that start with `#`. If the whole text is base64, the server decodes it first. This is the usual subscription body format.
- `line` is 1-based. `text` is the offending line, truncated to 80 characters.
- Imported clients are `untrusted` and have `allowInsecure` false.
- `skipped` counts links that are already present (same address, port and uuid).

Subscription object: `{"id", "name", "url", "lastUpdate", "count", "lastError"}`

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/subscriptions` | — | `[Subscription]` |
| POST | `/api/subscriptions` | `{"name", "url"}` (if `name` is empty, the server uses the URL host) | `201 Subscription`. The server fetches the URL immediately. |
| DELETE | `/api/subscriptions/:id` | — | `204`. The server also deletes the clients that came from this subscription, with the same cleanup as `DELETE /api/clients/:id`. |
| POST | `/api/subscriptions/:id/refresh` | — | `Subscription`. A fetch failure is not an HTTP error: the response is still `200`, with `lastError` set. |

## Groups

`{"id", "name", "strategy", "members": ["c1", "c2"], "stickyIncludeDest": false, "current": "c1", "traffic": {...}}`

- `strategy` is one of `failover`, `least-ping`, `round-robin` or `sticky`. `members` is ordered: failover tries the members in this order.
- `stickyIncludeDest` applies only to `sticky`. When true, the server pins per (source, destination). When false, it pins per source.
- `current` is the client in use now. It is `""` when no member is healthy. `current` and `traffic` are read-only.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/groups` | — | `[Group]` |
| POST | `/api/groups` | `{"name", "strategy", "members", "stickyIncludeDest"}` | `201 Group` |
| GET | `/api/groups/:id` | — | `Group` |
| PUT | `/api/groups/:id` | same as POST | `Group` |
| DELETE | `/api/groups/:id` | — | `204`; `409` if a rule targets the group |

## Rules

`{"id", "type", "values": ["..."], "target": {"kind", "id"}}`

- `type`: `source` (client IPs or CIDRs), `domain` (sniffed domain. A value matches that name and its subdomains: `ir` matches `x.ir`; `*.example.com` matches the subdomains only), `dest` (destination IP or CIDR), or `default` (matches everything, `values` is `[]`).
- `target.kind`: `client` or `group` (`id` must exist), or `direct` or `block` (`id` is `""`).
- The server evaluates the rules top to bottom, and the first match decides. The `default` rule matches everything, so rules placed after it never match. When no rule matches, the server applies `settings.killSwitch`.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/rules` | — | `[Rule]` in order |
| PUT | `/api/rules` | full ordered `[Rule]`. A rule without an `id` is new. | saved `[Rule]` (new rules get ids). Validation errors are `400` with messages such as `"rule 3: needs at least one value"`. |

## Settings

```jsonc
{
  "ports": { "transparent": 12345, "socks": 1080, "http": 8118, "dns": 5353, "ui": 8080 },  // 1-65535; socks/http/dns accept 0 = disabled
  "healthUrl": "https://www.gstatic.com/generate_204",
  "healthInterval": 30,          // seconds, 5-3600
  "killSwitch": "block",         // "block" | "direct"
  "dnsUpstream": "1.1.1.1:53",   // ip:port (IPv6 as [addr]:port), queried over TCP through the matched client
  "allowPrivateServers": false,  // let untrusted clients use private/CGNAT server addresses; omitted = false
  "routeros": { "enabled": true, "url": "https://172.17.0.1", "user": "v2ray",
                "password": "", "passwordSet": true, "addressList": "no-proxy",
                "certSha256": "" }   // hex SHA-256 of the router's certificate (colons allowed); "" = not verified
}
```

`GET /api/settings` and `PUT /api/settings` (full object) both return the saved settings. A change to `ports.ui` can take effect only after a restart. `dnsUpstream` defaults to `"1.1.1.1:53"`. An invalid value gives `400 {"error":"dnsUpstream must be ip:port"}`. The server also answers `400` when two ports are equal, when `ports.transparent` or `ports.ui` is 0, when `healthInterval` is outside 5–3600, or when `healthUrl` is not an http or https URL (`""` selects the default).

`allowPrivateServers` is off by default. While it is off, untrusted clients (from a subscription or `/api/import`) may not use private (RFC 1918, ULA) or CGNAT server addresses, so a malicious subscription or pasted link cannot aim health checks and connections at LAN devices. Clients saved through `POST /api/clients` or `PUT /api/clients/:id` that have no `subscriptionId` may always use them. Loopback, link-local, the container's own address and its gateway are always refused.

**`routeros.password` is write-only:**

- `GET` always returns `"password": ""`, plus `"passwordSet": true|false` to show whether a password is stored.
- `PUT` with `"password": ""` (or with no `password` field) keeps the stored password. `PUT` with a non-empty value replaces it.
- The server ignores `passwordSet` on `PUT`. Changing `url` or `user` without sending a new password clears the stored password; nothing else does.

## Stats

`GET /api/stats?target=total|client:<id>|group:<id>&range=1m|1h|24h`
→ `{"t": [unix seconds], "up": [bytes/s], "down": [bytes/s], "delay": [ms | null]}`

| range | points | step |
|---|---|---|
| `1m` | 60 | 1 s |
| `1h` | 60 | 1 min (average of the minute) |
| `24h` | 1440 | 1 min |

The arrays are oldest first and all have the same length. `delay` is the health-check delay: `null` when unknown or down, and always `null` for `total`. For a group, `delay` is the delay of its current member.

## Connections

`GET /api/connections` → `[{"id", "src", "dst", "domain", "rule", "client", "group", "up", "down", "start"}]`

- `src`: LAN client IP. `dst`: `ip:port`. `domain`: sniffed domain, or `""`.
- `rule`: id of the matched rule, or `""` when no rule matched and the kill switch decided.
- `client`: id of the proxy client used, `"direct"` for direct traffic, or `""` for blocked traffic.
- `group`: id of the group that chose the client, or `""`.
- The UI resolves names from `/api/clients`, `/api/groups` and `/api/rules`. It shows rules as `#<1-based index> <type> <first value>`, and refetches those lists when it meets an unknown id.
- `up` and `down`: bytes so far. `start`: RFC 3339.
- The UI polls this endpoint every 2 s.

## Events (SSE)

`GET /api/events` returns a `text/event-stream` with named events. The UI opens one EventSource after login.

| event | data | when |
|---|---|---|
| `traffic` | `{"t": 1791417572, "total": {"upRate", "downRate"}, "clients": {"<id>": {"upRate", "downRate", "conns"}}}` | every 1 s |
| `ping` | `{"id", "tcpMs", "delayMs", "state"}` | after each health check |
| `status` | `{"id", "state", "lastError"}` | when a client's state changes (including enable/disable) |
| `group` | `{"id", "current"}` | when a group's current member changes |

The server should send `retry: 3000` first and a comment line (`: ping`) every ~15 s to keep proxies from closing the stream.

## Static files

The server serves `web/dist` at `/`, with `index.html` as the fallback for `/`. Every text asset has a pre-compressed `<file>.gz` beside it. Serve that file with `Content-Encoding: gzip` when the client accepts gzip. Assets under `/assets/` have hashed names and can be cached forever. The UI uses hash routing, so the server needs no rewrites for SPA routes.

## Security responses

- `403` on any `/api/*` request whose `Host` header is not an IP literal, `localhost`, or a name listed in the `UI_HOSTS` env var (DNS-rebinding guard), and on mutating requests whose `Origin` host differs from `Host`.
- `415` on POST/PUT/DELETE without `Content-Type: application/json`.
- `429` (with `Retry-After`) from `POST /api/login`: more than one login in flight per IP, more than 5 attempts per IP per minute, or more than 30 attempts per minute across all IPs.
- `400` from `POST /api/import` with more than 1000 links; the config holds at most 1000 clients in total.
- Changing `settings.routeros.url` or `user` without sending a new password clears the stored password.
- Sessions are bound to the client IP that logged in (a request with the cookie from another IP gets `401`) and expire after 12 hours without use, or 7 days after login at the latest.
