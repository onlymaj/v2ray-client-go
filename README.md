# v2ray-client-go

A small VLESS/VMess client that runs as a MikroTik RouterOS container. It sends the whole LAN, and the router's own traffic, through one or more proxy clients. It is written by hand in Go and has an embedded Preact web UI. It is built for the **hAP ax2** (linux/arm64, Cortex-A53, 1 GB RAM, 128 MB flash), so the whole image stays **under 8 MB**.

Router setup: **[docs/routeros.md](docs/routeros.md)**.

## Features

- **Protocols:** VLESS (including XTLS Vision flow) and VMess (AEAD only).
- **Transports:** TCP, TLS with uTLS fingerprints (Chrome / Firefox / Safari / randomized), Reality, WebSocket (with or without TLS), and gRPC "gun" (`Tun` and `TunMulti`).
- **Inbounds:**
  - Transparent TCP. The container installs its own nat REDIRECT through nf_tables netlink or legacy x_tables, with no iptables binary, and reads `SO_ORIGINAL_DST`.
  - SOCKS5 and HTTP CONNECT for single hosts.
  - DNS. Queries are sent as DNS over TCP through the selected client.
- **Groups:** failover, least-ping, round-robin and sticky. Switching uses hysteresis so a group does not flap between clients.
- **Rules:** match on source CIDR, destination CIDR, or domain (a name with its subdomains, or `*.name` for the subdomains only, using TLS SNI or HTTP Host sniffing). Each rule targets a client, a group, `direct` or `block`.
- **Health checks** (TCP and real-delay), traffic stats with 24 h / 60 s history, and a live connection table.
- **Share links and subscriptions:** import and export `vless://` / `vmess://` links and subscription URLs.
- **RouterOS integration:** keeps the router's `no-proxy` address list (the proxy server addresses) in sync through the REST API, so the router's own connections to the proxy servers do not loop through the container. The LAN rules deliberately do not use this list, because subscription data feeds it.
- **Kill switch:** `block` (default) or `direct` when no client is available. It covers IPv4 TCP only.

### Out of scope

- UDP proxying. Only TCP and DNS are handled. Other UDP goes direct unless the router blocks it. The RouterOS guide blocks QUIC so browsers fall back to TCP.
- IPv6 transparent proxying. IPv6 traffic bypasses the proxy and the kill switch, so the RouterOS guide disables IPv6 or blocks it for the LAN (a required step).
- Server mode, Trojan, Shadowsocks, Hysteria, TUIC, and xray's JSON config format.
- The Vision splice/direct-copy optimization. Vision padding and unpadding are implemented, and the data is still copied through userspace.

## Hard constraints

- Image tar **< 8 MiB**. `make size` fails otherwise.
- **No xray-core, sing-box, gRPC-Go or protobuf.** The protocols are implemented by hand. Xray is used only as an *external* binary in interop tests.
- Allowed Go dependencies: the standard library, `golang.org/x/crypto` (including `x509roots/fallback` for CA roots in the scratch image), `golang.org/x/net` (http2), and `github.com/refraction-networking/utls` with its transitive dependencies.
- RAM: target about 20 MB RSS. `GOMEMLIMIT=32MiB`, fixed-size stat ring buffers, and a DNS LRU cache capped at 1024 entries.
- Web UI: under 150 KB gzipped, embedded in the binary.

## Build

The build does not need Docker. You need Go (see `go.mod`) and Node 22+ for the UI. Pinned tools are downloaded into `.tools/` on first use and checked against their sha256: `upx` 5.2.1 and `xray` 26.3.27 (for interop tests only).

| Command | What it does |
|---|---|
| `make build-ui` | `npm ci && npm run build` in `web/`. The output is embedded by the Go build. |
| `make build` | Static linux/arm64 binary (`CGO_ENABLED=0 -trimpath -ldflags="-s -w -buildid="`), then `upx --best --lzma` → `dist/v2ray-client-go` |
| `make test` | `go vet` + unit tests (protocol vectors, framing, rules, groups, share links) |
| `make interop` | Runs pinned xray servers on localhost for each protocol × transport and tests the client against them |
| `make image` | Writes the docker-save tar `dist/v2ray-client-go-arm64.tar` with `tools/mkimage`: one layer, scratch base, `GOMEMLIMIT=32MiB`, `CONFIG_DIR=/data` |
| `make size` | `make image`, then fails if the tar is ≥ 8 MiB |
| `make probe-image` | Feasibility probe that reports netfilter support and `SO_ORIGINAL_DST` inside a RouterOS container |
| `go run ./tools/sizereport [-write]` | Size breakdown per build-tag set (see below) |

You can build with only some protocols. Each optional package has its own build tag:

```sh
make build TAGS="vless reality"      # VLESS + Reality only
```

| Tag | Package |
|---|---|
| `vless` | `internal/outbound/vless` (+ Vision) |
| `vmess` | `internal/outbound/vmess` |
| `reality` | `internal/transport/reality` |
| `ws` | `internal/transport/ws` |
| `grpc` | `internal/transport/grpc` |

The default is all five tags. Without a tag, the code for it is not linked in, and clients that need it cannot be used (their dialer fails to build).

### Docker (alternative)

```sh
docker buildx build --platform linux/arm64 \
  -o type=docker,dest=dist/v2ray-client-go-arm64.tar -t v2ray-client-go:latest .
```

Both build stages run on the build host and cross-compile, so QEMU is not needed. `--build-arg TAGS="..."` selects the protocols.

## Configuration

The container is configured with environment variables. Everything else is set in the web UI and stored in `/data/config.json`.

| Variable | Default | |
|---|---|---|
| `ADMIN_PASSWORD` | (required) | UI/API password. It is hashed with scrypt at startup, and login is rate-limited per IP. |
| `CONFIG_DIR` | `/data` | Directory for `config.json`. Writes are atomic (temp file + rename) and happen only when something changes. |
| `GOMEMLIMIT` | `32MiB` | Go heap soft limit |
| `ROS_URL` / `ROS_USER` / `ROS_PASS` | | Optional RouterOS REST credentials for the `no-proxy` sync. `ROS_PASS` is used only together with `ROS_URL`. Set `routeros.certSha256` too, or the router's certificate is not verified. |
| `UI_HOSTS` | | Comma-separated host names allowed in the UI/API `Host` header (IP literals always are); DNS-rebinding guard |

`config.json` holds `clients`, `groups`, `rules`, `subscriptions` and `settings`. Default settings:

| Setting | Default |
|---|---|
| `ports.transparent` / `socks` / `http` / `dns` / `ui` | `12345` / `0` / `0` / `53` / `80` (0 disables; SOCKS and HTTP have no authentication, so they are off by default) |
| `healthUrl`, `healthInterval` | `https://www.gstatic.com/generate_204`, 60 s |
| `killSwitch` | `block` (or `direct`) |
| `dnsUpstream` | `1.1.1.1:53`, queried over TCP through the proxy |
| `routeros` | `url` `https://172.17.0.1`, `addressList` `no-proxy`, `certSha256` empty (no verification), disabled until configured |
| `allowPrivateServers` | `false`: subscription clients may not use private/CGNAT server addresses (manually added clients may) |

On first start, the config has an empty failover group called `default` and one default rule that points to it.

## API

The UI is a client of a JSON HTTP API on the UI port. It covers CRUD for clients, groups, rules and subscriptions, settings, stats, the live connection table, and server-sent events for live updates. Authentication uses a session cookie (HttpOnly, SameSite=Strict, bound to the client IP). The UI is served with a strict Content-Security-Policy (no inline scripts, no framing). See [web/API.md](web/API.md) for the endpoints and payloads.

## Architecture

```
cmd/v2ray-client-go/         wiring, env, signals
internal/config/          schema, defaults, validation, atomic JSON store
internal/inbound/         transparent (SO_ORIGINAL_DST), socks5, http connect, dns
internal/netfilter/       REDIRECT install via nf_tables netlink or legacy setsockopt
internal/sniff/           TLS SNI / HTTP Host
internal/router/          rule engine (CIDR, domains with subdomains)
internal/group/           failover, least-ping, round-robin, sticky + hysteresis
internal/outbound/        Dialer interface + registry, direct
  vless/ vmess/           protocol dialers                       [tags vless, vmess]
internal/transport/       Layer interface + registry, tcp, tls (uTLS)
  reality/ ws/ grpc/      transports                              [tags reality, ws, grpc]
internal/share/           share links, subscriptions
internal/events/          event bus (UI live updates)
internal/web/             embedded, gzipped UI
web/                      Preact + Vite + uPlot source
tools/mkimage/            docker-save tar writer (no Docker needed)
tools/sizereport/         size breakdown per tag set
test/interop/             tests against a real xray binary (tag interop)
probe/                    RouterOS feasibility probe
```

A connection takes this path: inbound (transparent/SOCKS/HTTP) → sniff → router (rules) → group selection → `outbound.Dialer` → a stack of `transport.Layer` (TCP → TLS/Reality → WS/gRPC) → protocol framing (VLESS/VMess). Each tagged package registers itself in `init()`.

## Size breakdown

`go run ./tools/sizereport -write` rebuilds every tag set and replaces the section below.

<!-- sizereport:start -->
_Not generated yet. Run `go run ./tools/sizereport -write`._
<!-- sizereport:end -->

## License

TBD.
