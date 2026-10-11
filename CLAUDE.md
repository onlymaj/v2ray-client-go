# CLAUDE.md

Guidance for Claude Code when working in this repository. Current status and the open work list are in `docs/STATUS.md`. Read it first.

## Project

v2ray-client-go: a tiny VLESS/VMess client with a web UI that runs as a MikroTik RouterOS container on a hAP ax2 (linux/arm64, 1 GB RAM, 128 MB flash). It routes the whole LAN and the router's own traffic through one or more proxy clients. Module `github.com/onlymaj/v2ray-client-go`, remote `https://github.com/onlymaj/v2ray-client-go` (public), branch `main`.

## Hard constraints

- The final container image must stay under 8 MB. Run `make size` after every change that could affect it and report the number. If a change would push it over, stop and propose options.
- Never import xray-core, v2ray-core, sing-box, `google.golang.org/grpc`, gVisor, or any protobuf library. Protocols are written by hand. Xray is a reading reference and a test dependency only.
- Allowed dependencies: Go stdlib, `golang.org/x/crypto` (including `x509roots/fallback`), `golang.org/x/net` (`http2`, `http/httpguts`, `netutil`), `github.com/refraction-networking/utls`. Ask before adding anything else.
- Runtime budget: `GOMEMLIMIT=32MiB`, target under 20 MB RSS. Metrics stay in RAM. Write to disk only when the config changes.
- Scope: VLESS (with xtls-rprx-vision) and VMess AEAD, over TCP, uTLS, Reality, WebSocket and gRPC. Out of scope: Trojan, Shadowsocks, Hysteria2, TUIC, GeoIP/GeoSite, UDP proxying (DNS is the only UDP handled). Do not add features outside scope without asking.
- The name is v2ray-client-go everywhere: module, binary, image, UI title, docs. Do not introduce any other product or organisation name.

## Commands

The toolchain needs no Docker. `make` downloads pinned UPX and Xray into `.tools/` and checks their sha256.

```bash
make build-ui   # web/: npm ci + build, fails over 150 KB gzipped
make build      # embed UI, build arm64 binary, UPX
make image      # dist/v2ray-client-go-arm64.tar (docker-save format, no Docker needed)
make size       # fails if the image is over 8 MB
make test       # go vet + go test with all build tags
make probe-image # M1 probe image for the router

# What to run before every commit:
T="vless vmess reality ws grpc"
GOOS=linux GOARCH=arm64 go vet -tags "$T" ./... && go test -race -tags "$T" ./...
```

Build tags `vless vmess reality ws grpc` gate each protocol and transport. Always pass all five unless you are measuring sizes.

Run the real binary locally in an isolated network namespace (it binds ports 80, 53 and 12345 and installs a REDIRECT rule, so never run it directly on this host):

```bash
go build -tags "vless vmess reality ws grpc" -o /tmp/nv2 ./cmd/v2ray-client-go
unshare -rn sh -c 'ip link set lo up; ADMIN_PASSWORD=secret CONFIG_DIR=/tmp/nv2cfg /tmp/nv2'
```

UI with mock data: `cd web && npx vite --host 0.0.0.0 --port 5174` (password `admin`). The mock API in `web/mock/` must match `web/API.md` and the Go server.

## Architecture

- `cmd/v2ray-client-go/main.go` wires everything and holds all cross-package adapters. Packages depend on each other through small interfaces or function arguments that main fills in.
- `internal/config`: schema, validation, atomic store. Subscribers get the latest snapshot, one notification at a time.
- `internal/outbound/{vless,vmess}`, `internal/transport/{tls,reality,ws,grpc}`: protocols and transports, registered in `init()` behind build tags.
- `internal/client`: builds a dialer from a config client (TCP → TLS/Reality → WS/gRPC → VLESS/VMess), with the server-address guard, warm pool and retry.
- `internal/dispatch`: rules → group pick → kill switch → dial → relay. Tracks established relays and cuts them when their route changes.
- `internal/inbound`: transparent (SO_ORIGINAL_DST), SOCKS5, HTTP CONNECT, with connection caps.
- `internal/dns`: forwarder with a per-route cache, per-source limits and connection pooling.
- `internal/netfilter`: installs the nat PREROUTING REDIRECT itself (nftables netlink, or legacy iptables setsockopt). No iptables binary.
- `internal/netguard`: which addresses may never be dialed, and which sources are the container or its gateway.
- `internal/routeros`: keeps the `no-proxy` address list in sync over the REST API.
- `internal/api`, `internal/web`: JSON API, auth, SSE, embedded UI. `web/`: Preact + Vite + shadcn/ui + uPlot.
- `internal/health`, `internal/stats`, `internal/group`, `internal/router`, `internal/sniff`, `internal/share`, `internal/events`, `internal/pool`.

## Conventions

- Comment protocol code with the spec or Xray source file it mirrors. Xray reference source, read-only: `~/go/pkg/mod/github.com/xtls/xray-core@v1.260327.0`.
- Every security fix gets a regression test. Name the round or the scenario in the test comment.
- Settings the client cannot honour are refused with a clear error, never silently dropped (see `share.Validate`).
- Anything from a share link or subscription is untrusted until the admin saves it through the form.
- Keep `docs/routeros.md`, `web/API.md` and `README.md` in step with code changes.
- Commit subjects are short and imperative. Push with plain `git push`: `origin` is HTTPS and this repo uses `gh`'s credentials (SSH to GitHub is not set up on this machine).
- In shell commands never use `pkill -f` with a pattern that can match your own command line. Kill by PID.
