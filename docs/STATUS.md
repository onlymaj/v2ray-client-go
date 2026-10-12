# Project status

Last updated: 2026-10-13

## Done

- All eight spec milestones are implemented except the items under "Not done yet": protocols (VLESS + Vision, VMess AEAD), transports (TCP, uTLS, Reality, WebSocket, gRPC), inbounds, DNS forwarder, health checks, stats, groups, rules, RouterOS sync, kill switch, API, UI, RouterOS guide, Dockerfile.
- Image: 2.54 MiB (limit 8 MB). Binary 9.2 MiB raw, 2.5 MiB after UPX. UI 107 KB gzipped (limit 150 KB).
- Checked on this machine only, in a network namespace: REDIRECT installs through nftables and through legacy iptables, all listeners come up, login, import, security headers and connection caps work.
- VLESS was tested against a real Xray v26.3.27 server: Reality + Vision (chrome, firefox, safari), TLS + Vision, TLS without flow. 10 of 10 scenarios passed.
- Security review: thirteen rounds of reviewers, about 135 findings, all fixed with regression tests except the ones listed under "Known limits".
- Stress test (round 7): the `-race` build ran in three network namespaces (LAN clients, the app, a real Xray server with VLESS TCP, VMess TCP, VLESS WS, VMess gRPC+TLS and VLESS TLS+Vision) for 75 s under SOCKS, HTTP CONNECT, transparent, TLS-sniffed and DNS traffic with config changes and SSE logouts at the same time. No races, panics, corrupted transfers, deadlocks or leaks. Repeated after the round-8 fixes (45 s) and the round-9, round-10, round-11, round-12 and round-13 fixes (30 s each) with the same result.

## Not done yet

In the order I would do them.

1. **Finish the security review loop.** The rule is: keep running rounds until one round finds nothing.
   - Rounds 7 to 13 are complete and their findings fixed (except the items under "Known limits"). Round 13 found 4 issues: audit of the round-12 fixes 1 (low: ALPN ignored for WebSocket without a hint); data path 2 (medium: stalled gRPC streams each hold a 256 KiB window and 512 of them fit under the conn caps, 128 MiB; low: with kill switch `direct`, a group not yet health-checked went direct for the first seconds after every start); management plane 1 (low: the example admin password from the docs was accepted and failed logins were not logged). So the loop is still open.
   - Run round 14 with three fresh reviewers: one audits the round-13 fixes, one takes the data path, one the management plane. For the audit, point at: `deliver`, `stallAfter` and `maxStalled` in `internal/transport/grpc/grpc.go` (at most 32 streams stalled for over 5 s; the next one is ended — check a legitimate paused download is not cut without an attack, and the counter cannot leak), `Selector.Unknown` in `internal/group/group.go` and its use in `route` in `internal/dispatch/dispatch.go` (a group no member of which has reported blocks even with kill switch `direct`), the extra accept errors in `internal/inbound/inbound.go` and `internal/dns/server.go`, and `docPassword`, `minPassword` and `logLogin` in `internal/api/auth.go`. Round 13's data-path reviewer left three things to check on the router, not in review: whether the container netns forwards packets before the REDIRECT is installed or after it is removed on exit, the container's `RLIMIT_NOFILE` (about 1,500 fds are possible at the caps), and how RouterOS enforces `memory-high`.
   - Run reviewers one at a time on this machine, and tell them to run one command at a time and no load tests. Rerun the stress test after data-path fixes (see "Done"; the rig is not in the repo yet).
   - Findings per round so far: about 25, 14, 7, 5, 3, 4, 5, 19, 13, 10, 8, 8, 4.
2. **Milestone 1 on the real router.** Nothing has run on the hAP ax2 yet. Build `make probe-image`, import `dist/v2ray-probe-arm64.tar`, and confirm REDIRECT plus `SO_ORIGINAL_DST` work inside a RouterOS container. This needs router access: an SSH key on the router, then its IP and user. Test steps are in `docs/routeros.md` and in the `probe/main.go` header.
3. **Interop test suite.** `make interop` has a target but `test/interop/` holds only reference files (`testdata/xray-vless.json`, `testdata/harness.go.txt`). Still never tested against a real server: VMess (all ciphers), WebSocket, gRPC (Tun and TunMulti), VLESS over plain TCP, and the Reality fallback path.
4. **Measure on the device.** RSS against the 20 MB target, and the image size after import. On amd64 the unpacked binary with `GOMEMLIMIT=32MiB` used 34 MB RSS at start and 41 MB under the stress load, without growing. A busy connection costs about 50 KB, plus up to 256 KB for a stalled gRPC stream. Known risk: right after a login the binary used about 50 MB on amd64, mostly the 16 MB scrypt buffer. If it matters on the router, halve the scrypt cost in `internal/api/auth.go`.
5. **Verify `docs/routeros.md` on the device.** It was written without a router. Check: property names for container envs and mounts (they changed in RouterOS 7.20), whether a per-container memory limit exists, how the kill-switch fallback route behaves, that NET_ADMIN is granted by default, and the reset-button step for container mode.
6. **README size table.** Run `go run ./tools/sizereport -write` to fill the per-build-tag size breakdown.
7. **Dockerfile.** Never built, because this machine has no Docker.

## Known limits, accepted on purpose

- A login flood can block admin devices that have never logged in, until it stops. Up to 16 devices that logged in before stay exempt.
- Sessions are tied to the client IP. If the admin device's IP changes, it must log in again.
- The RouterOS certificate is verified only when `certSha256` is set.
- `allowInsecure` can still be turned on by hand in the client form. It shows a red badge.
- Clients with no transport encryption are allowed and show a red "unencrypted" badge.
- UDP other than DNS is not proxied. The kill switch and the routing rules cover IPv4 TCP only; `docs/routeros.md` makes disabling or blocking IPv6 a required step.
- A LAN device that sends a forged TLS SNI or HTTP Host matching a `direct` domain rule gets a direct connection to whatever IP it dialed. Direct connections keep the original destination address on purpose; the sniffed name only selects the rule. Reported in round 8, not changed.
- A LAN device with four or more source addresses can hold all 64 UI connection slots and keep admins out until it stops (same class as the login flood above). Reported in round 8, not changed.
- A LAN device that forges many UDP source addresses can fill the DNS handler slots, each source staying within its own limits, and slow name resolution for everyone while it keeps sending. Sources that hold more than their fair share of upstream slots are refused first (round 10), but forged sources cannot be told apart. Reported in round 10, not changed.
- Port changes in the settings (including setting SOCKS, HTTP or DNS to 0) take effect only after a container restart; the listeners are bound once at start. The UI and `web/API.md` say so. Rebinding at runtime was not added (round 11).
- A `dest` rule sees only the IP the device connected to. A proxied connection that carries a host name (sniffed, or given to SOCKS5 or HTTP CONNECT) goes to the proxy server by name, so a `dest` rule cannot block or redirect an address reached that way; a device can forge the name. Direct connections are checked after resolving. Documented in `web/API.md`. Closing it for sniffed names would mean sending the original IP instead of the name whenever a `dest` rule exists (Xray's `routeOnly`). Reported in round 12, not changed.
- Turning RouterOS sync off or renaming the address list leaves the app's entries in the old list. `docs/routeros.md` section 9 gives the command to remove them. Reported in round 12, not changed.
- Share links with raw Unicode host names are rejected; the punycode form works.
- Not supported and refused at import: VLESS encryption, Reality `pqv`, legacy VMess (`alterId` above 0).
