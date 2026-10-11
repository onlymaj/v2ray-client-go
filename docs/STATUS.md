# Project status

Last updated: 2026-10-12. Update this file when a list item changes.

## Done

- All eight spec milestones are implemented except the items under "Not done yet": protocols (VLESS + Vision, VMess AEAD), transports (TCP, uTLS, Reality, WebSocket, gRPC), inbounds, DNS forwarder, health checks, stats, groups, rules, RouterOS sync, kill switch, API, UI, RouterOS guide, Dockerfile.
- Image: 2.53 MiB (limit 8 MB). Binary 9.2 MiB raw, 2.5 MiB after UPX. UI 107 KB gzipped (limit 150 KB).
- Checked on this machine only, in a network namespace: REDIRECT installs through nftables and through legacy iptables, all listeners come up, login, import, security headers and connection caps work.
- VLESS was tested against a real Xray v26.3.27 server: Reality + Vision (chrome, firefox, safari), TLS + Vision, TLS without flow. 10 of 10 scenarios passed.
- Security review: eight rounds of reviewers, about 85 findings, all fixed with regression tests except the ones listed under "Known limits".
- Stress test (round 7): the `-race` build ran in three network namespaces (LAN clients, the app, a real Xray server with VLESS TCP, VMess TCP, VLESS WS, VMess gRPC+TLS and VLESS TLS+Vision) for 75 s under SOCKS, HTTP CONNECT, transparent, TLS-sniffed and DNS traffic with config changes and SSE logouts at the same time. No races, panics, corrupted transfers, deadlocks or leaks. Repeated for 45 s after the round-8 fixes with the same result.

## Not done yet

In the order I would do them.

1. **Finish the security review loop.** The rule is: keep running rounds until one round finds nothing.
   - Round 7 is complete: its stress test found one issue (a log line for every failed DNS query), now fixed. Round 8 found 19 issues (audit of the round-7 fixes: 4, data path: 8, management plane: 7), so it does not end the loop. All are fixed except the two listed under "Known limits".
   - Run round 9 with fresh reviewers. Have one audit the round-8 fixes, especially: `Dispatcher.Preview` / `Selector.Peek`, rules after the default rule being ignored, plain domain values matching subdomains, the settings validation in `internal/config/validate.go` (it also runs when the config file is loaded), the 256 KiB gRPC stream window, and the DNS cache variant logic in `internal/dns/msg.go`.
   - Run reviewers one at a time on this machine, and tell them to run one command at a time.
   - Findings per round so far: about 25, 14, 7, 5, 3, 4, 5, 19.
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
- Share links with raw Unicode host names are rejected; the punycode form works.
- Not supported and refused at import: VLESS encryption, Reality `pqv`, legacy VMess (`alterId` above 0).
