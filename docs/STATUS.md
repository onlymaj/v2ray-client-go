# Project status

Last updated: 2026-10-12

## Done

- All eight spec milestones are implemented except the items under "Not done yet": protocols (VLESS + Vision, VMess AEAD), transports (TCP, uTLS, Reality, WebSocket, gRPC), inbounds, DNS forwarder, health checks, stats, groups, rules, RouterOS sync, kill switch, API, UI, RouterOS guide, Dockerfile.
- Image: 2.54 MiB (limit 8 MB). Binary 9.2 MiB raw, 2.5 MiB after UPX. UI 107 KB gzipped (limit 150 KB).
- Checked on this machine only, in a network namespace: REDIRECT installs through nftables and through legacy iptables, all listeners come up, login, import, security headers and connection caps work.
- VLESS was tested against a real Xray v26.3.27 server: Reality + Vision (chrome, firefox, safari), TLS + Vision, TLS without flow. 10 of 10 scenarios passed.
- Security review: eleven rounds of reviewers, about 120 findings, all fixed with regression tests except the ones listed under "Known limits".
- Stress test (round 7): the `-race` build ran in three network namespaces (LAN clients, the app, a real Xray server with VLESS TCP, VMess TCP, VLESS WS, VMess gRPC+TLS and VLESS TLS+Vision) for 75 s under SOCKS, HTTP CONNECT, transparent, TLS-sniffed and DNS traffic with config changes and SSE logouts at the same time. No races, panics, corrupted transfers, deadlocks or leaks. Repeated after the round-8 fixes (45 s) and the round-9, round-10 and round-11 fixes (30 s each) with the same result.

## Not done yet

In the order I would do them.

1. **Finish the security review loop.** The rule is: keep running rounds until one round finds nothing.
   - Rounds 7 to 11 are complete and their findings fixed (except the items under "Known limits"). Round 11 found 8 issues, all low: audit of the round-10 fixes 2 (the 1000-link cap bypassed by one unusable link, the DNS fair share rounding to 0), data path 3 (replies to malformed DNS responses, the Reality fallback fetch cut off by the caller's close, CONNECT host names up to 8 KB), management plane 3 (port changes need a restart but the UI and API.md did not say so, unsupported TLS link settings dropped silently, refresh notes shown as failures). So the loop is still open, but this was the first round with no medium or high finding.
   - Run round 12 with three fresh reviewers: one audits the round-11 fixes, one takes the data path, one the management plane. For the audit, point at: `tooManyLinks` in `internal/api/api.go`, `overShare` and the QR check at the top of `handle` in `internal/dns/server.go`, `transport.ErrConnKept` (returned by Reality's `Wrap` when the spider keeps the conn, honoured in `dialRaw` in `internal/client/client.go`), the 253-byte CONNECT host limit in `internal/inbound/httpproxy.go`, the refused `pcs`/`vcn`/`ech` link settings in `internal/share/share.go`, and the subscription `note` field (Go, UI, mock, API.md). The round-11 management reviewer did not cover `web/mock` against the Go handlers, `internal/web`, or the reconcile half of `internal/routeros/sync.go`.
   - Run reviewers one at a time on this machine, and tell them to run one command at a time and no load tests. Rerun the stress test after data-path fixes (see "Done"; the rig is not in the repo yet).
   - Findings per round so far: about 25, 14, 7, 5, 3, 4, 5, 19, 13, 10, 8.
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
- Share links with raw Unicode host names are rejected; the punycode form works.
- Not supported and refused at import: VLESS encryption, Reality `pqv`, legacy VMess (`alterId` above 0).
