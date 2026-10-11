# Project status

Last updated: 2026-10-11. Update this file when a list item changes.

## Done

- All eight spec milestones are implemented except the items under "Not done yet": protocols (VLESS + Vision, VMess AEAD), transports (TCP, uTLS, Reality, WebSocket, gRPC), inbounds, DNS forwarder, health checks, stats, groups, rules, RouterOS sync, kill switch, API, UI, RouterOS guide, Dockerfile.
- Image: 2.52 MiB (limit 8 MB). Binary 9.2 MiB raw, 2.5 MiB after UPX. UI 107 KB gzipped (limit 150 KB).
- Checked on this machine only, in a network namespace: REDIRECT installs through nftables and through legacy iptables, all listeners come up, login, import, security headers and connection caps work.
- VLESS was tested against a real Xray v26.3.27 server: Reality + Vision (chrome, firefox, safari), TLS + Vision, TLS without flow. 10 of 10 scenarios passed.
- Security review: seven rounds of parallel reviewers, about 65 findings, all fixed with regression tests.

## Not done yet

In the order I would do them.

1. **Finish the security review loop.** The rule is: keep running rounds until one round finds nothing.
   - Round 7 is incomplete. `sec7-fixes` (3 findings) and `sec7-system` (1 finding) are fixed and pushed. The third reviewer, a stress test of a race-detector build under load, never reported. Run it again: build with `go build -race`, run in `unshare -rn`, then drive SOCKS traffic, DNS queries, config changes and SSE logouts at the same time for 60–90 seconds, and watch for race reports, panics, deadlocks and leaks.
   - Then run round 8 with fresh reviewers. Have one audit the round-7 fixes (commit `6fcdf9a` and the unencrypted badge), especially the relay re-check in `internal/dispatch/relays.go` and the non-blocking WebSocket `Close`.
   - Findings per round so far: about 25, 14, 7, 5, 3, 4, 4.
2. **Milestone 1 on the real router.** Nothing has run on the hAP ax2 yet. Build `make probe-image`, import `dist/v2ray-probe-arm64.tar`, and confirm REDIRECT plus `SO_ORIGINAL_DST` work inside a RouterOS container. This needs router access: an SSH key on the router, then its IP and user. Test steps are in `docs/routeros.md` and in the `probe/main.go` header.
3. **Interop test suite.** `make interop` has a target but `test/interop/` holds only reference files (`testdata/xray-vless.json`, `testdata/harness.go.txt`). Still never tested against a real server: VMess (all ciphers), WebSocket, gRPC (Tun and TunMulti), VLESS over plain TCP, and the Reality fallback path.
4. **Measure on the device.** RSS against the 20 MB target, and the image size after import. Known risk: right after a login the binary used about 50 MB on amd64, mostly the 16 MB scrypt buffer. If it matters on the router, halve the scrypt cost in `internal/api/auth.go`.
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
- Share links with raw Unicode host names are rejected; the punycode form works.
- Not supported and refused at import: VLESS encryption, Reality `pqv`, legacy VMess (`alterId` above 0).
