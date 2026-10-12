# Running v2ray-client-go on RouterOS

This guide targets a MikroTik **hAP ax2** (arm64, 1 GB RAM, 128 MB flash, no USB) on **RouterOS v7**. The same steps work on any arm64 RouterOS v7 device with the container package. Every block below can be pasted into a terminal (WinBox → New Terminal, or SSH).

The result looks like this:

```
LAN hosts ──┐                                ┌─> proxy server (VLESS/VMess) ─> internet
            ├─ router ── br-containers ── veth-v2ray (172.17.0.2, container)
router  ────┘   (mangle: mark-routing                │
 itself          to-v2ray → 172.17.0.2)             └─> direct (rules = direct)
```

- New LAN TCP connections that are not going to the router or to a private/reserved address get the routing mark `to-v2ray`. The router then sends them to the container instead of the WAN gateway.
- Inside its own network namespace, the container installs a nat `PREROUTING` REDIRECT, either through nf_tables over netlink or through legacy x_tables setsockopt. No iptables binary is involved. The REDIRECT sends that TCP to the transparent port (12345). The app reads the original destination with `SO_ORIGINAL_DST` and forwards the connection through a proxy client, a group, directly, or not at all (block), depending on your rules.
- The container's own outbound connections leave through `br-containers` without a routing mark, so they never loop back into it.

Examples use these addresses. Change them to match your network:

| Item | Value |
|---|---|
| LAN subnet | `192.168.88.0/24` (defconf), interface list `LAN` |
| WAN interface list | `WAN` |
| Container bridge / router side | `br-containers`, `172.17.0.1/24` |
| Container veth | `veth-v2ray`, `172.17.0.2/24`, gateway `172.17.0.1` |

---

## 1. Enable container mode (one time)

Container support is off by default. Turning it on needs physical access to the router, which stops a remote attacker from enabling it.

```routeros
/system/device-mode/update container=yes
```

The command waits for confirmation. **Within 5 minutes, briefly press the reset (mode) button, or cold-reboot the router** (pull the power plug; a soft `/system reboot` does not count). Check the result after the router comes back:

```routeros
/system/device-mode/print
# container: yes
```

## 2. Install the container package

1. Download the **Extra packages** zip for **ARM64** from mikrotik.com/download. It must be the same version as your RouterOS (`/system/resource/print`).
2. Upload `container-7.xx-arm64.npk` to the router's Files: drag it into WinBox → Files, or use `scp container-7.xx-arm64.npk admin@192.168.88.1:/`.
3. Reboot, then check:

```routeros
/system/reboot
# after reboot:
/system/package/print where name=container
```

You do not need a registry (`/container/config registry-url`). The image is uploaded as a file.

## 3. Container network: veth + bridge

```routeros
/interface/veth/add name=veth-v2ray address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/add name=br-containers comment="v2ray-client: container bridge"
/interface/bridge/port/add bridge=br-containers interface=veth-v2ray
/ip/address/add address=172.17.0.1/24 interface=br-containers
```

- **Do not** add `br-containers` to the `LAN` interface list. The mangle rules below match `in-interface-list=LAN`. If the container's own outbound traffic counted as LAN, it would be routed back into the container and loop forever.
- The defconf `srcnat` masquerade (`out-interface-list=WAN`) already covers `172.17.0.0/24`, so the container can reach the internet with no extra NAT rule.

The defconf firewall drops input from anything that is not LAN. Allow the container to reach the router's DNS and REST API (section 9):

```routeros
/ip/firewall/filter
add chain=input action=accept in-interface=br-containers src-address=172.17.0.2 dst-address=172.17.0.1 protocol=udp dst-port=53 \
    comment="v2ray-client: container -> router DNS" place-before=[find comment="defconf: drop all not coming from LAN"]
add chain=input action=accept in-interface=br-containers src-address=172.17.0.2 dst-address=172.17.0.1 protocol=tcp dst-port=53,443 \
    comment="v2ray-client: container -> router DNS/REST" place-before=[find comment="defconf: drop all not coming from LAN"]
```

`in-interface=br-containers` matters: without it, a LAN host that forges the source address `172.17.0.2` also matches these rules.

**Required: drop forged container-subnet sources.** The container trusts the router address `172.17.0.1` more than a LAN device (for example, DNS queries from it are not rate-limited, because under DNS Option B every LAN query comes from the router). RouterOS does not filter forged source addresses by default (`rp-filter=no`), so drop anything that claims a `172.17.0.0/24` source but does not arrive on `br-containers`:

```routeros
/ip/firewall/raw
add chain=prerouting action=drop src-address=172.17.0.0/24 in-interface=!br-containers \
    comment="v2ray-client: drop forged container-subnet sources"
```

If your firewall is not defconf, put these rules above whatever rule drops input from non-LAN interfaces.

## 4. Storage: tmpdir, root-dir, /data mount

The hAP ax2 has only **128 MB of internal flash** and no USB, and RouterOS plus the wifi packages already use a large share of it. Run `/system/resource/print` and look at `free-hdd-space` before you continue. You need about 3× the image size free while importing: the tar, the extraction temp files and the extracted root. The image is under 8 MB, so about 25 MB is enough.

```routeros
/container/config/set tmpdir=v2ray/tmp
/container/mounts/add name=v2ray-data src=/v2ray/data dst=/data
```

- `tmpdir` holds the layers while they are extracted. Keep it on internal flash; the folder is created automatically.
- `/data` holds `config.json` (clients, groups, rules, settings). The mount keeps it when you re-import the image to upgrade. The app writes it only when something changes, using a temp file and a rename, so normal running causes little flash wear.

## 5. Environment variables

```routeros
/container/envs
add name=v2ray key=ADMIN_PASSWORD value="change-me-long-random"
add name=v2ray key=ROS_URL  value="https://172.17.0.1"
add name=v2ray key=ROS_USER value="v2ray"
add name=v2ray key=ROS_PASS value="another-long-random"
```

Replace both passwords before you paste this. The app refuses to start with `change-me-long-random` as `ADMIN_PASSWORD`, and logs a warning for one shorter than 10 characters. Failed logins are written to the container log with the source address.

| Variable | Required | Meaning |
|---|---|---|
| `ADMIN_PASSWORD` | yes | Web UI / API login. The app refuses to start without it. |
| `ROS_URL`, `ROS_USER`, `ROS_PASS` | no | REST access to this router, used to keep the `no-proxy` address list in sync (section 9). Leave them out to manage the list by hand. If `ROS_PASS` is set, `ROS_URL` must be set too; otherwise sync stays off, so that a UI user cannot point the URL at another host and capture the password. |
| `UI_HOSTS` | no | Comma-separated host names allowed in the `Host` header of UI/API requests. IP literals are always allowed and any other name is rejected, which blocks DNS-rebinding attacks from web pages a LAN user opens. Set it only if you reach the UI through a name, for example `UI_HOSTS=v2ray.lan`. |
| `CONFIG_DIR` | preset `/data` | Where `config.json` lives. |
| `GOMEMLIMIT` | preset `32MiB` | Go heap soft limit. Raise it only if you set a higher container memory limit. |

**These values are stored in plaintext in the router configuration.** Any router user with the `read` policy can see them with `/container/envs/print`, and they appear in `/export` output and in `/system/backup` files. So:

- Use long random passwords that are not used anywhere else, and a different one for each variable.
- Use `/export hide-sensitive` (the default on recent v7) when you share an export, and keep backup files private.
- Do not give router accounts the `read` policy unless they need it.

> RouterOS 7.20 and later renamed these properties: envs and mounts use `list=` instead of `name=`, and `/container/add` takes `envlists=` / `mountlists=`. Run `/container/envs/add ?` to see which form your version accepts.

## 6. Import and start the container

Build the image on your workstation (`make image`, see the README) and upload it:

```sh
scp dist/v2ray-client-go-arm64.tar admin@192.168.88.1:/
```

```routeros
/container/add file=v2ray-client-go-arm64.tar interface=veth-v2ray \
    root-dir=v2ray/root mounts=v2ray-data envlist=v2ray \
    dns=172.17.0.1 hostname=v2ray logging=yes start-on-boot=yes \
    comment="v2ray-client-go"
```

- `dns=172.17.0.1`: the container resolves names (proxy server hostnames, subscription URLs) through the router's resolver, **never through its own DNS inbound**. Its DNS inbound sends queries through a proxy client. If the container resolved through itself, it could not look up the proxy server's hostname before it had a working proxy, which is a deadlock. See section 8 for the matching router setting.
- `logging=yes` copies the app's stdout and stderr into the RouterOS log (topic `container`).

Extraction takes a few seconds. Wait until the status changes from `extracting` to `stopped`, then free the flash and start the container:

```routeros
/container/print
/file/remove v2ray-client-go-arm64.tar
/container/start [find comment="v2ray-client-go"]
```

The container runs as root in its own network namespace. It needs `NET_ADMIN` there to install the REDIRECT rule, and RouterOS grants that by default. If the log shows `netfilter: ... operation not permitted`, run the M1 probe image (`make probe-image`) to see which netfilter interfaces the kernel exposes.

### Memory limit

The app targets about 20 MB RSS (the UPX-unpacked text plus a heap capped by `GOMEMLIMIT=32MiB`). A 64 MB limit leaves headroom:

```routeros
# newer v7: per-container limit
/container/set [find comment="v2ray-client-go"] memory-high=64M
# older v7 (no per-container property): limit for all containers together
/container/config/set ram-high=64M
```

The property name depends on the version. Run `/container/set ?` to check. Restart the container after you change it.

### Upgrading

Stop the container, remove it (`/data` stays on the mount), upload the new tar and run `/container/add` again with the same arguments. Delete the old `v2ray/root` directory first if flash is tight.

## 7. Policy routing

### Routing table and route to the container

```routeros
/routing/table/add name=to-v2ray fib
/ip/route/add dst-address=0.0.0.0/0 gateway=172.17.0.2 routing-table=to-v2ray \
    distance=1 check-gateway=ping comment="v2ray-client: via container"
```

`check-gateway=ping` marks the route as inactive when the container stops answering. What happens next depends on the kill switch choice in section 10.

### Address lists

```routeros
/ip/firewall/address-list
add list=lan address=192.168.88.0/24
add list=v2ray-bypass address=0.0.0.0/8
add list=v2ray-bypass address=10.0.0.0/8
add list=v2ray-bypass address=100.64.0.0/10
add list=v2ray-bypass address=127.0.0.0/8
add list=v2ray-bypass address=169.254.0.0/16
add list=v2ray-bypass address=172.16.0.0/12
add list=v2ray-bypass address=192.168.0.0/16
add list=v2ray-bypass address=224.0.0.0/4
add list=v2ray-bypass address=240.0.0.0/4
```

- `v2ray-bypass` is static and maintained by you. It holds private, CGNAT, multicast and reserved ranges, plus anything else that must never go through the proxy, such as the endpoints of VPN tunnels the router itself opens.
- `no-proxy` belongs to the app (the setting `routeros.addressList`, default `no-proxy`). The app keeps it in sync through the REST API: the addresses of the enabled proxy servers (after re-resolving hostnames, at most 8 addresses per name). Keep your own entries in `v2ray-bypass` so a sync never removes them. If you do not enable REST sync and you route router-originated traffic (below), create `no-proxy` by hand and **at least add every proxy server IP to it**.

`v2ray-bypass` applies to LAN and router traffic. `no-proxy` applies **only to router-originated traffic** (the `output` chain): there it stops the router's connections to the proxy servers from looping back into the container. The container's own connections need no such exclusion, because they do not enter from `LAN`. (A malicious subscription can still make the router's own connections to an IP it lists go out directly. That affects only router-originated traffic.)

**Do not use `no-proxy` in the LAN rules.** Its content comes partly from data the app does not control: server addresses in subscriptions. A malicious subscription could list any IP as a "server" and so make LAN traffic to that IP skip the container, its rules and the kill switch. LAN traffic that your rules send `direct` still goes through the container, which sends it out directly. That costs one extra hop on the router.

### Mangle: LAN traffic

```routeros
/ip/firewall/mangle
add chain=prerouting action=jump jump-target=v2ray-new in-interface-list=LAN \
    protocol=tcp connection-state=new connection-mark=no-mark comment="v2ray-client: classify new LAN TCP"
add chain=prerouting action=mark-routing new-routing-mark=to-v2ray passthrough=no \
    in-interface-list=LAN connection-mark=v2ray comment="v2ray-client: route LAN via container"

add chain=v2ray-new action=return dst-address-type=local       comment="v2ray-client: to the router itself"
add chain=v2ray-new action=return dst-address-list=v2ray-bypass comment="v2ray-client: private/reserved"
add chain=v2ray-new action=mark-connection new-connection-mark=v2ray passthrough=yes comment="v2ray-client: proxy this connection"
```

- The exclusions run only for the **first packet** of a connection. The decision is stored as a connection mark, so later changes to the address lists do not move live connections and break them halfway.
- There is deliberately no `no-proxy` exclusion here (see "Address lists" above). If you set up an older version of this guide, remove that rule: `/ip/firewall/mangle/remove [find chain=v2ray-new dst-address-list=no-proxy]`.
- Only TCP is marked. The container proxies TCP only. UDP sent to it would be dropped (see "UDP" below).
- The `lan` list is not used above, which keeps `in-interface-list=LAN`. If you prefer to match by source, replace `in-interface-list=LAN` with `src-address-list=lan` in both prerouting rules.

### Mangle: router-originated traffic

Connections the router opens itself (`/tool fetch`, the package updater, cloud features, TCP VPN clients) pass through the `output` chain:

```routeros
/ip/firewall/mangle
add chain=output action=jump jump-target=v2ray-out protocol=tcp \
    connection-state=new connection-mark=no-mark comment="v2ray-client: classify new router TCP"
add chain=output action=mark-routing new-routing-mark=to-v2ray passthrough=no \
    connection-mark=v2ray-out comment="v2ray-client: route router TCP via container"

add chain=v2ray-out action=return dst-address-type=local        comment="v2ray-client: local"
add chain=v2ray-out action=return dst-address-list=v2ray-bypass comment="v2ray-client: private/reserved"
add chain=v2ray-out action=return dst-address-list=no-proxy      comment="v2ray-client: app-managed direct list"
add chain=v2ray-out action=mark-connection new-connection-mark=v2ray-out passthrough=yes comment="v2ray-client: proxy this connection"
```

- The container's own traffic is **forwarded** traffic, not router-originated, so it never reaches `output`. No exclusion is needed for it here.
- The router's management sessions (WinBox, SSH, WebFig, API) are connections **to** the router, so their replies are not `connection-state=new` in `output`. They are never marked.
- Exclude the server address of any TCP tunnel the router opens itself (SSTP, OpenVPN-TCP) by adding it to `v2ray-bypass`. Otherwise the tunnel runs through the proxy.
- If you only want the LAN proxied, leave this block out.

### Fasttrack must skip proxied connections

Fasttracked packets skip mangle, so they would lose their routing mark after the first few packets. Limit the defconf fasttrack rule to unmarked connections:

```routeros
/ip/firewall/filter/set [find action=fasttrack-connection] connection-mark=no-mark
```

### Block QUIC (UDP 443)

Browsers try HTTP/3 over UDP 443 first. UDP is not proxied, so QUIC would go out directly and bypass the proxy. Reject it so browsers fall back to TCP straight away:

```routeros
/ip/firewall/filter/add chain=forward action=reject reject-with=icmp-port-unreachable \
    in-interface-list=LAN protocol=udp dst-port=443 comment="v2ray-client: no QUIC, force TCP" \
    place-before=[find action=fasttrack-connection]
```

A `reject` is better than a `drop` here because browsers fall back immediately instead of waiting for a timeout.

### IPv6 (required)

**This client proxies IPv4 only.** Every rule above (mangle, QUIC reject, DNS dst-nat, kill switch) is IPv4. If your ISP gives you IPv6, LAN hosts prefer it, and all IPv6 traffic (web, QUIC, DNS) goes out directly with your real address, even with the strict kill switch. Do one of the following before you rely on the proxy:

- **Disable IPv6** (simplest; a reboot may be needed):

  ```routeros
  /ipv6/settings/set disable-ipv6=yes
  ```

- **Or keep IPv6 on the router but block it for the LAN.** Drop forwarded IPv6 from the LAN and stop advertising IPv6 DNS servers:

  ```routeros
  /ipv6/firewall/filter/add chain=forward action=reject reject-with=icmp-no-route \
      in-interface-list=LAN comment="v2ray-client: no direct IPv6 from LAN" place-before=0
  /ipv6/nd/set [find] advertise-dns=no
  /ipv6/dhcp-server/remove [find]
  ```

  `reject` makes clients fall back to IPv4 at once. Check from a LAN host with `curl -6 https://ifconfig.me`; it must fail.

### UDP

Only TCP and DNS are handled. Other UDP from the LAN (games, VoIP, WebRTC, WireGuard, and QUIC if you do not block it) **goes out directly through the WAN with your real IP**. You can block it with a forward rule, but most of those applications then stop working, so decide based on what you need. UDP proxying is out of scope for this client.

## 8. DNS

The container runs a DNS inbound on port 53. It answers queries by sending them as DNS over TCP to `settings.dnsUpstream` (default `1.1.1.1:53`) through the client that your rules pick. This avoids poisoned plaintext answers from the ISP. You can get LAN DNS to it in two ways. **Use option A** unless you have a reason not to.

### Option A (recommended): dst-nat LAN DNS to the container

```routeros
/ip/firewall/nat
add chain=dstnat action=dst-nat in-interface-list=LAN protocol=udp dst-port=53 \
    to-addresses=172.17.0.2 to-ports=53 comment="v2ray-client: LAN DNS -> container"
add chain=dstnat action=dst-nat in-interface-list=LAN protocol=tcp dst-port=53 \
    to-addresses=172.17.0.2 to-ports=53 comment="v2ray-client: LAN DNS -> container"
```

- This catches LAN clients whichever server they are configured with: the router, 8.8.8.8, or anything else.
- The router's own resolver (`/ip dns`) stays on its normal upstream. The container uses it through `dns=172.17.0.1`, so nothing loops: LAN → container → proxy, and container → router → ISP.
- Trade-off: LAN clients no longer see the router's static DNS entries or DHCP hostnames (`/ip dns static`). Names the router itself resolves (NTP, updates) are not protected.

### Option B: router forwards to the container

```routeros
/ip/dns/set servers=172.17.0.2 allow-remote-requests=yes
```

- LAN clients keep using the router (the defconf DHCP server hands it out). They keep the router's cache and static entries, and the router's own lookups are also protected.
- **The container must then not use the router as its resolver.** Otherwise the router asks the container, the container asks the router, and so on. Recreate the container with `dns=` set to a public resolver, for example `dns=1.1.1.1`. That traffic goes out directly because it comes from the container. The container only resolves proxy server and subscription hostnames there.
- Those lookups are plain UDP, so your ISP sees which proxy hostnames you use and can block or poison them. With option B, **enter proxy servers by IP address**, not hostname.
- If the container is down, the router cannot resolve any names at all: no NTP and no updates. Option A breaks only LAN DNS. You can add a second server (`servers=172.17.0.2,1.1.1.1`), but RouterOS may query both, which leaks lookups.

In both options the router's input firewall must accept DNS from LAN (defconf already does). For option A, the forward chain must allow LAN → 172.17.0.2:53. Defconf allows that.

## 9. RouterOS REST API for no-proxy sync

The app can update the `no-proxy` address list through the REST API. **This is optional.** RouterOS cannot limit a user to one address list: the `write` policy lets the user change any setting except users, including firewall rules, routes and scripts. Whoever controls the container (it runs as root and parses data from remote servers) then controls the router. If that risk is too high for you, skip this section and keep `no-proxy` up to date by hand.

If you enable it, give the app a dedicated user with as few rights as RouterOS allows, reachable only from the container:

```routeros
# self-signed certificate for www-ssl
/certificate/add name=v2ray-api common-name=172.17.0.1 subject-alt-name=IP:172.17.0.1 \
    key-usage=digital-signature,key-encipherment,tls-server days-valid=3650
/certificate/sign v2ray-api
# REST only from the container and your admin hosts (replace 192.168.88.10)
/ip/service/set www-ssl certificate=v2ray-api disabled=no address=172.17.0.2/32,192.168.88.10/32

# limited group + user, login only from the container
/user/group/add name=v2ray-api policy=read,write,rest-api comment="v2ray-client: no-proxy sync"
/user/add name=v2ray group=v2ray-api password="another-long-random" address=172.17.0.2/32
```

- Do **not** add the `api` policy. It opens the binary API (port 8728) to this user, which REST does not need. If your build has no `rest-api` policy, update RouterOS.
- `address=172.17.0.2/32` on the user means the credentials work only from the container, even if they leak. Without `address=` on `www-ssl`, enabling it also opens WebFig over HTTPS to the whole LAN.
- **Alternative: plain HTTP on the container bridge only.** Enable `www` with `address=172.17.0.2/32`, set `ROS_URL=http://172.17.0.1`, and accept TCP 80 from `172.17.0.2` instead of 443 in the input rule from section 3 (keep `in-interface=br-containers`). The traffic never leaves the router, but the password crosses the veth in cleartext. Do not open `www` to the LAN for this purpose.

### Pin the certificate (`certSha256`)

The certificate is self-signed, and the scratch image has no trust store that could check it. Without a pin the app accepts **any** certificate and logs a warning at startup, so anything that can answer on `172.17.0.1:443` gets the REST password. Set `settings.routeros.certSha256` (UI: Settings → RouterOS) to the SHA-256 of the certificate, as 64 hex characters:

```routeros
/certificate/print proplist=name,fingerprint where name=v2ray-api
```

RouterOS shows the SHA-256 of the certificate as `fingerprint`. To double-check from an admin host listed in `www-ssl address=`:

```sh
openssl s_client -connect 172.17.0.1:443 </dev/null 2>/dev/null \
  | openssl x509 -outform der | sha256sum
```

Both must print the same value. The app then rejects any other certificate, even if it is otherwise valid. When you renew or replace the certificate, update the pin, or the sync stops (the container log shows the error).

Configure the same URL, user, password and pin in the UI (Settings → RouterOS), or pass the URL and credentials as `ROS_*` envs (section 5). If you later change the URL or the user in the UI, enter the password again: the app clears the stored one so it is never sent to another host or account. Check that it works:

```routeros
/ip/firewall/address-list/print where list=no-proxy
```

If you turn the sync off or change the address-list name, the app stops looking at the old list and the entries it created stay there. The router's own connections to those addresses keep going out direct. Remove them by hand (the app marks its entries with a comment):

```routeros
/ip/firewall/address-list/remove [find list=no-proxy comment="v2ray-client-go"]
```

## 10. Kill switch

What should happen to proxied traffic when no proxy works? The app and the router each handle one half of the answer.

**Inside the app** (`settings.killSwitch`, for when the container runs but every client in the selected group is down):

- `block` (default): the connection is refused, so proxied TCP does not leak. This covers only what the router sends to the container: UDP (section 7) and IPv6 (unless you followed "IPv6 (required)") never reach it.
- `direct`: the connection goes out directly from the container. This applies only after a health check has found the clients down. In the first seconds after a start, before any client of a group has been checked, the connection is refused instead, so a restart does not send traffic out directly while the proxies are fine.

**On the router** (for when the container itself is down or stopped):

- **Strict:** add a blackhole fallback, so marked traffic is dropped instead of using the main table:

  ```routeros
  /ip/route/add dst-address=0.0.0.0/0 blackhole routing-table=to-v2ray distance=2 comment="v2ray-client: strict kill switch"
  ```

- **Fail open:** add a fallback route through the WAN gateway. Traffic goes out directly while `check-gateway=ping` reports the container as down:

  ```routeros
  /ip/route/add dst-address=0.0.0.0/0 gateway=<WAN gateway IP> routing-table=to-v2ray distance=2 comment="v2ray-client: fallback direct"
  ```

  With a DHCP WAN the gateway can change. On recent v7 builds, let the DHCP client install its default route into both tables (`/ip/dhcp-client/set [find interface=ether1] default-route-tables=main,to-v2ray`; check `/ip/dhcp-client/set ?`). For PPPoE, use `gateway=pppoe-out1`.

Add only **one** of these. If you add neither, whether marked traffic falls back to the `main` table depends on the RouterOS version. Be explicit.

## 11. Web UI

Open `http://172.17.0.2/` from a LAN host and log in with `ADMIN_PASSWORD`.

**Required: restrict the container to your admin hosts.** The UI is plain HTTP, so the password crosses the LAN (and Wi-Fi) in cleartext, and by default every LAN or guest host could try to log in. Allow the UI only from your admin addresses (replace `192.168.88.10`; add more rules or use an address list for several hosts):

```routeros
/ip/firewall/filter
add chain=forward action=accept dst-address=172.17.0.2 protocol=tcp dst-port=80 \
    connection-state=new src-address=192.168.88.10 comment="v2ray-client: UI from admin host" place-before=[find action=fasttrack-connection]
add chain=forward action=reject reject-with=tcp-reset dst-address=172.17.0.2 protocol=tcp dst-port=!53 \
    connection-state=new comment="v2ray-client: no other direct access to the container" place-before=[find action=fasttrack-connection]
```

**Give each admin host a static DHCP lease** (`/ip/dhcp-server/lease/make-static [find address=192.168.88.10]`). The rules above trust the address. A login session is also bound to the client IP it logged in from, so a session cookie sniffed from the plaintext traffic cannot be replayed from another address. With a dynamic lease, the admin host can get a new address, which ends its session, and another device can later get the admin's old address.

Both rules match only new connections (`connection-state=new`). Without that, the second rule would also reset the replies to the container's own outgoing connections, which arrive with the destination `172.17.0.2`, and nothing would be proxied. The second rule also blocks the SOCKS and HTTP ports if you enable them. Proxied traffic is not affected: it is routed to the container with its original destination address, not addressed to `172.17.0.2`. DNS (port 53) stays open for option A in section 8.

The SOCKS5 and HTTP CONNECT inbounds are **off by default** (port 0). They have no authentication and can connect to any address, including the router's own services at `172.17.0.1`. A connection through them reaches the router with the container's address, which gets around the `address=172.17.0.2/32` limit on the REST user. Enable them (settings `ports.socks` / `ports.http`, then restart) only if you need them, and allow them only from trusted hosts with a forward rule like the one above.

### Private server addresses (`allowPrivateServers`)

By default, clients that came from a **subscription** or from **pasted share links** (shown as "untrusted") may not use private (RFC 1918, ULA) or CGNAT server addresses. Otherwise a malicious subscription could make the container open health checks and connections to devices on your LAN. Clients you add or save through the form may always use them; saving an imported client in the form lifts the restriction for it. Loopback, link-local, the container's own address and its gateway are always refused.

If a subscription or imported link really serves from a private or CGNAT address (for example a server on your own LAN or behind a carrier NAT), turn on Settings → "Allow untrusted servers on private/LAN addresses" (`settings.allowPrivateServers`). Turn it on only for subscriptions you trust.

## Troubleshooting

```routeros
/container/print detail                       # status, root-dir, interface, envlist
/log/print where topics~"container"           # app logs (logging=yes)
/ip/route/print where routing-table=to-v2ray # route active? (A flag, check-gateway result)
/ip/firewall/mangle/print stats where comment~"v2ray"   # are the rules counting?
/ip/firewall/connection/print where connection-mark=v2ray
/ping 172.17.0.2                              # veth up?
```

- **Container does not start.** Check `/system/device-mode/print` (container: yes) and `free-hdd-space`. Make sure the tar was built for arm64 (`make image` always builds arm64). `ADMIN_PASSWORD` must be set; otherwise the app exits right away and the log says why.
- **Router-originated traffic:** `/tool/fetch url=https://ifconfig.me/ip output=user` should print the proxy server's exit IP, not your WAN IP. `/tool/traceroute 1.1.1.1 routing-table=to-v2ray` should show `172.17.0.2` as the first hop.
- **LAN traffic:** run `curl https://ifconfig.me` on a LAN host and expect the proxy's IP. The UI's connections page should list the connection with its original destination and the client that was chosen. If the mangle counters rise but nothing appears in the UI, the REDIRECT is missing: the container log shows which netfilter method was used at startup (`nftables` or `iptables-legacy`) or why both failed.
- **Works for a few seconds, then stalls:** fasttrack is still active for marked connections. See section 7.
- **Everything loops or times out:** `br-containers` is in the `LAN` list, or a proxy server IP is missing from `no-proxy`/`v2ray-bypass` while router-originated traffic is marked.
- **No shell:** the image is `scratch`, so `/container/shell` has nothing to run. Use the logs and the UI.
- **Memory (RSS):** the app does not report its own memory use. Some v7 versions show container memory in `/container/print detail`. For the whole box, compare `free-memory` in `/system/resource/print` before and after starting the container. The UPX-packed binary unpacks into anonymous memory, so expect a baseline of about 10–12 MB before any traffic.
