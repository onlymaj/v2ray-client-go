package dispatch

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// Destinations a LAN connection may never reach: the container itself and
// the router behind it (its management services accept the container's
// address), plus addresses that are never a valid remote host.

const selfRefresh = time.Minute

var (
	// selfAddrs returns the container's own addresses and its default
	// gateway (a var so tests can replace it).
	selfAddrs = loadSelfAddrs

	// lookupIP resolves a domain routed direct (a var for tests).
	lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}

	selfMu   sync.Mutex
	selfSet  map[netip.Addr]bool
	selfTime time.Time
)

var errRefused = errors.New("dispatch: destination refused")

// refused reports whether ip must not be dialed for a LAN connection.
func refused(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return true
	}
	selfMu.Lock()
	defer selfMu.Unlock()
	if selfSet == nil || time.Since(selfTime) > selfRefresh {
		selfSet = map[netip.Addr]bool{}
		for _, a := range selfAddrs() {
			selfSet[a.Unmap()] = true
		}
		selfTime = time.Now()
	}
	return selfSet[ip]
}

// resolve returns the first address of host, preferring IPv4.
func resolve(ctx context.Context, host string) (netip.Addr, error) {
	ips, err := lookupIP(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	var v6 netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() {
			return ip, nil
		}
		if !v6.IsValid() {
			v6 = ip
		}
	}
	if !v6.IsValid() {
		return netip.Addr{}, errors.New("dispatch: no address for " + host)
	}
	return v6, nil
}

func loadSelfAddrs() []netip.Addr {
	var out []netip.Addr
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				out = append(out, p.Addr())
			}
		}
	}
	if f, err := os.Open("/proc/net/route"); err == nil {
		defer f.Close()
		out = append(out, parseGateways(f)...)
	}
	return out
}

// parseGateways returns the gateways of the default routes in a
// /proc/net/route table (hex fields in host byte order, little endian).
func parseGateways(f io.Reader) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 3 || fs[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(fs[2])
		if err != nil || len(b) != 4 {
			continue
		}
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], binary.LittleEndian.Uint32(b))
		if gw := netip.AddrFrom4(a); !gw.IsUnspecified() {
			out = append(out, gw)
		}
	}
	return out
}
