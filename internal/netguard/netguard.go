// Package netguard decides which addresses the container may not dial:
// itself and the router behind it (its management services accept the
// container's address), addresses that are never a valid remote host, and
// (for untrusted sources such as subscriptions) private networks.
package netguard

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

const selfRefresh = time.Minute

var (
	// SelfAddrs returns the container's own addresses and its default
	// gateway (a var so tests can replace it; call ResetCache after).
	SelfAddrs = loadSelfAddrs

	selfMu   sync.Mutex
	selfSet  map[netip.Addr]bool
	selfTime time.Time
)

// ResetCache drops the cached self addresses so the next Refused call
// reloads them.
func ResetCache() {
	selfMu.Lock()
	selfSet = nil
	selfMu.Unlock()
}

// Refused reports whether ip must never be dialed: loopback, unspecified,
// link-local, multicast, broadcast, or one of the container's own
// addresses or its default gateway.
func Refused(ip netip.Addr) bool {
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
		for _, a := range SelfAddrs() {
			selfSet[a.Unmap()] = true
		}
		selfTime = time.Now()
	}
	return selfSet[ip]
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Private reports whether ip is in a private range: RFC 1918, ULA
// (fc00::/7) or CGNAT (100.64.0.0/10).
func Private(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsPrivate() || cgnat.Contains(ip)
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
		out = append(out, ParseGateways(f)...)
	}
	return out
}

// ParseGateways returns the gateways of the default routes in a
// /proc/net/route table (hex fields in host byte order, little endian).
func ParseGateways(f io.Reader) []netip.Addr {
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
